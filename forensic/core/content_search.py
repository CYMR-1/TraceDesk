"""按目录记录读取文件内容；所有结果坐标均为文件内字节偏移。

优化策略：
1. 跳过长度小于搜索字节串的条目，避免无效打开与读取。
2. 对同一 (分区偏移, inode, 大小) 的非删除硬链接只扫描一次，按原清单顺序复用结果。
3. 在滚动窗口内按 (分区偏移, inode 编号) 聚合与排序，同一 MFT 记录仅 open_meta 一次，
   并把随机读转为接近顺序的 MFT / 镜像访问；大文件切分为非稀疏区间并行扫描。
4. 通过独立子进程并行读取（绕开 pytsk3 回调的 GIL 竞争），稀疏零区在非全零检索时直接跳过；
   删除记录及无法直接定位的属性仍回退 icat，保持原有语义与确定性命中顺序。
"""
import collections
import json
import multiprocessing
import os
import tempfile
import threading
import uuid
import _winapi
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path

from .case import sha256
from .search_worker import (Cancelled, EntryStream, matches, parse_inode,
                            probe_large_entry, scan_batch, scan_inode_groups)
from ..engines import ewf
from ..engines.random_read import VolumeReader
from ..engines.tsk import TSK, buffered_output, can_export, deleted_source_note, tsk_error

__all__ = ['Cancelled', 'EntryStream', 'SearchControl', 'matches', 'pattern', 'protected_source', 'search']

# 读取进程数：EWF 解压以 CPU 为瓶颈，留出核心给界面与系统，同时控制内存占用。
WORKERS = max(1, min(12, (os.cpu_count() or 2) - 1))
POOL_MIN_ENTRIES = 512      # 条目较少时直接在本进程读取，省去子进程启动开销。
WIN_INIT_FILES = 2048       # 首个窗口偏小，尽快流式产出首批命中并支持提前达到上限。
WIN_MAX_FILES = 8192        # 后续窗口扩大，兼顾 MFT 顺序局部性、多核饱和度与实时命中刷新。
WIN_INIT_BYTES = 128 << 20
WIN_MAX_BYTES = 512 << 20
PIECE_SPLIT_MIN = 64 << 20  # 达到此大小的普通文件切分为多段并行读取。
PIECE_BYTES = 32 << 20
ICAT_THREADS = 8            # icat 为外部子进程，可用线程并发等待。


class SearchControl:
    def __init__(self):
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.processes = set()

    def cancel(self):
        self.event.set()
        self.stop_readers()

    def stop_readers(self):
        with self.lock:
            for process in self.processes:
                process.kill()

    def check(self):
        if self.event.is_set():
            raise Cancelled()


def pattern(query, encoding):
    value = bytes.fromhex(query) if encoding == 'HEX' else query.encode(encoding)
    if not 1 <= len(value) <= 4096:
        raise ValueError('搜索内容须为 1 至 4096 字节')
    return value


@contextmanager
def protected_source(image, segmented):
    """持有全部源文件的拒写、拒删除句柄，直到校验与搜索都结束。"""
    def parts():
        return ewf.segments(image) if segmented else [Path(image)]

    paths = parts()
    with ExitStack() as handles:
        try:
            for path in paths:
                # FILE_SHARE_READ 只允许其他读取者（包括 icat 和读取进程）。
                handle = _winapi.CreateFile(str(path), _winapi.GENERIC_READ, 1, 0,
                                            _winapi.OPEN_EXISTING, 0, 0)
                handles.callback(_winapi.CloseHandle, handle)
        except OSError:
            handles.close()
            yield False
            return
        stamp = ewf.snapshot(paths)
        yield True
        if ewf.snapshot(parts()) != stamp:
            raise ValueError('搜索期间镜像或分段清单发生变化，结果未发布')


class _StopStream:
    def __init__(self, stream, stop):
        self.stream = stream
        self.stop = stop

    def read(self, length):
        if self.stop.is_set():
            raise Cancelled()
        return self.stream.read(length)


def read_entry(tool, image, entry, needle, control, stop, limit, byte_progress):
    found = []
    control.check()
    if entry['size'] < len(needle) or stop.is_set():
        return found, None
    try:
        args = tool.entry_args(image, entry)
        with tempfile.TemporaryFile() as stderr, buffered_output(tool, 'icat', args, stderr, entry['size']) as (proc, stream):
            try:
                with control.lock:
                    control.check()
                    if stop.is_set():
                        return found, None
                    control.processes.add(proc)
                for offset, before, after in matches(_StopStream(stream, stop), entry['size'], needle, control,
                                                     progress=byte_progress):
                    found.append((entry, offset, before, after))
                    if limit is not None and len(found) == limit:
                        return found, None
                if stream.read(1):
                    raise OSError('输出超过目录记录长度')
                if proc.wait():
                    stderr.seek(0)
                    raise OSError(tsk_error(stderr.read(2000)) or 'icat 读取失败')
            finally:
                with control.lock:
                    control.processes.discard(proc)
                proc.kill()
    except OSError as error:
        control.check()
        return found, dict(path=entry['path'], offset=entry['offset'], inode=entry['inode'], error=str(error))
    return found, None


def _pack_shards(sorted_groups, target_shards):
    """按估算 I/O 权重将已排序的 inode 分组切分为连续分片，兼顾局部性与负载均衡。"""
    if not sorted_groups:
        return []
    weights = [32768 + sum(min(spec[3], PIECE_BYTES) for spec in group[2]) for group in sorted_groups]
    target_w = max(1, sum(weights) // max(1, target_shards))
    shards, current, current_w = [], [], 0
    for group, weight in zip(sorted_groups, weights):
        current.append(group)
        current_w += weight
        if current_w >= target_w:
            shards.append(current)
            current, current_w = [], 0
    if current:
        shards.append(current)
    return shards


def _wait_future(future, control):
    while True:
        control.check()
        try:
            return future.result(timeout=0.05)
        except FutureTimeout:
            continue


def scan_entries(tool, image, entries, needle, control, progress, limit, *, workers=None):
    """逐项产出 (命中列表, 失败记录)，严格按 entries 原顺序发布。"""
    total = len(entries)
    if not total:
        return
    workers = WORKERS if workers is None else workers
    nlen = len(needle)
    parallel = workers > 1 and total >= POOL_MIN_ENTRIES
    byte_progress = progress if total == 1 else None
    stop = threading.Event()

    # 统计会重复出现的非删除硬链接，仅缓存多次引用的键并在最后一次发布后释放。
    key_counts = collections.Counter()
    for entry in entries:
        if entry['size'] >= nlen and not entry.get('deleted') and entry['mode'].startswith('r/'):
            key_counts[(entry['offset'], str(entry['inode']), entry['size'])] += 1
    shared_remaining = {key: count for key, count in key_counts.items() if count > 1}
    shared_cache = {}

    with ExitStack() as stack:
        icat = ThreadPoolExecutor(ICAT_THREADS)
        stack.callback(icat.shutdown, wait=True, cancel_futures=True)
        pool = None
        if parallel:
            pool_size = min(workers, max(1, total // 256))
            pool = multiprocessing.get_context('spawn').Pool(pool_size)
            stack.callback(pool.join)
            stack.callback(pool.terminate)
        local_volume = None
        volume_failed = False

        def get_volume():
            nonlocal local_volume, volume_failed
            if local_volume is None and not volume_failed:
                try:
                    local_volume = VolumeReader(image)
                    stack.callback(local_volume.close)
                except Exception:
                    volume_failed = True
            return local_volume

        # 退出时最先中断阻塞中的读取线程和子进程。
        stack.callback(control.stop_readers)
        stack.callback(stop.set)

        def fallback(entry):
            return read_entry(tool, image, entry, needle, control, stop, limit, byte_progress)

        if not byte_progress:
            progress('搜索文件内容', 0, total)

        cursor = emitted = 0
        win_files = WIN_INIT_FILES
        max_win_bytes = WIN_INIT_BYTES

        while cursor < total:
            control.check()
            # 1. 取下一窗口的条目（保持清单顺序，窗口大小随进度自适应增大）。
            win_end = cursor
            win_bytes = 0
            win_seen_keys = set()
            while win_end < total and (win_end - cursor) < win_files:
                entry = entries[win_end]
                size = entry['size']
                cost = 0
                if size >= nlen:
                    if not entry.get('deleted') and entry['mode'].startswith('r/'):
                        key = (entry['offset'], str(entry['inode']), size)
                        if key not in shared_cache and key not in win_seen_keys:
                            win_seen_keys.add(key)
                            cost = min(size, 128 << 20)
                    else:
                        cost = min(size, 128 << 20)
                if win_end > cursor and win_bytes + cost > max_win_bytes:
                    break
                win_bytes += cost
                win_end += 1

            # 2. 对窗口内条目分类：跳过、复用硬链接缓存、直接读取（分组/分片）或 icat。
            entry_key = {}          # idx -> key
            win_direct = {}         # idx -> (hits_with_entry, error_dict)
            deleted_futures = {}    # idx -> Future
            key_entry = {}          # key -> 代表 entry
            key_results = {}        # key -> (raw_hits, error_msg)
            key_icat_futures = {}   # key -> Future
            key_pieces = {}         # key -> [remaining_pieces, {p_start: raw_hits}, needs_icat]
            task_to_key = {}        # task_id -> (key, p_start)
            inode_groups = collections.defaultdict(list)
            large_shards = []
            task_seq = 0
            window_done = 0

            for idx in range(cursor, win_end):
                entry = entries[idx]
                size = entry['size']
                if size < nlen:
                    win_direct[idx] = ([], None)
                    window_done += 1
                    continue
                if not entry.get('deleted') and entry['mode'].startswith('r/'):
                    key = (entry['offset'], str(entry['inode']), size)
                    entry_key[idx] = key
                    if key in shared_cache:
                        window_done += 1
                        continue
                    if key in key_entry:
                        window_done += 1
                        continue
                    key_entry[key] = entry
                    parsed = parse_inode(entry['inode'])
                    if parsed is None:
                        key_icat_futures[key] = icat.submit(fallback, entry)
                        continue
                    ino_num, atype, aid = parsed
                    if parallel and size >= PIECE_SPLIT_MIN:
                        vol = get_volume()
                        pieces = probe_large_entry(vol, entry, needle, PIECE_BYTES) if vol is not None else None
                        if pieces is None:
                            key_icat_futures[key] = icat.submit(fallback, entry)
                        elif not pieces:
                            key_results[key] = ([], None)
                            window_done += 1
                        else:
                            key_pieces[key] = [len(pieces), {}, False]
                            for p_start, p_end in pieces:
                                task_seq += 1
                                task_to_key[task_seq] = (key, p_start)
                                large_shards.append([(entry['offset'], ino_num,
                                                      [(task_seq, atype, aid, size, p_start, p_end, False)])])
                    else:
                        task_seq += 1
                        task_to_key[task_seq] = (key, 0)
                        key_pieces[key] = [1, {}, False]
                        inode_groups[(entry['offset'], ino_num)].append(
                            (task_seq, atype, aid, size, 0, size, False))
                else:
                    parsed = parse_inode(entry['inode'])
                    if parsed is not None and entry.get('deleted'):
                        key = ('del', idx)
                        entry_key[idx] = key
                        key_entry[key] = entry
                        ino_num, atype, aid = parsed
                        task_seq += 1
                        task_to_key[task_seq] = (key, 0)
                        key_pieces[key] = [1, {}, False]
                        inode_groups[(entry['offset'], ino_num)].append(
                            (task_seq, atype, aid, size, 0, size, True))
                    else:
                        deleted_futures[idx] = icat.submit(fallback, entry)

            # 3. 按 (分区偏移, inode 编号) 排序并打包分片，顺序读取 MFT。
            sorted_groups = sorted(((off, ino, specs) for (off, ino), specs in inode_groups.items()),
                                   key=lambda item: (item[0], item[1]))
            shards = large_shards + _pack_shards(sorted_groups, (workers * 4) if parallel else 1)

            def apply_shard_result(result_map):
                nonlocal window_done
                for tid, found in result_map.items():
                    key, p_start = task_to_key[tid]
                    state = key_pieces[key]
                    state[0] -= 1
                    if found is None:
                        state[2] = True
                    else:
                        state[1][p_start] = found
                    if state[0]:
                        continue
                    del key_pieces[key]
                    if state[2]:
                        key_icat_futures[key] = icat.submit(fallback, key_entry[key])
                    else:
                        merged = [hit for start in sorted(state[1]) for hit in state[1][start]]
                        key_results[key] = (merged if limit is None else merged[:limit], None)
                        window_done += 1

            # 4. 执行分片扫描（多进程并行或单进程复用 VolumeReader）。
            if shards:
                if parallel:
                    pending = [(pool.apply_async(scan_batch, (str(image), needle, limit, shard)), shard)
                               for shard in shards]
                    while pending:
                        control.check()
                        ready = [item for item in pending if item[0].ready()]
                        if not ready:
                            pending[0][0].wait(0.05)
                            continue
                        for item in ready:
                            pending.remove(item)
                            async_res, shard = item
                            try:
                                result_map = async_res.get(0)
                            except Cancelled:
                                raise
                            except Exception:
                                result_map = {spec[0]: None for _, _, specs in shard for spec in specs}
                            apply_shard_result(result_map)
                        if not byte_progress:
                            progress('搜索文件内容', min(total, emitted + window_done), total)
                else:
                    vol = get_volume()
                    for shard in shards:
                        control.check()
                        if vol is not None:
                            result_map = scan_inode_groups(vol, shard, needle, limit, control,
                                                           progress=byte_progress)
                        else:
                            result_map = {spec[0]: None for _, _, specs in shard for spec in specs}
                        apply_shard_result(result_map)
                        if not byte_progress:
                            progress('搜索文件内容', min(total, emitted + window_done), total)

            # 5. 收集本窗口内所有 icat 读取结果（删除项与回退项）。
            for key, future in key_icat_futures.items():
                found, error = _wait_future(future, control)
                raw_hits = [(pos, before, after) for _, pos, before, after in found]
                key_results[key] = (raw_hits, error['error'] if error else None)
                window_done += 1
                if not byte_progress:
                    progress('搜索文件内容', min(total, emitted + window_done), total)

            for idx, future in deleted_futures.items():
                win_direct[idx] = _wait_future(future, control)
                window_done += 1
                if not byte_progress:
                    progress('搜索文件内容', min(total, emitted + window_done), total)

            # 缓存会被后续条目复用的硬链接结果。
            for key, value in key_results.items():
                if key in shared_remaining:
                    shared_cache[key] = value

            # 6. 严格按原清单顺序发布本窗口结果；若调用方达上限提前 break，立即退出。
            for idx in range(cursor, win_end):
                control.check()
                if idx in win_direct:
                    result = win_direct[idx]
                else:
                    entry = entries[idx]
                    key = entry_key[idx]
                    raw_hits, error_msg = key_results[key] if key in key_results else shared_cache[key]
                    if key in shared_remaining:
                        shared_remaining[key] -= 1
                        if shared_remaining[key] == 0:
                            del shared_remaining[key]
                            shared_cache.pop(key, None)
                    entry_hits = [(entry, pos, before, after) for pos, before, after in raw_hits]
                    entry_error = (dict(path=entry['path'], offset=entry['offset'],
                                        inode=entry['inode'], error=error_msg)
                                   if error_msg is not None else None)
                    result = (entry_hits, entry_error)
                emitted += 1
                yield result

            cursor = win_end
            win_files = min(WIN_MAX_FILES, win_files * 2)
            max_win_bytes = min(WIN_MAX_BYTES, max_win_bytes * 2)


def search(case, query, encoding, control, progress, *, limit=None, selected=None, on_hit=None):
    needle = pattern(query, encoding)
    tool = TSK()
    image = case.image()
    evidence = case.data['evidence']
    if selected is not None and (not can_export(selected) or selected not in case.displayed_entries()):
        raise ValueError('请选择当前案件中的普通文件')
    if selected is None and case.browsing_directories:
        raise ValueError('全案搜索需要先在文件浏览中建立完整文件索引，亦可选择搜索单个文件。')
    entries = [selected] if selected is not None else [entry for entry in case.data['inventory'] if can_export(entry)]
    hits, errors = [], []
    completed = 0
    state = '完成'
    verification = '校验未完成'

    def verify(stage):
        def notify(done, total):
            control.check()
            progress(stage, done, total)
        if not case.operation_check(notify):
            raise ValueError('镜像摘要与案件不一致，拒绝使用搜索结果')

    try:
        control.check()
        with protected_source(image, evidence.get('format') == 'EWF') as protected:
            verify('搜索前校验')
            verification = '全程持有镜像只读共享句柄，搜索前复算 SHA-256' if protected else '搜索前后分别复算 SHA-256'
            if case.source_note():
                verification = case.source_note()
            with closing(scan_entries(tool, image, entries, needle, control, progress, limit)) as results:
                for found, error in results:
                    batch = found if limit is None else found[:limit - len(hits)]
                    if batch:
                        hits.extend(batch)
                        if on_hit is not None:
                            on_hit(batch)
                    if limit is not None and len(hits) == limit:
                        state = f'达到 {limit} 条上限，未搜索全部内容'
                        break
                    if error:
                        errors.append(error)
                    completed += 1
            control.check()
            if not protected or evidence.get('large_image'):
                verify('搜索后校验')
    except Cancelled:
        state = '已取消；结果未发布'
        hits.clear()
    if control.event.is_set():
        state = '已取消；结果未发布'
        hits.clear()
    if errors and state == '完成':
        state = '部分文件读取失败'
    record = dict(query=query, encoding=encoding, needle=needle.hex(), image_sha256=evidence['sha256'],
                  verification=verification,
                  scope='选中文件' if selected is not None else '清单内可读取的文件，不含未分配空间',
                  selected={k: selected[k] for k in ('path', 'offset', 'inode')} if selected is not None else None,
                  partition_scans=case.data.get('partition_scans', []),
                  status=state, visited=completed, eligible=len(entries), errors=errors, hits=[
                      dict(path=e['path'], offset=e['offset'], inode=e['inode'], deleted=e['deleted'],
                           file_byte=pos, before=before, after=after, reallocated=e.get('reallocated', False),
                           source_note=deleted_source_note(e))
                      for e, pos, before, after in hits])
    name = 'search_' + uuid.uuid4().hex + '.json'
    output = case.folder / 'reports' / name
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    case.log('CONTENT_SEARCH', name, state, query=query, encoding=encoding, hits=len(hits), failed=len(errors),
             visited=completed, eligible=len(entries), sha256=sha256(output))
    return record, hits, name
