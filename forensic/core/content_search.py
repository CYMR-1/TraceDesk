"""按目录记录读取文件内容；所有结果坐标均为文件内字节偏移。"""
import json
import msvcrt
import os
import tempfile
import threading
import uuid
import _winapi
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path

from .case import sha256
from ..engines import ewf
from ..engines.tsk import TSK, can_export, deleted_source_note, tsk_error


class Cancelled(Exception):
    pass


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


def matches(stream, size, needle, control, chunk=256 * 1024, *, progress=None):
    tail, consumed, cursor = b'', 0, 0
    while consumed < size:
        control.check()
        block = stream.read(min(chunk, size - consumed))
        base = consumed - len(tail)
        data = tail + block
        consumed += len(block)
        if progress:
            progress('搜索文件字节', consumed, size)
        # 等到后文的 12 个字节到齐才发布，块边界处的复核上下文也应完整。
        end = len(data) if consumed == size or not block else max(0, len(data) - 12)
        while True:
            pos = data.find(needle, max(0, cursor - base), end)
            if pos < 0:
                break
            control.check()
            yield base + pos, data[max(0, pos-12):pos].hex(' '), data[pos+len(needle):pos+len(needle)+12].hex(' ')
            cursor = base + pos + 1
        if not block:
            raise OSError(f'仅读到 {consumed}/{size} 字节')
        cursor = max(cursor, base + end - len(needle) + 1)
        tail = data[-(len(needle) + 24):]


@contextmanager
def protected_source(image, segmented):
    """持有全部源文件的拒写、拒删除句柄，直到校验与搜索都结束。"""
    def parts():
        return ewf.segments(image) if segmented else [Path(image)]

    paths = parts()
    with ExitStack() as handles:
        try:
            for path in paths:
                # FILE_SHARE_READ 只允许其他读取者（包括 icat）。
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


@contextmanager
def buffered_icat(tool, args, stderr, size):
    # Windows 默认匿名管道很小，大文件会频繁阻塞 icat。最多缓存 1 MiB。
    handles = list(_winapi.CreatePipe(None, min(size, 1024 * 1024)))
    try:
        def open_end(mode, flags):
            fd = msvcrt.open_osfhandle(handles[0], flags | os.O_BINARY)
            handles.pop(0)  # 此后由文件对象关闭句柄。
            return os.fdopen(fd, mode)

        with open_end('rb', os.O_RDONLY) as source, open_end('wb', os.O_WRONLY) as target:
            with tool.popen_image('icat', args, stdout=target, stderr=stderr) as proc:
                target.close()  # 只留下子进程的写端，子进程退出时读取方才能收到 EOF。
                yield proc, source
    finally:
        for handle in handles:
            _winapi.CloseHandle(handle)


def read_entry(tool, image, entry, needle, control, stop, limit, byte_progress):
    found = []
    control.check()
    if not entry['size'] or stop.is_set():
        return found, None
    try:
        args = tool.entry_args(image, entry)
        with tempfile.TemporaryFile() as stderr, buffered_icat(tool, args, stderr, entry['size']) as (proc, stream):
            try:
                with control.lock:
                    control.check()
                    if stop.is_set():
                        return found, None
                    control.processes.add(proc)
                for offset, before, after in matches(stream, entry['size'], needle, control, progress=byte_progress):
                    found.append((entry, offset, before, after))
                    if len(found) == limit:
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


def scan_entries(tool, image, entries, needle, control, progress, limit):
    completed = 0
    remaining = iter(entries)
    stop = threading.Event()
    byte_progress = progress if len(entries) == 1 else None
    # 只提前读取四项，按原清单顺序发布，使上限和命中顺序可复现。
    with ThreadPoolExecutor(max_workers=4) as pool:
        pending = deque()
        try:
            while True:
                control.check()
                while len(pending) < 4:
                    entry = next(remaining, None)
                    if entry is None:
                        break
                    pending.append(pool.submit(read_entry, tool, image, entry, needle, control, stop, limit, byte_progress))
                if not pending:
                    return
                if not byte_progress:
                    progress('搜索文件内容', completed, len(entries))
                yield pending.popleft().result()
                completed += 1
        finally:
            stop.set()
            control.stop_readers()
            for future in pending:
                future.cancel()


def search(case, query, encoding, control, progress, *, limit=1000, selected=None):
    needle = pattern(query, encoding)
    tool = TSK()
    image = case.image()
    evidence = case.data['evidence']
    if selected is not None and (not can_export(selected) or selected not in case.data['inventory']):
        raise ValueError('请选择当前案件中的普通文件')
    entries = [selected] if selected is not None else [entry for entry in case.data['inventory'] if can_export(entry)]
    hits, errors = [], []
    completed = 0
    state = '完成'
    verification = '校验未完成'
    def verify(stage):
        def notify(done, total):
            control.check()
            progress(stage, done, total)
        if not case.verify(notify):
            raise ValueError('镜像摘要与案件不一致，拒绝使用搜索结果')
    try:
        control.check()
        with protected_source(image, evidence.get('format') == 'EWF') as protected:
            verify('搜索前校验')
            verification = '全程持有镜像只读共享句柄，搜索前复算 SHA-256' if protected else '搜索前后分别复算 SHA-256'
            with closing(scan_entries(tool, image, entries, needle, control, progress, limit)) as results:
                for found, error in results:
                    hits.extend(found[:limit - len(hits)])
                    if len(hits) == limit:
                        state = f'达到 {limit} 条上限，未搜索全部内容'
                        break
                    if error:
                        errors.append(error)
                    completed += 1
            control.check()
            if not protected:
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
                  selected={k:selected[k] for k in ('path','offset','inode')} if selected is not None else None,
                  partition_scans=case.data.get('partition_scans', []),
                  status=state, visited=completed, eligible=len(entries), errors=errors, hits=[
                      dict(path=e['path'], offset=e['offset'], inode=e['inode'], deleted=e['deleted'],
                           file_byte=pos, before=before, after=after, reallocated=e.get('reallocated',False),
                           source_note=deleted_source_note(e))
                      for e,pos,before,after in hits])
    name = 'search_' + uuid.uuid4().hex + '.json'
    output = case.folder / 'reports' / name
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    case.log('CONTENT_SEARCH', name, state, query=query, encoding=encoding, hits=len(hits), failed=len(errors),
             visited=completed, eligible=len(entries), sha256=sha256(output))
    return record, hits, name
