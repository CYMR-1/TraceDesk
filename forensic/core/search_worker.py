"""内容搜索的字节匹配与分片读取；可在独立进程中运行，不依赖案件和界面。"""
from contextlib import suppress
import re

import pytsk3

from ..engines.random_read import VolumeReader

CONTEXT = 12
INODE_RE = re.compile(r'(\d+)(?:-(\d+)-(\d+))?')
SPARSE_SKIP_BLOCKED = pytsk3.TSK_FS_ATTR_COMP | pytsk3.TSK_FS_ATTR_ENC


class Cancelled(Exception):
    pass


class NoControl:
    """子进程由主进程整体终止，无需逐块检查取消。"""
    @staticmethod
    def check():
        pass


def parse_inode(inode):
    match = INODE_RE.fullmatch(str(inode))
    if not match:
        return None
    return int(match[1]), (int(match[2]) if match[2] else None), (int(match[3]) if match[3] else None)


def matches(stream, size, needle, control, chunk=1024 * 1024, *, progress=None):
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
        end = len(data) if consumed == size or not block else max(0, len(data) - CONTEXT)
        while True:
            pos = data.find(needle, max(0, cursor - base), end)
            if pos < 0:
                break
            control.check()
            yield (base + pos, data[max(0, pos - CONTEXT):pos].hex(' '),
                   data[pos + len(needle):pos + len(needle) + CONTEXT].hex(' '))
            cursor = base + pos + 1
        if not block:
            raise OSError(f'仅读到 {consumed}/{size} 字节')
        cursor = max(cursor, base + end - len(needle) + 1)
        tail = data[-(len(needle) + 2 * CONTEXT):]


class EntryStream:
    def __init__(self, read_at, stop=None, position=0):
        self.read_at = read_at
        self.stop = stop
        self.position = position

    def read(self, length):
        if self.stop is not None and self.stop.is_set():
            raise Cancelled()
        data = self.read_at(self.position, length)
        self.position += len(data)
        return data


def _ensure_fs(volume, offset):
    if volume.offset != offset:
        volume.fs = pytsk3.FS_Info(volume.image, offset=offset * 512)
        volume.offset = offset
    return volume.fs


def _non_sparse_intervals(attr, block_size, size, needle, p_start, p_end):
    """返回需要扫描的命中起点区间 [(h_lo, h_hi), ...]。

    仅对未压缩、未加密的非常驻属性跳过稀疏零区（搜索全零模式时不跳过）。
    无任何数据 run（如 $BadClus:$Bad）时返回 None，交由 icat 给出一致的读取状态。
    """
    flags = attr.info.flags
    if not (flags & pytsk3.TSK_FS_ATTR_NONRES):
        return [(p_start, p_end)]
    runs = list(attr)
    if not runs:
        return None
    if not any(needle) or (flags & SPARSE_SKIP_BLOCKED):
        return [(p_start, p_end)]
    if not any(r.flags & pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE for r in runs):
        return [(p_start, p_end)]
    overlap = len(needle) - 1
    intervals = []
    for run in runs:
        if run.flags & pytsk3.TSK_FS_ATTR_RUN_FLAG_SPARSE:
            continue
        h_lo = max(p_start, run.offset * block_size - overlap)
        h_hi = min(p_end, (run.offset + run.len) * block_size)
        if h_lo >= h_hi:
            continue
        if intervals and h_lo <= intervals[-1][1]:
            intervals[-1] = (intervals[-1][0], max(intervals[-1][1], h_hi))
        else:
            intervals.append((h_lo, h_hi))
    return intervals


def _scan_intervals(file, attr_args, size, intervals, needle, limit, control, progress=None):
    def read_at(offset, length):
        if not length:
            return b''
        block = file.read_random(offset, length, *attr_args)
        if len(block) != length:
            raise OSError('原始文件内容短读')
        return block

    found = []
    extra = len(needle) - 1 + CONTEXT
    for h_lo, h_hi in intervals:
        read_lo = max(0, h_lo - CONTEXT)
        read_hi = min(size, h_hi + extra)
        if read_hi - read_lo < len(needle):
            continue
        for rel_pos, before, after in matches(EntryStream(read_at, position=read_lo),
                                              read_hi - read_lo, needle, control, progress=progress):
            pos = read_lo + rel_pos
            if pos >= h_hi:
                break
            if pos >= h_lo:
                found.append((pos, before, after))
                if limit is not None and len(found) == limit:
                    return found
    return found


def scan_inode_groups(volume, groups, needle, limit, control, progress=None):
    """按 (分区偏移, inode 编号) 分组扫描；同一 MFT 记录只打开一次。

    groups 每项为 (offset, ino_num, [(task_id, atype, aid, size, p_start, p_end, deleted), ...])。
    NTFS 的删除记录数据 run 位于 MFT 中，可直接按属性读取；FAT 等文件系统删除记录返回 None 回退 icat -r。
    返回 {task_id: 命中列表或 None}；None 表示无法直接读取，需回退 icat。
    """
    results = {}
    nlen = len(needle)
    for offset, ino_num, specs in groups:
        control.check()
        try:
            fs = _ensure_fs(volume, offset)
            is_ntfs = fs.info.ftype == pytsk3.TSK_FS_TYPE_NTFS
            if not is_ntfs and all(spec[6] for spec in specs):
                for spec in specs:
                    results[spec[0]] = None
                continue
            file = fs.open_meta(inode=ino_num)
        except (OSError, RuntimeError, ValueError):
            for spec in specs:
                results[spec[0]] = None
            continue
        attr_map = None
        block_size = fs.info.block_size
        for task_id, atype, aid, size, p_start, p_end, deleted in specs:
            control.check()
            if size < nlen or p_start >= p_end:
                results[task_id] = []
                continue
            if deleted and not is_ntfs:
                results[task_id] = None
                continue
            try:
                if atype is not None:
                    if attr_map is None:
                        attr_map = {(a.info.type, a.info.id): a for a in file}
                    attr = attr_map.get((atype, aid))
                    if attr is None or attr.info.size != size:
                        results[task_id] = None
                        continue
                    intervals = _non_sparse_intervals(attr, block_size, size, needle, p_start, p_end)
                    if intervals is None:
                        results[task_id] = None
                        continue
                    attr_args = (atype, aid)
                else:
                    if file.info.meta is None or file.info.meta.size != size:
                        results[task_id] = None
                        continue
                    intervals = [(p_start, p_end)]
                    attr_args = ()
                results[task_id] = _scan_intervals(file, attr_args, size, intervals, needle, limit,
                                                   control, progress=progress)
            except (OSError, RuntimeError, ValueError):
                results[task_id] = None
    return results


def probe_large_entry(volume, entry, needle, piece_bytes):
    """探测大文件的有效扫描区间并切分为并行的 [p_start, p_end) 片段。

    返回 None 表示需回退 icat；返回 [] 表示无须读取（全稀疏）。
    """
    parsed = parse_inode(entry['inode'])
    if parsed is None or entry.get('deleted') or not entry['mode'].startswith('r/'):
        return None
    ino_num, atype, aid = parsed
    size = entry['size']
    try:
        fs = _ensure_fs(volume, entry['offset'])
        file = fs.open_meta(inode=ino_num)
        if atype is not None:
            attr = next((a for a in file if (a.info.type, a.info.id) == (atype, aid)), None)
            if attr is None or attr.info.size != size:
                return None
            intervals = _non_sparse_intervals(attr, fs.info.block_size, size, needle, 0, size)
            if intervals is None:
                return None
        else:
            if file.info.meta is None or file.info.meta.size != size:
                return None
            intervals = [(0, size)]
    except (OSError, RuntimeError, ValueError):
        return None
    pieces = []
    for lo, hi in intervals:
        for start in range(lo, hi, piece_bytes):
            pieces.append((start, min(hi, start + piece_bytes)))
    return pieces


_volume = None


def _worker_volume(image):
    global _volume
    if _volume is None:
        _volume = VolumeReader(image)
    return _volume


def scan_batch(image, needle, limit, groups):
    """子进程入口：一个进程复用一个镜像句柄和文件系统解析结果。"""
    volume = _worker_volume(image)
    return scan_inode_groups(volume, groups, needle, limit, NoControl)


def close_worker():
    global _volume
    if _volume is not None:
        with suppress(Exception):
            _volume.close()
        _volume = None
