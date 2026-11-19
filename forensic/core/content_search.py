"""按目录记录读取文件内容；所有结果坐标均为文件内字节偏移。"""
import json
import subprocess
import tempfile
import threading
import uuid

from .case import sha256
from ..engines.tsk import TSK, can_export, deleted_source_note, tsk_error


class Cancelled(Exception):
    pass


class SearchControl:
    def __init__(self):
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.process = None

    def cancel(self):
        self.event.set()
        with self.lock:
            if self.process and self.process.poll() is None:
                self.process.kill()

    def check(self):
        if self.event.is_set():
            raise Cancelled()


def pattern(query, encoding):
    value = bytes.fromhex(query) if encoding == 'HEX' else query.encode(encoding)
    if not 1 <= len(value) <= 4096:
        raise ValueError('搜索内容须为 1 至 4096 字节')
    return value


def matches(stream, size, needle, control, chunk=256 * 1024):
    tail, consumed, cursor = b'', 0, 0
    while consumed < size:
        control.check()
        block = stream.read(min(chunk, size - consumed))
        if not block:
            raise OSError(f'仅读到 {consumed}/{size} 字节')
        base = consumed - len(tail)
        data = tail + block
        consumed += len(block)
        while True:
            pos = data.find(needle, max(0, cursor - base))
            if pos < 0:
                break
            control.check()
            yield base + pos, data[max(0, pos-12):pos].hex(' '), data[pos+len(needle):pos+len(needle)+12].hex(' ')
            cursor = base + pos + 1
        cursor = max(cursor, consumed - len(needle) + 1)
        tail = data[-(len(needle) + 12):]


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
    def verify(stage):
        def notify(done, total):
            control.check()
            progress(stage, done, total)
        if not case.verify(notify):
            raise ValueError('镜像摘要与案件不一致，拒绝使用搜索结果')
    try:
        verify('搜索前校验')
        for entry in entries:
            control.check()
            progress('搜索文件内容', completed, len(entries))
            if entry['size']:
                args = tool.entry_args(image, entry)
                try:
                    with tempfile.TemporaryFile() as stderr, tool.popen_image('icat', args, stdout=subprocess.PIPE,
                            stderr=stderr) as proc:
                        with control.lock:
                            control.process = proc
                        try:
                            control.check()
                            for offset, before, after in matches(proc.stdout, entry['size'], needle, control):
                                hits.append((entry, offset, before, after))
                                if len(hits) >= limit:
                                    state = f'达到 {limit} 条上限，未搜索全部内容'
                                    break
                            if state == '完成':
                                if proc.stdout.read(1):
                                    raise OSError('输出超过目录记录长度')
                                if proc.wait():
                                    stderr.seek(0)
                                    raise OSError(tsk_error(stderr.read(2000)) or 'icat 读取失败')
                        finally:
                            proc.kill()
                            with control.lock:
                                control.process = None
                except OSError as error:
                    control.check()
                    errors.append(dict(path=entry['path'], offset=entry['offset'], inode=entry['inode'], error=str(error)))
            if state != '完成':
                break
            completed += 1
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
