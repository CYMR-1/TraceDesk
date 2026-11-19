"""后台只读字节读取与文本/十六进制格式化，不依赖 Qt。"""
import queue
import subprocess
import tempfile
import threading
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path

from ..engines.tsk import TSK, tsk_error


ROW_BYTES = 16
PAGE_BYTES = 4096


def preview_text(window, start, size, encoding, page_bytes=PAGE_BYTES):
    """按字符起始字节归属页面，保留文本换行且不重复跨页 UTF-8 字符。"""
    prefix = min(3, start)
    length = min(page_bytes, max(0, size - start))
    if encoding == 'ASCII':
        return ''.join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else '·'
                       for b in window[prefix:prefix + length])
    result, index = [], -prefix
    for char in window.decode('utf-8', errors='surrogateescape'):
        if 0 <= index < length:
            result.append(char if char.isprintable() or char in '\r\n\t' else
                          '�' if 0xDC80 <= ord(char) <= 0xDCFF else '·')
        index += len(char.encode('utf-8', errors='surrogateescape'))
    return ''.join(result)


def preview_rows(window, start, size, encoding, page_bytes=PAGE_BYTES):
    prefix = min(3, start)
    data = window[prefix:prefix + min(page_bytes, size - start)]
    strings = [''] * ((len(data) + ROW_BYTES - 1) // ROW_BYTES)
    if encoding == 'ASCII':
        for i, byte in enumerate(data):
            strings[i // ROW_BYTES] += chr(byte) if 32 <= byte < 127 else '·'
    else:
        # 每个字符只出现一次，归到其首字节所在行。非法字节各占一个替换符。
        index = -prefix
        for char in window.decode('utf-8', errors='surrogateescape'):
            if 0 <= index < len(data):
                if 0xDC80 <= ord(char) <= 0xDCFF:
                    display = '�'
                else:
                    display = char if char.isprintable() else '·'
                strings[index // ROW_BYTES] += display
            index += len(char.encode('utf-8', errors='surrogateescape'))
    for row, chars in enumerate(strings):
        i = row * ROW_BYTES
        yield (f'{start + i:08X}', data[i:i + ROW_BYTES].hex(' ').upper(), chars)


class PreviewReader:
    """在后台按需读取 icat 字节流，缓存已查看的部分以便向前翻页。"""

    def __init__(self, image, entry, page_bytes=PAGE_BYTES):
        self.page_bytes = page_bytes
        self.pages = queue.Queue()
        self.results = queue.Queue()
        self.closed = threading.Event()
        self.process = None
        self.pages.put(0)
        threading.Thread(target=self._run, args=(image, entry), daemon=True).start()

    def close(self):
        self.closed.set()
        self.pages.put(None)
        process = self.process
        if process is not None:
            process.kill()

    def _run(self, image, entry):
        try:
            if not Path(image).is_file():
                raise FileNotFoundError(f'案件记录的镜像不存在：{image}')
            if 'extents' in entry:
                with open(image, 'rb') as source:
                    self._read_extents(source, entry['extents'])
                return
            tool = TSK()
            deleted = entry.get('deleted', False)
            args = tool.entry_args(image, entry)
            with tempfile.TemporaryFile() as errors, tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as cache:
                with tool.popen_image('icat', args, stdout=subprocess.PIPE, stderr=errors) as process:
                    self.process = process
                    try:
                        self._read_pages(process, errors, cache, entry['size'], deleted)
                    finally:
                        process.kill()
                        self.process = None
        except Exception as error:
            if not self.closed.is_set():
                self.results.put((None, b'', 0, str(error)))

    def _read_extents(self, source, extents):
        offsets = list(accumulate((length for _, length in extents), initial=0))
        while not self.closed.is_set():
            page = self.pages.get()
            if page is None:
                return
            start = max(0, page * self.page_bytes - 3)
            end = min(offsets[-1], (page + 1) * self.page_bytes + 3)
            index = bisect_right(offsets, start) - 1
            window = bytearray()
            while start < end:
                length = min(end, offsets[index + 1]) - start
                source.seek(extents[index][0] + start - offsets[index])
                data = source.read(length)
                if len(data) != length:
                    raise OSError('空间区域超出当前镜像，请重新读取文件树')
                window.extend(data)
                start += length
                index += 1
            self.results.put((page, bytes(window), offsets[-1], ''))

    def _read_pages(self, process, errors, cache, recorded_size, deleted):
        size = recorded_size
        note = ''
        cached = 0
        while not self.closed.is_set():
            page = self.pages.get()
            if page is None:
                return
            start = page * self.page_bytes
            left = max(0, start - 3)
            right = min(size, start + self.page_bytes + 3)
            while right > cached:
                if self.closed.is_set():
                    return
                # 最后一页多读一个字节以确认 EOF 和 icat 的退出状态。
                expected = min(right - cached, 1024 * 1024)
                requested = expected + int(cached + expected == size)
                chunk = process.stdout.read(requested)
                if len(chunk) < requested and process.wait():
                    errors.seek(0)
                    note = tsk_error(errors.read(2000)) or 'icat 读取异常'
                    if not deleted or not (cached or chunk):
                        raise OSError(note)
                if len(chunk) != expected:
                    if not deleted:
                        raise OSError('读取长度与文件清单不一致，请重新读取文件树')
                    if not (cached or chunk):
                        raise OSError('未能从该删除记录读取数据')
                    if len(chunk) < expected:
                        # 已删除文件的簇链可能不完整。保留可读前缀，按实际长度翻页。
                        size = right = cached + len(chunk)
                        note = f'可读 {size} / {recorded_size} 字节' + (f' · {note}' if note else '')
                    else:
                        chunk = chunk[:expected]
                        note = '已按目录记录大小截取'
                        process.kill()
                cache.seek(cached)
                cache.write(chunk)
                cached += len(chunk)
            if start >= size and size:
                page = (size - 1) // self.page_bytes
                left = max(0, page * self.page_bytes - 3)
                right = size
            cache.seek(left)
            self.results.put((page, cache.read(right - left), size, note))
