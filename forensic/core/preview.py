"""后台只读字节读取与文本/十六进制格式化，不依赖 Qt。"""
import codecs
import queue
import re
import subprocess
import tempfile
import threading
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path

from ..engines.tsk import TSK, tsk_error
from ..engines.random_read import VolumeReader
from contextlib import closing


ROW_BYTES = 16
PAGE_BYTES = 4096


PREVIEW_ENCODINGS = ('ASCII', 'UTF-8', 'UTF-16LE', 'UTF-16BE', 'GBK', 'GB18030', 'Big5',
                     'Windows-1252', 'ISO-8859-1')
LEGACY_MULTIBYTE = {'GBK', 'GB18030', 'Big5'}


class PageWindow(bytes):
    """保留原始字节，以及从文件起点解码时延续到本页的字符长度。"""
    encoding = None
    carry = 0


def page_characters(window, start, size, encoding, page_bytes):
    prefix = min(3, start)
    length = min(page_bytes, max(0, size - start))
    index = 0
    if encoding.startswith('UTF-16'):
        index = -(start - prefix) % 2
    elif encoding in LEGACY_MULTIBYTE:
        index = prefix - getattr(window, 'carry', prefix)
    unit_order = {'UTF-16LE': 'little', 'UTF-16BE': 'big'}.get(encoding)
    while index < len(window) and index - prefix < length:
        byte = window[index]
        step = 1
        if encoding == 'ASCII':
            char = chr(byte) if byte < 128 else '·'
        else:
            if unit_order:
                unit = int.from_bytes(window[index:index + 2], unit_order)
                step = 4 if 0xD800 <= unit <= 0xDBFF else 2
            elif encoding == 'UTF-8' and byte >= 0xC2:
                step = 2 if byte < 0xE0 else 3 if byte < 0xF0 else 4
            elif encoding in LEGACY_MULTIBYTE and 0x81 <= byte <= 0xFE:
                step = 4 if (encoding == 'GB18030' and index + 1 < len(window)
                             and 0x30 <= window[index + 1] <= 0x39) else 2
            try:
                char = window[index:index + step].decode(encoding)
            except UnicodeDecodeError:
                step = 2 if unit_order else 1
                char = '�'
        if index >= prefix:
            yield index - prefix, char
        index += step


def preview_text(window, start, size, encoding, page_bytes=PAGE_BYTES):
    return ''.join(char if char.isprintable() or char in '\r\n\t' else '·'
                   for _, char in page_characters(window, start, size, encoding, page_bytes))


def preview_rows(window, start, size, encoding, page_bytes=PAGE_BYTES):
    prefix = min(3, start)
    data = window[prefix:prefix + min(page_bytes, size - start)]
    strings = [''] * ((len(data) + ROW_BYTES - 1) // ROW_BYTES)
    for offset, char in page_characters(window, start, size, encoding, page_bytes):
        strings[offset // ROW_BYTES] += char if char.isprintable() else '·'
    for row, chars in enumerate(strings):
        i = row * ROW_BYTES
        yield (f'{start + i:08X}', data[i:i + ROW_BYTES].hex(' ').upper(), chars)


class PreviewReader:
    """在后台按需读取 icat 字节流，缓存已查看的部分以便向前翻页。"""

    def __init__(self, image, entry, page_bytes=PAGE_BYTES, encoding='ASCII', validate=None):
        self.encoding = encoding
        self.checkpoint = None
        self.page_bytes = page_bytes
        self.pages = queue.Queue()
        self.results = queue.Queue()
        self.closed = threading.Event()
        self.process = None
        self.pages.put(0)
        threading.Thread(target=self._run, args=(image, entry, validate), daemon=True).start()

    def close(self):
        self.closed.set()
        self.pages.put(None)
        process = self.process
        if process is not None:
            process.kill()

    def _run(self, image, entry, validate=None):
        try:
            if validate:
                validate()
            if not Path(image).is_file():
                raise FileNotFoundError(f'案件记录的镜像不存在：{image}')
            if 'extents' in entry:
                with open(image, 'rb') as source:
                    self._read_extents(source, entry['extents'])
                return
            if (entry['size'] >= 8 << 20 and not entry.get('deleted')
                    and entry['mode'].startswith('r/')):
                try:
                    with closing(VolumeReader(image)) as reader:
                        read_at = reader.open_entry(entry)
                        while not self.closed.is_set():
                            page = self.pages.get()
                            if page is None:
                                break
                            try:
                                self._publish(page, entry['size'], '', read_at)
                            except (OSError, ValueError, RuntimeError):
                                self.pages.put(page)
                                raise
                        return
                except (OSError, ValueError, RuntimeError):
                    if self.closed.is_set():
                        return
                    # 无法随机读取的属性沿用 icat 预览路径。
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

        def read_at(start, length):
            end = min(offsets[-1], start + length)
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
            return bytes(window)

        while not self.closed.is_set():
            page = self.pages.get()
            if page is None:
                return
            self._publish(page, offsets[-1], '', read_at)

    def _publish(self, page, size, note, read_at):
        start = page * self.page_bytes
        left = max(0, start - 3)
        end = min(size, start + self.page_bytes + 3)
        window = PageWindow(read_at(left, end - left))
        encoding = getattr(self, 'encoding', 'ASCII')
        if start and encoding in LEGACY_MULTIBYTE:
            window.carry = self._legacy_carry(start, encoding, read_at)
        window.encoding = encoding
        self.results.put((page, window, size, note))

    def _legacy_carry(self, start, encoding, read_at):
        # GBK 等的首、尾字节范围重叠。跳页时从确定的字符边界同步，
        # 顺序翻页时复用上次的解码器状态，避免将连续中文错开一个字节。
        lower, pending = 0, b''
        if self.checkpoint:
            codec, offset, saved = self.checkpoint
            if codec == encoding and offset <= start:
                lower, pending = offset, saved
        pos = start
        while pos > lower and not self.closed.is_set():
            left = max(lower, pos - 65536)
            block = read_at(left, pos - left)
            # 0x00–0x2F 均不能作为这些编码的续字节。
            anchor = re.search(rb'[\x00-\x2f][^\x00-\x2f]*\Z', block)
            if anchor:
                lower, pending = left + anchor.start() + 1, b''
                break
            pos = left
        decoder = codecs.getincrementaldecoder(encoding)(errors='replace')
        decoder.setstate((pending, 0))
        while lower < start and not self.closed.is_set():
            chunk = read_at(lower, min(start - lower, 65536))
            if not chunk:
                raise OSError('无法读取预览页前的编码边界')
            decoder.decode(chunk)
            lower += len(chunk)
        carry = decoder.getstate()[0]
        self.checkpoint = encoding, start, carry
        return len(carry)

    def _read_pages(self, process, errors, cache, recorded_size, deleted):
        size = recorded_size
        note = ''
        cached = 0

        def read_at(offset, length):
            cache.seek(offset)
            return cache.read(length)

        while not self.closed.is_set():
            page = self.pages.get()
            if page is None:
                return
            start = page * self.page_bytes
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
            self._publish(page, size, note, read_at)
