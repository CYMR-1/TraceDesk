"""只读文件预览。每页保留前后各三个字节，用于解码跨页的 UTF-8 字符。"""
import queue
import subprocess
import tempfile
import threading
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QFontMetrics
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QGridLayout, QHeaderView, QLabel,
    QMessageBox, QPushButton, QSizePolicy, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from .tsk import TSK, deleted_source_note, tsk_error


ROW_BYTES = 16
PAGE_BYTES = 4096


def preview_rows(window, start, size, encoding):
    prefix = min(3, start)
    data = window[prefix:prefix + min(PAGE_BYTES, size - start)]
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

    def __init__(self, image, entry):
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
            command = tool.command('icat', args)
            with tempfile.TemporaryFile() as errors, tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as cache:
                with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors,
                                      creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as process:
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
            start = max(0, page * PAGE_BYTES - 3)
            end = min(offsets[-1], (page + 1) * PAGE_BYTES + 3)
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
            start = page * PAGE_BYTES
            left = max(0, start - 3)
            right = min(size, start + PAGE_BYTES + 3)
            if right > cached:
                # 最后一页多读一个字节以确认 EOF 和 icat 的退出状态。
                expected = right - cached
                requested = expected + int(right == size)
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
                cached = right
            cache.seek(left)
            self.results.put((page, cache.read(right - left), size, note))


class FilePreview(QWidget):
    """独立的文件内容视图；读取器只提供字节，视图负责分页和编码选择。"""

    def __init__(self, parent):
        super().__init__(parent)
        self.reader = None
        self.window = b''
        self.size = self.page = 0
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 4, 0, 0)
        self._layout.setSpacing(6)
        self._build_toolbar()
        self._build_rows()
        self.clear()

    def _build_toolbar(self):
        bar = QGridLayout()
        bar.setContentsMargins(0, 0, 0, 0)
        bar.setHorizontalSpacing(8)
        title = QLabel('文件内容')
        title.setProperty('role', 'section')
        bar.addWidget(title, 0, 0)
        bar.addWidget(QLabel('字符编码'), 0, 1)
        self.encoding = QComboBox()
        self.encoding.addItems(('ASCII', 'UTF-8'))
        self.encoding.currentTextChanged.connect(self.render)
        bar.addWidget(self.encoding, 0, 2)
        bar.setColumnStretch(3, 1)
        self.previous = QPushButton('上一页')
        self.previous.clicked.connect(lambda: self.turn(-1))
        self.next = QPushButton('下一页')
        self.next.clicked.connect(lambda: self.turn(1))
        bar.addWidget(self.previous, 0, 4)
        bar.addWidget(self.next, 0, 5)
        self.status_details = QPushButton('状态详情')
        self.status_details.setFlat(True)
        self.status_details.clicked.connect(self._show_status)
        bar.addWidget(self.status_details, 0, 6)
        # 单独的弹性状态行保留完整文字，长提示不会挤走翻页控件。
        self.status = QLabel()
        self.status.setProperty('role', 'muted')
        self.status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        bar.addWidget(self.status, 1, 0, 1, 7)
        self._layout.addLayout(bar)

    def _show_status(self):
        if self.status.text():
            QMessageBox.information(self, '文件预览状态', self.status.text())

    def _set_status(self, message):
        self.status.setText(message)
        self.status.setToolTip(message)

    def _build_rows(self):
        fixed = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        fixed.setPointSize(11)
        metrics = QFontMetrics(fixed)
        self.rows = QTreeWidget()
        self.rows.setObjectName('hexPreview')
        self.rows.setColumnCount(3)
        self.rows.setHeaderLabels(('文件偏移 (HEX)', '十六进制', '字符'))
        self.rows.setFont(fixed)
        self.rows.setRootIsDecorated(False)
        self.rows.setUniformRowHeights(True)
        self.rows.setAlternatingRowColors(True)
        self.rows.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rows.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.rows.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.rows.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.rows.header().setStretchLastSection(True)
        for column, characters in enumerate((16, 48, 20)):
            self.rows.setColumnWidth(column, metrics.horizontalAdvance('0') * characters + 20)
        self.vertical = self.rows.verticalScrollBar()
        self.horizontal = self.rows.horizontalScrollBar()
        self._layout.addWidget(self.rows, 1)

    def clear(self, message='请选择文件'):
        if self.reader:
            self.reader.close()
            self.reader = None
        self.page = self.size = 0
        self.window = b''
        self.source_note = ''
        self.rows.clear()
        self._set_status(message)
        self.previous.setEnabled(False)
        self.next.setEnabled(False)

    def open_file(self, image, entry):
        self.clear()
        self.source_note = deleted_source_note(entry)
        self.size = entry['size']
        if self.size:
            self._set_status('正在读取…')
            self.reader = PreviewReader(image, entry)
        else:
            self._set_status('删除记录为 0 字节，无内容可显示' if entry.get('deleted') else '空文件（0 字节）')

    def turn(self, direction):
        if self.reader is None or not 0 <= self.page + direction < (self.size + PAGE_BYTES - 1) // PAGE_BYTES:
            return
        self.previous.setEnabled(False)
        self.next.setEnabled(False)
        self._set_status('正在读取…')
        self.reader.pages.put(self.page + direction)

    def poll(self):
        if self.reader is None:
            return
        try:
            page, value, size, note = self.reader.results.get_nowait()
        except queue.Empty:
            return
        if page is None:
            self.clear('读取失败：' + note)
            return
        self.page, self.window, self.size = page, value, size
        self.render()
        self.vertical.setValue(0)
        count = (self.size + PAGE_BYTES - 1) // PAGE_BYTES
        self._set_status(' · '.join(filter(None, (f'第 {page + 1} / {count} 页', self.source_note, note))))
        self.previous.setEnabled(page > 0)
        self.next.setEnabled(page + 1 < count)

    def render(self, event=None):
        position = self.vertical.value()
        self.rows.clear()
        self.rows.addTopLevelItems([
            QTreeWidgetItem(values)
            for values in preview_rows(self.window, self.page * PAGE_BYTES, self.size, self.encoding.currentText())
        ])
        self.vertical.setValue(position)
