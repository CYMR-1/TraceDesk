"""只读文件预览。每页保留前后各三个字节，用于解码跨页的 UTF-8 字符。"""
import queue

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QFontMetrics
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QPlainTextEdit, QPushButton, QSizePolicy, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from ..engines.tsk import deleted_source_note
from ..core.preview import PAGE_BYTES, PreviewReader, preview_rows, preview_text
from .tabs import TabbedView
from .metrics import CONTROL_GAP, SECTION_GAP


class FilePreview(QWidget):
    """独立的文件内容视图；读取器只提供字节，视图负责分页和编码选择。"""

    def __init__(self, parent):
        super().__init__(parent)
        self.reader = None
        self.window = b''
        self.size = self.page = 0
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(SECTION_GAP)
        self._build_rows()
        self._build_controls()
        self.clear()

    def _build_controls(self):
        self.encoding_controls = QWidget(self.formats)
        encoding_layout = QHBoxLayout(self.encoding_controls)
        encoding_layout.setContentsMargins(CONTROL_GAP, 0, 0, 0)
        encoding_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        encoding_layout.addWidget(QLabel('编码'))
        self.encoding = QComboBox()
        self.encoding.addItems(('ASCII', 'UTF-8'))
        self.encoding.currentTextChanged.connect(self.render)
        encoding_layout.addWidget(self.encoding)
        self.formats.set_actions(self.encoding_controls, (self.encoding,))

        bar = QHBoxLayout()
        bar.setContentsMargins(0, 0, 0, 0)
        bar.setSpacing(CONTROL_GAP)
        self.status = QLabel()
        self.status.setProperty('role', 'muted')
        self.status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        bar.addWidget(self.status, 1)
        self.previous = QPushButton('上一页')
        self.previous.clicked.connect(lambda: self.turn(-1))
        self.next = QPushButton('下一页')
        self.next.clicked.connect(lambda: self.turn(1))
        bar.addWidget(self.previous)
        bar.addWidget(self.next)
        self._layout.addLayout(bar)

    def _set_status(self, message):
        self.status.setText(message)
        self.status.setToolTip(message)

    def _build_rows(self):
        fixed = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        if 'Consolas' in QFontDatabase.families():
            fixed.setFamily('Consolas')
        fixed.setPointSizeF(10.5)
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
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(fixed)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.formats = TabbedView()
        self.formats.layout().setSpacing(SECTION_GAP)
        self.formats.addTab(self.text, '文本')
        self.formats.addTab(self.rows, '十六进制')
        self._layout.addWidget(self.formats, 1)

    def clear(self, message='请选择文件'):
        if self.reader:
            self.reader.close()
            self.reader = None
        self.page = self.size = 0
        self.window = b''
        self.source_note = ''
        self.rows.clear()
        self.text.clear()
        self._set_status(message)
        self.previous.setEnabled(False)
        self.next.setEnabled(False)

    def open_file(self, image, entry):
        self.clear()
        self.source_note = deleted_source_note(entry)
        self.size = entry['size']
        if self.size:
            self._set_status('正在读取…')
            self.reader = PreviewReader(image, entry, page_bytes=PAGE_BYTES)
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
        self.text.verticalScrollBar().setValue(0)
        count = (self.size + PAGE_BYTES - 1) // PAGE_BYTES
        self._set_status(' · '.join(filter(None, (f'第 {page + 1} / {count} 页', self.source_note, note))))
        self.previous.setEnabled(page > 0)
        self.next.setEnabled(page + 1 < count)

    def render(self, event=None):
        position = self.vertical.value()
        self.rows.clear()
        self.rows.addTopLevelItems([
            QTreeWidgetItem(values)
            for values in preview_rows(self.window, self.page * PAGE_BYTES, self.size, self.encoding.currentText(), page_bytes=PAGE_BYTES)
        ])
        self.text.setPlainText(preview_text(self.window, self.page * PAGE_BYTES, self.size, self.encoding.currentText(), page_bytes=PAGE_BYTES))
        self.vertical.setValue(position)
