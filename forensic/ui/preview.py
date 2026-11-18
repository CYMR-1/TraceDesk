"""只读文件预览。每页保留前后各三个字节，用于解码跨页的 UTF-8 字符。"""
import queue
from pathlib import Path

from PySide6.QtCore import QBuffer, QIODevice, QSize, Qt
from PySide6.QtGui import QFontDatabase, QFontMetrics, QImageReader, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel,
    QPlainTextEdit, QPushButton, QSizePolicy, QStackedWidget, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from ..engines.tsk import deleted_source_note
from ..core.preview import PAGE_BYTES, PreviewReader, preview_rows, preview_text
from .tabs import TabbedView
from .metrics import CONTROL_GAP, SECTION_GAP


MAX_IMAGE_BYTES = 32 * 1024 * 1024
MAX_IMAGE_PIXELS = 40_000_000
IMAGE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp', '.tif', '.tiff', '.ico'}


class ImagePreview(QLabel):
    """保存解码后的预览图，随可用空间等比例缩放。"""

    def __init__(self):
        super().__init__()
        self.setObjectName('imagePreview')
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWordWrap(True)
        self.setMinimumSize(0, 0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.original = QPixmap()

    def reset(self, message=''):
        self.original = QPixmap()
        self.setText(message)

    def show_image(self, image):
        self.original = QPixmap.fromImage(image)
        self._fit()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit()

    def _fit(self):
        if not self.original.isNull():
            bounds = self.contentsRect().size() - QSize(12, 12)
            if bounds.width() > 0 and bounds.height() > 0:
                self.setPixmap(self.original.scaled(
                    bounds, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))


class FilePreview(QWidget):
    """独立的文件内容视图；读取器只提供字节，视图负责分页和编码选择。"""

    def __init__(self, parent):
        super().__init__(parent)
        self.reader = None
        self.image_reader = None
        self.window = b''
        self.size = self.page = 0
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(SECTION_GAP)
        self._build_rows()
        self._build_controls()
        self.formats.currentChanged.connect(self._update_controls)
        self.clear()

    def _build_controls(self):
        self.encoding_controls = QWidget(self.formats)
        self.encoding_controls.setObjectName('previewEncoding')
        encoding_layout = QHBoxLayout(self.encoding_controls)
        encoding_layout.setContentsMargins(CONTROL_GAP, 0, 0, 0)
        encoding_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        encoding_layout.addWidget(QLabel('编码'))
        self.encoding = QComboBox()
        self.encoding.setObjectName('previewEncodingChoice')
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
        for button in (self.previous, self.next):
            button.setProperty('role', 'pager')
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
        self.image = ImagePreview()
        self.content = QStackedWidget()
        self.content.addWidget(self.text)
        self.content.addWidget(self.image)
        self.formats = TabbedView()
        self.formats.tabBar().setObjectName('previewTabs')
        self.formats.layout().setSpacing(SECTION_GAP)
        self.formats.addTab(self.content, '文本')
        self.formats.addTab(self.rows, '十六进制')
        self._layout.addWidget(self.formats, 1)

    def _reset_data(self):
        """停止旧读取并清空内容，不改变正在显示的格式标签。"""
        if self.image_reader:
            self.image_reader.close()
            self.image_reader = None
        if self.reader:
            self.reader.close()
            self.reader = None
        self.page = self.size = 0
        self.window = b''
        self.source_note = ''
        self._image_checked = False
        self._image_status = ''
        self.image.reset()
        self.rows.clear()
        self.text.clear()
        self.previous.setEnabled(False)
        self.next.setEnabled(False)

    def _set_image_mode(self, enabled):
        self._image_mode = enabled
        self.content.setCurrentWidget(self.image if enabled else self.text)
        title = '图片' if enabled else '文本'
        if self.formats.tabBar().tabText(0) != title:
            self.formats.tabBar().setTabText(0, title)

    def clear(self, message='请选择文件'):
        self._has_file = False
        self.formats.hide()
        self._reset_data()
        self._set_image_mode(False)
        self._page_status = message
        self._update_controls()

    def open_file(self, image, entry):
        self._reset_data()
        self._has_file = True
        self.source_note = deleted_source_note(entry)
        self._source, self._entry = image, dict(entry)
        self.size = entry['size']
        # 常见图片立即显示图片标签；未知类型保持当前标签直到文件头读取完成。
        if Path(entry.get('path', '')).suffix.lower() in IMAGE_SUFFIXES:
            self._set_image_mode(True)
        if self.size:
            self._page_status = self._image_status = '正在读取…'
            self.reader = PreviewReader(image, entry, page_bytes=PAGE_BYTES)
        else:
            self._set_image_mode(False)
            self._page_status = '删除记录为 0 字节，无内容可显示' if entry.get('deleted') else '空文件（0 字节）'
        self._update_controls()

    def turn(self, direction):
        if self.reader is None or not 0 <= self.page + direction < (self.size + PAGE_BYTES - 1) // PAGE_BYTES:
            return
        self.previous.setEnabled(False)
        self.next.setEnabled(False)
        self._set_status('正在读取…')
        self._page_status = self.status.text()
        self.reader.pages.put(self.page + direction)

    def poll(self):
        self._poll_image()
        if self.reader is None:
            return
        try:
            page, value, size, note = self.reader.results.get_nowait()
        except queue.Empty:
            return
        if page is None:
            self._reset_data()
            self._page_status = self._image_status = '读取失败：' + note
            self._update_controls()
            return
        self.page, self.window, self.size = page, value, size
        if not self._image_checked:
            self._image_checked = True
            self._start_image()
        self.render()
        self.vertical.setValue(0)
        self.text.verticalScrollBar().setValue(0)
        count = (self.size + PAGE_BYTES - 1) // PAGE_BYTES
        self._page_status = ' · '.join(filter(None, (f'第 {page + 1} / {count} 页', self.source_note, note)))
        self.previous.setEnabled(page > 0)
        self.next.setEnabled(page + 1 < count)
        self._update_controls()

    def _update_controls(self, event=None):
        showing_image = self._image_mode and self.formats.currentIndex() == 0
        self.formats.setVisible(self._has_file)
        self.status.setVisible(self._has_file)
        self.encoding_controls.setVisible(not showing_image)
        self.previous.setVisible(self._has_file and not showing_image)
        self.next.setVisible(self._has_file and not showing_image)
        self._set_status(self._image_status if showing_image else self._page_status)

    @staticmethod
    def _decoder(data):
        buffer = QBuffer()
        buffer.setData(data)
        buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        decoder = QImageReader(buffer)
        decoder.setDecideFormatFromContent(True)
        decoder.setAutoTransform(True)
        return buffer, decoder

    def _start_image(self):
        # 用文件内容识别格式；保留常见扩展名的损坏图片提示。
        buffer, decoder = self._decoder(self.window)
        if not decoder.canRead() and Path(self._entry.get('path', '')).suffix.lower() not in IMAGE_SUFFIXES:
            self._set_image_mode(False)
            return
        self._set_image_mode(True)
        self._image_status = '正在读取图片…'
        self.image.reset(self._image_status)
        self.formats.setCurrentIndex(0)
        if self._entry['size'] > MAX_IMAGE_BYTES:
            self._image_error('图片超过 32 MiB 预览上限，可导出后查看')
            return
        # 复用后台只读读取器获取完整图片，字节分页仍由原读取器提供。
        self.image_reader = PreviewReader(self._source, self._entry, page_bytes=MAX_IMAGE_BYTES)

    def _image_error(self, message):
        self._image_status = ' · '.join(filter(None, (message, self.source_note)))
        self.image.reset(message + '；可切换十六进制查看原始字节。')
        self._update_controls()

    def _poll_image(self):
        if self.image_reader is None:
            return
        try:
            page, data, size, note = self.image_reader.results.get_nowait()
        except queue.Empty:
            return
        self.image_reader.close()
        self.image_reader = None
        if page is None:
            self._image_error('图片读取失败：' + note)
            return
        buffer, decoder = self._decoder(data)
        dimensions = decoder.size()
        if not dimensions.isValid() or dimensions.isEmpty():
            self._image_error('图片损坏或格式不受支持')
            return
        if dimensions.width() * dimensions.height() > MAX_IMAGE_PIXELS:
            self._image_error('图片超过 4000 万像素预览上限，可导出后查看')
            return
        if max(dimensions.width(), dimensions.height()) > 4096:
            decoder.setScaledSize(dimensions.scaled(QSize(4096, 4096), Qt.AspectRatioMode.KeepAspectRatio))
        decoded = decoder.read()
        if decoded.isNull():
            self._image_error('图片解码失败：' + decoder.errorString())
            return
        self.image.show_image(decoded)
        self._image_status = ' · '.join(filter(None, (
            f'图片 {dimensions.width()} × {dimensions.height()}',
            '首帧' if decoder.supportsAnimation() else '', self.source_note, note)))
        self._update_controls()

    def render(self, event=None):
        position = self.vertical.value()
        self.rows.clear()
        self.rows.addTopLevelItems([
            QTreeWidgetItem(values)
            for values in preview_rows(self.window, self.page * PAGE_BYTES, self.size, self.encoding.currentText(), page_bytes=PAGE_BYTES)
        ])
        self.text.setPlainText(preview_text(self.window, self.page * PAGE_BYTES, self.size, self.encoding.currentText(), page_bytes=PAGE_BYTES))
        self.vertical.setValue(position)
