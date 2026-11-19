import io
import queue
import shutil
import struct
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from PySide6.QtCore import QBuffer, QIODevice, Qt
from PySide6.QtGui import QColor, QImage
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QMainWindow, QTreeWidgetItemIterator, QVBoxLayout

from forensic.ui.controller import App
from forensic.ui.appearance import DesktopAppearance
from forensic.core.preview import PREVIEW_ENCODINGS
from forensic.ui.preview import FilePreview, PAGE_BYTES, PreviewReader, preview_rows, preview_text
from forensic.engines.tsk import TSK
from forensic.paths import ROOT


class PreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def image_preview(self, data, name='photo.png'):
        test_root = ROOT / '.test-work'
        test_root.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=test_root)
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / 'image.dd'
        # 两段不连续区域，验证完整图像读取与十六进制分页共享只读来源。
        split = len(data) // 2
        source.write_bytes(data[:split] + b'gap' + data[split:])
        preview = FilePreview(None)
        preview.resize(600, 350)
        preview.show()
        self.addCleanup(preview.deleteLater)
        self.addCleanup(preview.clear)
        entry = dict(path=name, size=len(data), extents=[[0, split], [split + 3, len(data) - split]])
        preview.open_file(source, entry)
        self.wait_preview(preview)
        return preview, source, entry

    def wait_preview(self, preview):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.qt.processEvents()
            preview.poll()
            if preview._image_checked and preview.image_reader is None and preview.status.text() != '正在读取…':
                return
            time.sleep(.01)
        self.fail('预览读取超时：' + preview.status.text())

    def test_image_content_detection_full_read_resize_hex_and_text_switch(self):
        picture = QImage(128, 96, QImage.Format.Format_RGB32)
        picture.fill(QColor('#087f6b'))
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        # BMP 超过一页，且扩展名不提示图片，验证实际文件头识别。
        self.assertTrue(picture.save(buffer, 'BMP'))
        data = bytes(buffer.data())
        self.assertGreater(len(data), PAGE_BYTES)
        preview, source, entry = self.image_preview(data, 'photo.bin')
        self.assertEqual(preview.formats.tabBar().tabText(0), '图片')
        self.assertEqual(preview.image.original.toImage().pixelColor(64, 48), QColor('#087f6b'))
        self.assertFalse(preview.next.isVisible())
        self.assertFalse(preview.encoding_controls.isVisible())
        preview.resize(400, 250)
        self.qt.processEvents()
        pixmap = preview.image.pixmap()
        self.assertLessEqual(pixmap.width(), preview.image.width())
        self.assertLessEqual(pixmap.height(), preview.image.height())
        self.assertAlmostEqual(pixmap.width() / pixmap.height(), 128 / 96, places=1)
        preview.formats.setCurrentIndex(1)
        self.assertTrue(preview.next.isVisible())
        self.assertTrue(preview.next.isEnabled())
        preview.next.click()
        self.wait_preview(preview)
        self.assertEqual(preview.rows.topLevelItem(0).text(0), '00001000')
        preview.formats.setCurrentIndex(0)
        self.assertIn('128 × 96', preview.status.text())
        self.assertFalse(preview.image.original.isNull())
        preview.open_file(source, dict(path='text.txt', size=3, extents=[[len(data) // 2, 3]]))
        self.wait_preview(preview)
        self.assertEqual(preview.formats.tabBar().tabText(0), '文本')
        self.assertEqual(preview.text.toPlainText(), 'gap')
        self.assertTrue(preview.image.original.isNull())
        self.assertTrue(preview.encoding_controls.isVisible())

    def test_corrupt_and_oversized_images_keep_hex_available(self):
        preview, source, entry = self.image_preview(b'broken PNG data', 'broken.PNG')
        self.assertIn('损坏', preview.status.text())
        preview.formats.setCurrentIndex(1)
        self.assertEqual(preview.rows.topLevelItem(0).text(1), b'broken PNG data'.hex(' ').upper())
        with patch('forensic.ui.preview.MAX_IMAGE_BYTES', 4):
            preview.open_file(source, entry)
            self.wait_preview(preview)
        self.assertIn('预览上限', preview.status.text())
        self.assertIsNone(preview.image_reader)
        preview.clear()
        self.assertEqual(preview.status.text(), '请选择文件')
        self.assertEqual(preview.formats.tabBar().tabText(0), '文本')

    def test_image_from_real_fat_file_via_tsk(self):
        picture = QImage(16, 16, QImage.Format.Format_RGB32)
        picture.fill(QColor('#8752c4'))
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        self.assertTrue(picture.save(buffer, 'BMP'))
        raw = bytes(buffer.data())
        temp = tempfile.TemporaryDirectory(dir=ROOT / '.test-work')
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / 'fat.dd'
        shutil.copyfile(ROOT / 'evidence' / 'demo.dd', source)
        directory = (2048 + 1 + 2 * 64) * 512
        with source.open('r+b') as stream:
            stream.seek(directory + 3 * 32)
            record = bytearray(stream.read(32))
            cluster = struct.unpack_from('<H', record, 26)[0]
            record[:11] = b'PHOTO   BMP'
            struct.pack_into('<I', record, 28, len(raw))
            stream.seek(directory + 3 * 32)
            stream.write(record)
            stream.seek(directory + 32 * 512 + (cluster - 2) * 512)
            stream.write(raw)
        entry = next(e for e in TSK().files(source, 2048) if e['path'] == 'PHOTO.BMP')
        preview = FilePreview(None)
        self.addCleanup(preview.deleteLater)
        self.addCleanup(preview.clear)
        preview.open_file(source, entry)
        self.wait_preview(preview)
        self.assertIn('16 × 16', preview.status.text())
        self.assertEqual(preview.image.original.toImage().pixelColor(0, 0), QColor('#8752c4'))

    def test_switching_files_cancels_pending_image_and_ignores_old_results(self):
        preview, source, entry = self.image_preview(b'broken image', 'broken.png')
        stale_reader = SimpleNamespace(close=unittest.mock.Mock(), results=queue.Queue())
        preview.image_reader = stale_reader
        preview.open_file(source, dict(entry, path='text.txt'))
        stale_reader.close.assert_called_once()
        stale_reader.results.put((0, b'old image', 9, ''))
        self.wait_preview(preview)
        self.assertEqual(preview.formats.tabBar().tabText(0), '文本')
        self.assertEqual(preview.text.toPlainText(), 'broken image')

    def test_image_switch_never_temporarily_changes_tab_to_text(self):
        raw = (ROOT / 'forensic/assets/tracedesk.png').read_bytes()
        preview, source, entry = self.image_preview(raw)
        for name in ('second.png', 'image-without-extension'):
            with self.subTest(name=name), patch.object(
                    preview.formats.tabBar(), 'setTabText', wraps=preview.formats.tabBar().setTabText) as change:
                preview.open_file(source, dict(entry, path=name))
                self.assertEqual(preview.formats.tabBar().tabText(0), '图片')
                self.assertTrue(preview.formats.isVisible())
                self.assertTrue(preview.image.original.isNull(), '不能在新文件名下显示旧图片')
                self.wait_preview(preview)
                self.assertFalse(preview.image.original.isNull())
                self.assertEqual(preview.formats.tabBar().tabText(0), '图片')
                self.assertNotIn(unittest.mock.call(0, '文本'), change.call_args_list)

    def test_no_selection_hides_formats_encoding_and_paging(self):
        preview = FilePreview(None)
        self.addCleanup(preview.deleteLater)
        self.addCleanup(preview.clear)
        preview.show()
        self.qt.processEvents()
        self.assertFalse(preview.formats.isVisible())
        self.assertFalse(preview.status.isVisible())
        self.assertFalse(preview.previous.isVisible())
        self.assertFalse(preview.next.isVisible())
        self.assertFalse(preview.encoding.isVisible())
        raw = (ROOT / 'forensic/assets/tracedesk.png').read_bytes()
        loaded, _, _ = self.image_preview(raw)
        loaded.clear('请选择目录中的文件')
        self.qt.processEvents()
        self.assertFalse(loaded.formats.isVisible())
        self.assertFalse(loaded.status.isVisible())
        self.assertFalse(loaded.previous.isVisible())
        self.assertIsNone(loaded.reader)
        self.assertIsNone(loaded.image_reader)

    def test_utf8_across_rows_and_pages(self):
        raw = b'a' * 15 + '取'.encode() + b'b' * (PAGE_BYTES - 19) + '🙂'.encode() + b'\xff\r\n'
        first = list(preview_rows(raw[:PAGE_BYTES + 3], 0, len(raw), 'UTF-8'))
        second = list(preview_rows(raw[PAGE_BYTES - 3:], PAGE_BYTES, len(raw), 'UTF-8'))
        self.assertEqual(first[0][2], 'a' * 15 + '取')
        self.assertEqual(first[1][2], 'b' * 14)
        self.assertEqual(first[-1][2], 'b' * 15 + '🙂')
        self.assertEqual(second, [('00001000', '9F 99 82 FF 0D 0A', '�··')])

    def test_text_preview_keeps_newlines_and_utf8_page_boundaries(self):
        raw = b'a' * (PAGE_BYTES - 1) + '取证\n\t'.encode() + b'\xff\x00'
        head = preview_text(raw[:PAGE_BYTES + 3], 0, len(raw), 'UTF-8')
        tail = preview_text(raw[PAGE_BYTES - 3:], PAGE_BYTES, len(raw), 'UTF-8')
        self.assertEqual(head + tail, 'a' * (PAGE_BYTES - 1) + '取证\n\t�·')
        self.assertEqual(preview_text(b'A\r\n\x00', 0, 4, 'ASCII'), 'A\r\n·')
        self.assertEqual(preview_text(b'\x80\xe9', 0, 2, 'Windows-1252'), '€é')
        self.assertEqual(preview_text(b'\x80\xe9', 0, 2, 'ISO-8859-1'), '·é')

    def test_chinese_and_utf16_encodings_after_direct_page_jump(self):
        for encoding, sample in (('GBK', '取证'), ('Big5', '鑑識'), ('GB18030', '取🙂'),
                                 ('UTF-16LE', '证🙂'), ('UTF-16BE', '证🙂')):
            with self.subTest(encoding=encoding):
                value = 'A' + sample * 3000
                raw = value.encode(encoding)
                preview, _, _ = self.image_preview(raw, 'test.txt')
                # 先以 ASCII 直接跳到第三页，再按所选编码重新同步。
                preview.turn(2)
                self.wait_preview(preview)
                preview.encoding.setCurrentText(encoding)
                self.wait_preview(preview)
                index = 0
                expected = []
                for char in value:
                    if 2 * PAGE_BYTES <= index < 3 * PAGE_BYTES:
                        expected.append(char)
                    index += len(char.encode(encoding))
                self.assertEqual(preview.text.toPlainText(), ''.join(expected))
                self.assertEqual(''.join(preview.rows.topLevelItem(i).text(2)
                                         for i in range(preview.rows.topLevelItemCount())), ''.join(expected))

    def test_encoding_popup_in_preview_dialog(self):
        dialog = QDialog()
        self.addCleanup(dialog.deleteLater)
        DesktopAppearance(dialog).configure()
        layout = QVBoxLayout(dialog)
        preview = FilePreview(dialog)
        layout.addWidget(preview)
        preview._has_file = True
        preview._update_controls()
        dialog.resize(860, 550)
        dialog.show()
        self.qt.processEvents()
        combo = preview.encoding
        combo.showPopup()
        self.qt.processEvents()
        view = combo.view()
        try:
            # Windows 可能先播放弹出动画，然后才显示接收点击的列表。
            deadline = time.monotonic() + 2
            while not view.isVisible() and time.monotonic() < deadline:
                QTest.qWait(10)
            self.assertTrue(view.isVisible())
            self.assertEqual([combo.itemText(i) for i in range(combo.count())], list(PREVIEW_ENCODINGS))
            for row in range(combo.count()):
                rect = view.visualRect(view.model().index(row, 0))
                self.assertTrue(view.viewport().rect().contains(rect), (row, rect, view.viewport().rect()))
                self.assertGreaterEqual(rect.width(), view.fontMetrics().horizontalAdvance(combo.itemText(row)))
            last = view.model().index(combo.count() - 1, 0)
            QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton, pos=view.visualRect(last).center())
            self.assertEqual(combo.currentText(), 'ISO-8859-1')
        finally:
            combo.hidePopup()
            dialog.close()

    def test_file_selection_encoding_paging_and_resize(self):
        test_root = ROOT / '.test-work'
        test_root.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=test_root)
        self.addCleanup(temp.cleanup)
        image = Path(temp.name) / 'demo.dd'
        shutil.copyfile(ROOT / 'evidence' / 'demo.dd', image)
        # FAT16 测试镜像根目录中，追加两个同名删除项。第二项仍指向 NOTES.TXT 的簇。
        directory = (2048 + 1 + 2 * 64) * 512
        with image.open('r+b') as stream:
            stream.seek(directory + 32)
            record = bytearray(stream.read(32))
            record[0] = 0xe5
            empty = record.copy()
            empty[26:32] = bytes(6)
            stream.seek(directory + 5 * 32)
            stream.write(empty + record)
        entries = TSK().files(image, 2048)
        root = QMainWindow()
        root.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen)
        app = App(root)
        self.addCleanup(root.deleteLater)
        self.addCleanup(app.close)
        app.case = SimpleNamespace(image=lambda: image, close=lambda: None)
        app.display(entries)
        root.show()
        self.qt.processEvents()
        preview = app.preview
        split = app.browser.split
        initial_sizes = split.sizes()
        height = preview.height()
        split.setSizes([initial_sizes[0] - 35, initial_sizes[1] + 35])
        self.qt.processEvents()
        self.assertGreater(preview.height(), height)

        def items():
            iterator = QTreeWidgetItemIterator(app.tree)
            while iterator.value():
                yield iterator.value()
                iterator += 1

        def select(path):
            item = next(item for item in items()
                        if (entry := item.data(0, Qt.ItemDataRole.UserRole)) and entry['path'] == path)
            app.tree.setCurrentItem(item)
            self.qt.processEvents()

        def read_page():
            deadline = time.monotonic() + 5
            while preview.status.text() == '正在读取…' and time.monotonic() < deadline:
                self.qt.processEvents()
                time.sleep(0.01)
            self.assertTrue(preview.status.text().startswith('第 '), preview.status.text())
            return [tuple(preview.rows.topLevelItem(row).text(column) for column in range(3))
                    for row in range(preview.rows.topLevelItemCount())]

        with patch('forensic.ui.preview.PAGE_BYTES', 32):
            select('DOCS/CASE.TXT')
            self.assertEqual(read_page()[0][2], 'Case note inside')
            select('PAYLOAD.BIN')
            select('NOTES.TXT')
            ascii_rows = read_page()
            self.assertEqual(ascii_rows[0][2], '·' * 16)
            preview.encoding.setCurrentText('UTF-8')
            self.qt.processEvents()
            utf8_rows = read_page()
            self.assertEqual(utf8_rows[0][:2], ascii_rows[0][:2])
            preview.next.click()
            tail = read_page()
            self.assertEqual(tail[0][0], '00000020')
            self.assertEqual(''.join(row[2] for row in utf8_rows + tail), '取证演示：证据固定、审计、文件导出。··')
            preview.previous.click()
            self.assertEqual(read_page(), utf8_rows)
            select('DOCS')
            self.assertEqual(preview.rows.topLevelItemCount(), 0)
            self.assertIsNone(preview.reader)

            original = next(e for e in entries if e['path'] == 'NOTES.TXT')
            deleted = [e for e in entries if e.get('deleted')]
            self.assertEqual([e['size'] for e in deleted], [0, original['size']])
            area = dict(original, path='测试区域', mode='v/v', inode='', size=32, extents=[[510, 4], [0, 28]])
            app.display([*deleted, area])
            matches = [item for item in items() if item.text(0) == deleted[0]['path']]
            self.assertEqual([item.data(0, Qt.ItemDataRole.UserRole)['inode'] for item in matches],
                             [e['inode'] for e in deleted])
            app.tree.setCurrentItem(matches[0])
            self.qt.processEvents()
            self.assertIn('0 字节', preview.status.text())
            self.assertEqual(preview.rows.topLevelItemCount(), 0)
            app.tree.setCurrentItem(matches[1])
            self.qt.processEvents()
            self.assertEqual(read_page(), utf8_rows)
            self.assertIn('已删除', preview.status.text())
            preview.next.click()
            self.assertEqual(read_page(), tail)
            preview.encoding.setCurrentText('ASCII')
            preview.previous.click()
            self.assertEqual(read_page(), ascii_rows)
            select('测试区域')
            with image.open('rb') as source:
                head = source.read(28)
                source.seek(510)
                expected = source.read(4) + head
            self.assertEqual(bytes.fromhex(' '.join(row[1] for row in read_page())), expected)

    def test_partial_deleted_preview_keeps_pages_after_read_error(self):
        reader = PreviewReader.__new__(PreviewReader)
        reader.page_bytes = 32
        reader.pages, reader.results, reader.closed = queue.Queue(), queue.Queue(), threading.Event()
        for page in (0, 3, 0, None):
            reader.pages.put(page)
        raw = bytes(range(51))
        process = SimpleNamespace(stdout=io.BytesIO(raw), wait=lambda: 1)
        reader._read_pages(process, io.BytesIO(b'read error'), io.BytesIO(), 100, deleted=True)
        self.assertEqual(reader.results.get_nowait()[:3], (0, raw[:35], 100))
        page, data, size, note = reader.results.get_nowait()
        self.assertEqual((page, data, size), (1, raw[29:], 51))
        self.assertIn('51 / 100', note)
        self.assertEqual(reader.results.get_nowait(), (0, raw[:35], size, note))
