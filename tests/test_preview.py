import io
import queue
import shutil
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QTreeWidgetItemIterator

from forensic.gui import App
from forensic.preview import PAGE_BYTES, PreviewReader, preview_rows
from forensic.tsk import ROOT, TSK


class PreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def test_utf8_across_rows_and_pages(self):
        raw = b'a' * 15 + '取'.encode() + b'b' * (PAGE_BYTES - 19) + '🙂'.encode() + b'\xff\r\n'
        first = list(preview_rows(raw[:PAGE_BYTES + 3], 0, len(raw), 'UTF-8'))
        second = list(preview_rows(raw[PAGE_BYTES - 3:], PAGE_BYTES, len(raw), 'UTF-8'))
        self.assertEqual(first[0][2], 'a' * 15 + '取')
        self.assertEqual(first[1][2], 'b' * 14)
        self.assertEqual(first[-1][2], 'b' * 15 + '🙂')
        self.assertEqual(second, [('00001000', '9F 99 82 FF 0D 0A', '�··')])

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

        with patch('forensic.preview.PAGE_BYTES', 32):
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
        reader.pages, reader.results, reader.closed = queue.Queue(), queue.Queue(), threading.Event()
        for page in (0, 1, 0, None):
            reader.pages.put(page)
        raw = bytes(range(51))
        process = SimpleNamespace(stdout=io.BytesIO(raw), wait=lambda: 1)
        with patch('forensic.preview.PAGE_BYTES', 32):
            reader._read_pages(process, io.BytesIO(b'read error'), io.BytesIO(), 100, deleted=True)
        self.assertEqual(reader.results.get_nowait()[:3], (0, raw[:35], 100))
        page, data, size, note = reader.results.get_nowait()
        self.assertEqual((page, data, size), (1, raw[29:], 51))
        self.assertIn('51 / 100', note)
        self.assertEqual(reader.results.get_nowait(), (0, raw[:35], size, note))
