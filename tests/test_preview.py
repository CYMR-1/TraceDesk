import gc
import io
import queue
import shutil
import tempfile
import threading
import time
import tkinter as tk
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from forensic.gui import App
from forensic.preview import PAGE_BYTES, PreviewReader, preview_rows
from forensic.tsk import ROOT, TSK


class PreviewTests(unittest.TestCase):
    def test_utf8_across_rows_and_pages(self):
        raw = b'a' * 15 + '取'.encode() + b'b' * (PAGE_BYTES - 19) + '🙂'.encode() + b'\xff\r\n'
        first = list(preview_rows(raw[:PAGE_BYTES + 3], 0, len(raw), 'UTF-8'))
        second = list(preview_rows(raw[PAGE_BYTES - 3:], PAGE_BYTES, len(raw), 'UTF-8'))
        self.assertEqual(first[0][2], 'a' * 15 + '取')
        self.assertEqual(first[1][2], 'b' * 14)
        self.assertEqual(first[-1][2], 'b' * 15 + '🙂')
        self.assertEqual(second, [('00001000', '9F 99 82 FF 0D 0A', '�··')])

    def test_file_selection_encoding_paging_and_resize(self):
        temp = tempfile.TemporaryDirectory()
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
        root = tk.Tk()
        callback_errors = []
        root.report_callback_exception = lambda kind, error, tb: callback_errors.append(error)
        self.addCleanup(lambda: self.assertEqual(callback_errors, [], 'Tk 回调不应产生隐藏异常'))
        root.attributes('-alpha', 0)
        app = App(root)
        # 在主线程回收 Tk 对象，避免后续测试的工作线程触发 Tcl 析构。
        self.addCleanup(gc.collect)
        self.addCleanup(root.destroy)
        self.addCleanup(app.preview.clear)
        app.case = SimpleNamespace(image=lambda: image)
        app.display(entries)
        root.update()
        preview = app.preview
        split = preview.master
        x, y = split.sash_coord(0)
        height = preview.winfo_height()
        split.sash_place(0, x, y - 35)
        root.update_idletasks()
        self.assertGreater(preview.winfo_height(), height)

        def select(path):
            item = next(item for item, entry in app.entries.items() if entry['path'] == path)
            app.tree.selection_set(item)
            root.update()

        def read_page():
            deadline = time.monotonic() + 5
            while preview.status.get() == '正在读取…' and time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
            self.assertTrue(preview.status.get().startswith('第 '), preview.status.get())
            return [preview.rows.item(i, 'values') for i in preview.rows.get_children()]

        with patch('forensic.preview.PAGE_BYTES', 32):
            select('DOCS/CASE.TXT')
            self.assertEqual(read_page()[0][2], 'Case note inside')
            select('PAYLOAD.BIN')
            select('NOTES.TXT')
            ascii_rows = read_page()
            self.assertEqual(ascii_rows[0][2], '·' * 16)
            preview.encoding.set('UTF-8')
            preview.encoding.event_generate('<<ComboboxSelected>>')
            root.update()
            utf8_rows = read_page()
            self.assertEqual(utf8_rows[0][:2], ascii_rows[0][:2])
            preview.next.invoke()
            tail = read_page()
            self.assertEqual(tail[0][0], '00000020')
            self.assertEqual(''.join(row[2] for row in utf8_rows + tail), '取证演示：证据固定、审计、文件导出。··')
            preview.previous.invoke()
            self.assertEqual(read_page(), utf8_rows)
            select('DOCS')
            self.assertFalse(preview.rows.get_children())
            self.assertIsNone(preview.reader)

            original = next(e for e in entries if e['path'] == 'NOTES.TXT')
            deleted = [e for e in entries if e.get('deleted')]
            self.assertEqual([e['size'] for e in deleted], [0, original['size']])
            area = dict(original, path='测试区域', mode='v/v', inode='', size=32, extents=[[510, 4], [0, 28]])
            app.display([*deleted, area])
            matches = [i for i in app.tree.get_children() if app.tree.item(i, 'text') == deleted[0]['path']]
            self.assertEqual([app.entries[i]['inode'] for i in matches], [e['inode'] for e in deleted])
            app.tree.selection_set(matches[0])
            root.update()
            self.assertIn('0 字节', preview.status.get())
            self.assertFalse(preview.rows.get_children())
            app.tree.selection_set(matches[1])
            root.update()
            self.assertEqual(read_page(), utf8_rows)
            self.assertIn('已删除', preview.status.get())
            preview.next.invoke()
            self.assertEqual(read_page(), tail)
            preview.encoding.set('ASCII')
            preview.encoding.event_generate('<<ComboboxSelected>>')
            preview.previous.invoke()
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
