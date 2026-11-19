"""1 TiB 稀疏 RAW 的真实 GUI 入口、高偏移文件操作及独立哈希任务。"""
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PySide6.QtWidgets import QApplication, QMainWindow

from forensic.core.case import Case, sha256
from forensic.core.content_search import search, SearchControl
from forensic.core.file_tools import examine
from forensic.paths import EVIDENCE_DIR, TEST_WORK_DIR
from forensic.engines.ewf import segments
from forensic.engines.tsk import TSK
from forensic.core.preview import PAGE_BYTES, PreviewReader
from forensic.ui.controller import App


class LargeImages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def setUp(self):
        TEST_WORK_DIR.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=TEST_WORK_DIR)
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.window = QMainWindow()
        self.app = App(self.window)
        self.addCleanup(self.window.deleteLater)
        self.addCleanup(self.app._shutdown)
        self.app.create_case(self.folder / 'cases', 'large', '测试', '大容量镜像')

    def finish(self, condition):
        deadline = time.monotonic() + 30
        with patch('forensic.ui.controller.QMessageBox.critical') as errors:
            while condition() and time.monotonic() < deadline:
                self.qt.processEvents()
                self.app.poll()
                time.sleep(.002)
            errors.assert_not_called()
        self.assertFalse(condition())

    def load(self, path):
        with patch('forensic.features.evidence.choose_file', return_value=str(path)):
            self.app.load()
        self.finish(lambda: self.app.busy)

    def test_sparse_tib_at_high_partition_offset(self):
        path = self.folder / 'large.dd'
        path.touch()
        sparse = subprocess.run(['fsutil', 'sparse', 'setflag', path], capture_output=True)
        if sparse.returncode:
            self.skipTest('测试卷无法建立稀疏文件')
        size = 1 << 40
        volume = EVIDENCE_DIR / 'demo_volume.dd'
        length = volume.stat().st_size
        offset = (size - length) // 512
        mbr = bytearray(512)
        struct.pack_into('<B3sB3sII', mbr, 446, 0, bytes(3), 6, bytes(3), offset, length // 512)
        mbr[510:] = bytes.fromhex('55aa')
        with path.open('r+b') as stream, volume.open('rb') as source:
            stream.write(mbr)
            stream.seek(offset * 512)
            shutil.copyfileobj(source, stream)
        self.assertEqual(path.stat().st_size, size)
        # 误触发全盘读取直接失败，避免回归时实际读取 1 TiB。
        def hash_file(target, progress=None):
            self.assertNotEqual(Path(target), path)
            return sha256(target, progress)
        with patch('forensic.core.case.sha256', side_effect=hash_file):
            self.load(path)
            case = self.app.case
            self.assertIsNone(case.data['evidence']['sha256'])
            self.assertEqual(case.directory_location, (offset, None, ''))
            self.assertFalse(case.data['inventory'])
            browser = self.app.browser
            docs = next(item for item in browser._items.values() if item.text(0) == 'DOCS')
            browser._open_directory(docs, 0)
            self.finish(lambda: self.app.busy)
            entry = next(e for e in case.directory_entries if e['path'] == 'DOCS/CASE.TXT')
            item = next(item for item in browser._items.values() if item.text(0) == 'CASE.TXT')
            browser.tree.setCurrentItem(item)
            self.finish(lambda: not browser.preview.window)
            self.assertIn(b'Case note', browser.preview.window)
            output = case.export(entry)
            self.assertEqual(examine(case, entry, output)[0], '一致')
            self.assertIn('待固定', case.data['exports'][0]['source_verification'])
            record, hits, _ = search(case, 'note', 'UTF-8', SearchControl(), lambda *_: None, selected=entry)
            self.assertEqual(hits[0][1], 5)
            self.assertIn('待固定', record['verification'])
            with self.assertRaisesRegex(ValueError, '完整文件索引'):
                search(case, 'note', 'UTF-8', SearchControl(), lambda *_: None)
            self.app.scan()
            self.finish(lambda: self.app.busy)
            self.assertFalse(case.browsing_directories)
            self.assertTrue(case.timeline_events())
            self.assertTrue(case.data['partition_scans'][0]['count'])
            self.assertIn(b'File System Type: FAT16', case.export_fsstat(offset).read_bytes())

    def test_tib_volume_preview_reads_last_cluster(self):
        path = self.folder / 'whole-volume.dd'
        path.touch()
        if subprocess.run(['fsutil', 'sparse', 'setflag', path], capture_output=True).returncode:
            self.skipTest('测试卷无法建立稀疏文件')
        total = 1 << 31
        sectors_per_cluster = 64
        reserved = 32
        fat_sectors = (total // sectors_per_cluster + 2 + 127) // 128
        first_data = reserved + 2 * fat_sectors
        clusters = (total - first_data) // sectors_per_cluster
        cluster_bytes = sectors_per_cluster * 512
        file_clusters = 320
        start_cluster = clusters + 2 - file_clusters
        length = file_clusters * cluster_bytes
        boot = bytearray(512)
        boot[:11] = bytes.fromhex('eb5890') + b'TRACEDSK'
        struct.pack_into('<HBHBHHBHHHII', boot, 11, 512, sectors_per_cluster, reserved, 2,
                         0, 0, 0xf8, 0, 63, 255, 0, total)
        struct.pack_into('<IHHIHH', boot, 36, fat_sectors, 0, 0, 2, 1, 6)
        boot[64], boot[66] = 0x80, 0x29
        boot[71:90] = b'TRACE TEST FAT32   '
        boot[510:] = bytes.fromhex('55aa')
        root = bytearray(32)
        root[:12] = b'TAIL    BIN '
        struct.pack_into('<H', root, 20, start_cluster >> 16)
        struct.pack_into('<HI', root, 26, start_cluster & 0xffff, length)
        with path.open('r+b') as file:
            file.seek(total * 512 - 1)
            file.write(bytes(1))
            for sector in (0, 6):
                file.seek(sector * 512)
                file.write(boot)
            for sector in (reserved, reserved + fat_sectors):
                file.seek(sector * 512)
                file.write(struct.pack('<III', 0x0ffffff8, 0x0fffffff, 0x0fffffff))
                file.seek(sector * 512 + start_cluster * 4)
                chain = [*range(start_cluster + 1, start_cluster + file_clusters), 0x0fffffff]
                file.write(struct.pack(f'<{file_clusters}I', *chain))
            file.seek(first_data * 512)
            file.write(root)
            file.seek(first_data * 512 + clusters * cluster_bytes - 6)
            file.write(b'ENDTAG')
        self.load(path)
        case = self.app.case
        self.assertEqual(case.data['evidence']['coverage']['volumes'][0]['volume_end'], 1 << 40)
        entry = next(e for e in case.directory_entries if e['path'] == 'TAIL.BIN')
        with patch.object(TSK, 'popen_image', side_effect=AssertionError('应直接定位末页')):
            reader = PreviewReader(path, entry)
            try:
                self.assertEqual(reader.results.get(timeout=10)[0], 0)
                reader.pages.put(length // PAGE_BYTES - 1)
                page, buffer, size, note = reader.results.get(timeout=10)
                self.assertEqual((page, size, note, buffer[-6:]), (length // PAGE_BYTES - 1, length, '', b'ENDTAG'))
            finally:
                reader.close()

        cancel = threading.Event()
        deadline = threading.Timer(30, cancel.set)
        deadline.start()
        try:
            entries = case.scan_all(cancel=cancel)
        finally:
            deadline.cancel()
        free = next(e for e in entries if e['path'] == '空余空间（未分配簇）')
        self.assertEqual(free['size'], (clusters - file_clusters - 1) * cluster_bytes)
        self.assertEqual(len(free['extents']), 1)

    def test_native_random_preview_and_index_search(self):
        image = self.folder / 'volume.dd'
        volume = bytearray((EVIDENCE_DIR / 'demo_volume.dd').read_bytes()[:512])
        # 32 MiB FAT16 卷，单文件 10 MiB，末页有独立标记。
        volume[13] = 4
        struct.pack_into('<H', volume, 19, 0)
        struct.pack_into('<I', volume, 32, 65536)
        fat = bytearray(64 * 512)
        struct.pack_into('<HH', fat, 0, 0xfff8, 0xffff)
        length = 10 << 20
        clusters = length // 2048
        for cluster in range(2, 2 + clusters):
            struct.pack_into('<H', fat, 2 * cluster, cluster + 1 if cluster < clusters + 1 else 0xffff)
        root = bytearray(32 * 512)
        root[:12] = b'LARGE   BIN '  # 8.3 文件名和普通文件属性
        struct.pack_into('<HI', root, 26, 2, length)
        # 第二个目录项用于实际走多文件读取线程复用路径。
        root[32:44] = b'SMALL   TXT '
        struct.pack_into('<HI', root, 58, clusters + 2, 6)
        struct.pack_into('<H', fat, 2 * (clusters + 2), 0xffff)
        with image.open('wb') as dest:
            dest.write(volume + fat + fat + root)
            start = dest.tell()
            dest.seek(start + length - 6)
            dest.write(b'marker' * 2)
            dest.truncate(32 << 20)
        with patch('forensic.core.case.LARGE_IMAGE_BYTES', 1):
            self.load(image)
        case = self.app.case
        entry = next(e for e in case.directory_entries if e['path'] == 'LARGE.BIN')
        with patch.object(TSK, 'popen_image', side_effect=AssertionError('预览不应顺序读取文件前缀')):
            reader = PreviewReader(image, entry)
            try:
                self.assertEqual(reader.results.get(timeout=5)[0], 0)
                page = length // PAGE_BYTES - 1
                reader.pages.put(page)
                number, window, _, note = reader.results.get(timeout=5)
                self.assertEqual((number, note, window[-6:]), (page, '', b'marker'))
            finally:
                reader.close()
        case.scan_all()
        with patch.object(TSK, 'popen_image', side_effect=AssertionError('普通文件应复用卷解析器')):
            _, hits, _ = search(case, 'marker', 'UTF-8', SearchControl(), lambda *_: None)
        self.assertEqual([(e['path'], p) for e, p, *_ in hits],
                         [('LARGE.BIN', length - 6), ('SMALL.TXT', 0)])

    def test_cancel_index_preserves_directory_and_retry(self):
        image = self.folder / 'index.dd'
        shutil.copyfile(EVIDENCE_DIR / 'demo.dd', image)
        with patch('forensic.core.case.LARGE_IMAGE_BYTES', 1):
            self.load(image)
        case = self.app.case
        before = case.directory_entries
        self.app.scan()
        self.app.browser.index_button.click()
        self.finish(lambda: self.app.busy)
        self.assertIs(case.directory_entries, before)
        self.assertTrue(case.browsing_directories)
        self.assertEqual(case.check_audit()[-1]['result'], '已取消')
        self.app.scan()
        self.finish(lambda: self.app.busy)
        self.assertFalse(case.browsing_directories)

    def test_timeline_paging_uses_original_event_positions(self):
        from forensic.core.timeline import TimelineEvents
        rows = [dict(path=f'dir/{i}', offset=0, inode=str(i), mode='r/r', mtime=i,
                     atime=i, ctime=0, crtime=0) for i in range(1, 1101)]
        events = TimelineEvents(rows)
        panel = self.app.view.panels['timeview']
        panel.set_text(('时间线', events, lambda _, work, done: done(work())))
        panel._jump(21)
        self.assertEqual(panel.table.topLevelItem(99).text(0), '2200')
        panel.search.setText('dir/1100')
        panel._search()
        self.assertEqual([panel.table.topLevelItem(i).text(0) for i in range(2)], ['2199', '2200'])

    def test_ewf_letter_segments_and_unrelated_sidecar(self):
        first = self.folder / 'disk.E01'
        for i in range(1, 100):
            first.with_suffix(f'.E{i:02}').touch()
        first.with_suffix('.EAA').write_bytes(bytes.fromhex('455646090d0aff00'))
        first.with_suffix('.txt').write_text('notes')
        self.assertEqual(segments(first)[-1].suffix, '.EAA')
        first.with_suffix('.EAC').write_bytes(bytes.fromhex('455646090d0aff00'))
        with self.assertRaisesRegex(ValueError, '分段缺失'):
            segments(first)

    def test_background_baseline_cancel_commit_and_reopen(self):
        path = self.folder / 'demo.dd'
        shutil.copyfile(EVIDENCE_DIR / 'demo.dd', path)
        with patch('forensic.core.case.LARGE_IMAGE_BYTES', 1):
            self.load(path)
        case = self.app.case
        with self.assertRaises(PermissionError):
            with path.open('r+b'):
                pass
        with self.assertRaisesRegex(ValueError, '固定'):
            case.report()
        self.app.verify()
        self.assertFalse(self.app.busy)
        self.app.verify()
        self.finish(lambda: self.app.hash_runner.busy)
        self.assertIsNone(case.data['evidence']['sha256'])
        self.app.verify()
        self.finish(lambda: self.app.hash_runner.busy)
        self.assertEqual(case.data['evidence']['sha256'], sha256(path))
        with patch('forensic.core.case.sha256', wraps=sha256) as reader:
            case.report()
            self.assertFalse(any(call.args[0] == str(path) for call in reader.call_args_list))
        case.close()
        case = Case(case.folder)
        self.addCleanup(case.close)
        with self.assertRaisesRegex(ValueError, '重新打开'):
            case.operation_check()
        self.assertTrue(case.verify())
        self.assertTrue(case.operation_check())
        case.close()
        with path.open('ab') as stream:
            stream.write(b'x')
        reopened = Case(case.folder)
        self.addCleanup(reopened.close)
        with self.assertRaisesRegex(ValueError, '加载记录'):
            reopened.browse_directory(2048)
