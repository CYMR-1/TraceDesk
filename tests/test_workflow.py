import hashlib
import json
import tempfile
import subprocess
import sys
from unittest.mock import patch
import unittest
from pathlib import Path
from forensic.core import Case, display_time, export_filename, sha256
from forensic.tsk import TSK
from scripts.make_demo import create


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        test_root = Path(__file__).resolve().parent.parent / '.test-work'
        test_root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=test_root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = self.root / 'evidence' / 'test.dd'
        self.manifest = create(self.image)
        self.case = Case.create(self.root / 'cases', 'TEST-001', '测试人员', 'FAT16 教学镜像')

        self.addCleanup(self.case.close)

    def load_scan(self):
        self.case.load(self.image)
        return self.case.scan(2048)

    def test_complete_real_tsk_workflow(self):
        entries = self.load_scan()
        self.assertTrue(self.case.verify())
        readme = next(e for e in entries if e['path'] == 'README.TXT')
        self.assertEqual(readme['mtime'], 1788249900)  # 2026-09-01 08:05 UTC，不受宿主时区影响。
        for name, expected in self.manifest.items():
            entry = next(e for e in entries if e['path'] == name)
            exported = self.case.export(entry)
            self.assertEqual(exported, self.case.folder / 'exports' / Path(name).name)
            self.assertEqual(sha256(exported), expected['sha256'])
            self.assertEqual(exported.stat().st_size, expected['size'])
        self.assertGreater(len(self.case.timeline()), 0)
        report = self.case.report()
        self.assertEqual(report.suffix, '.md')
        content = report.read_text(encoding='utf-8')
        self.assertIn('通过：本次报告', content)
        self.assertIn(sha256(self.image), content)
        self.assertIn('取证人员确认', content)
        self.case.close()
        reopened = Case(self.case.folder)
        self.addCleanup(reopened.close)
        self.assertEqual(len(reopened.data['exports']), len(self.manifest))
        self.assertEqual(sha256(self.image), json.loads(self.image.with_suffix('.manifest.json').read_text())['image_sha256'])

    def test_unpartitioned_volume(self):
        image = self.root / 'volume.dd'
        create(image, False)
        self.case.load(image)
        self.assertEqual(self.case.data['evidence']['partitions'][0]['offset'], 0)
        self.assertTrue(any(e['path'] == 'DOCS/CASE.TXT' for e in self.case.scan(0)))

    def test_filter(self):
        self.load_scan()
        entries = self.case.filtered('TXT', 'docs')
        self.assertEqual([e['path'] for e in entries], ['DOCS/CASE.TXT'])

    def test_chinese_fls_names(self):
        tool = TSK()
        # “石头”的 CP936 字节恰好也是合法 UTF-8，不能靠解码异常猜编码。
        for path in ('石头.jpg', '素材', '素材/7134-中文20110102.doc'):
            with self.subTest(path=path):
                body = f'0|/{path}|15|r/rrwxrwxrwx|0|0|128|0|0|0|0\r\n'.encode('cp936')
                result = subprocess.CompletedProcess([], 0, stdout=body)
                empty = subprocess.CompletedProcess([], 0, stdout=b'')
                with patch('forensic.tsk.TSK_TEXT_ENCODING', 'cp936'), patch.object(tool, 'run', side_effect=[result, empty]):
                    entry, = tool.files(self.image, 128)
                self.assertEqual(entry['path'], path)
                self.assertEqual(entry['inode'], '15')

    def test_deleted_records_and_fat_regions(self):
        # 在临时 FAT16 夹具中添加两个同名删除项，以及一个分配后没有目录项指向的簇。
        volume = 2048 * 512
        root_dir = volume + (1 + 2 * 64) * 512
        data = root_dir + 32 * 512
        with self.image.open('r+b') as stream:
            stream.seek(root_dir)
            record = bytearray(stream.read(32))
            record[0] = 0xe5
            stream.seek(root_dir + 5 * 32)
            empty = record.copy()
            empty[26:32] = bytes(6)
            stream.write(empty + record)
            for fat in (1, 65):
                stream.seek(volume + fat * 512 + 20 * 2)
                stream.write(b'\xff\xff')
        entries = self.load_scan()
        deleted = [e for e in entries if e.get('deleted') and e['path'].endswith('EADME.TXT')]
        self.assertEqual(len(deleted), 2)
        self.assertNotEqual(deleted[0]['inode'], deleted[1]['inode'])
        self.assertIn(deleted[0], self.case.filtered('txt', 'EADME'))
        empty_path, data_path = [self.case.export(e) for e in deleted]
        self.assertEqual(empty_path.read_bytes(), b'')
        self.assertEqual(empty_path.name, data_path.name)
        self.assertNotEqual(empty_path, data_path)
        self.assertEqual(sha256(data_path), self.manifest['README.TXT']['sha256'])
        record = self.case.data['exports'][-1]
        self.assertTrue(record['deleted'])
        self.assertTrue(record['start_cluster_allocated'])
        self.assertEqual(record['inode'], deleted[1]['inode'])
        self.assertEqual(record['size'], record['recorded_size'])
        self.assertEqual(record['sha256'], sha256(data_path))
        self.assertIn('起始簇已被占用', self.case.report().read_text(encoding='utf-8'))
        by_path = {e['path']: e for e in entries}
        for name in ('$MBR', '$FAT1', '$FAT2', '(根目录)'):
            self.assertGreater(by_path[name]['size'], 0)
        self.assertEqual(by_path['闲置空间（已分配未关联簇）']['extents'], [[data + 18 * 512, 512]])
        free = by_path['空余空间（未分配簇）']
        self.assertEqual(len(free['extents']), 2)
        self.assertEqual(free['size'], sum(n for _, n in free['extents']))

    def test_deleted_export_partial_and_unreadable(self):
        entry = next(e for e in self.load_scan() if e['path'] == 'README.TXT')
        entry.update(deleted=True, reallocated=True)
        tool = TSK()
        self.assertNotIn('-r', tool.entry_args(self.image, entry))
        self.assertIn('-r', tool.entry_args(self.image, dict(entry, reallocated=False)))
        command = [sys.executable, '-c', "import sys; sys.stdout.buffer.write(b'prefix'); sys.exit(1)"]
        with patch.object(tool, 'command', return_value=command):
            output = self.case.export(entry, tool)
        self.assertEqual(output.read_bytes(), b'prefix')
        record = self.case.data['exports'][-1]
        self.assertEqual(record['size'], 6)
        self.assertEqual(record['recorded_size'], entry['size'])
        self.assertTrue(record['reallocated'])
        self.assertTrue(record['read_note'])
        self.assertEqual(self.case.check_audit()[-1]['result'], '部分导出')
        with patch.object(tool, 'command', return_value=[sys.executable, '-c', 'pass']), self.assertRaises(OSError):
            self.case.export(entry, tool)
        self.assertEqual(list(output.parent.iterdir()), [output])
        self.assertEqual(self.case.data['exports'], [record])
        self.assertEqual(self.case.check_audit()[-1]['result'], '失败')

        entry['size'] = 3
        with patch.object(tool, 'command', return_value=command):
            limited = self.case.export(entry, tool)
        self.assertEqual(limited.read_bytes(), b'pre')
        self.assertIn('截取', self.case.data['exports'][-1]['read_note'])

    def test_modified_image_blocks_export_and_report_marks_failure(self):
        entries = self.load_scan()
        with self.image.open('r+b') as stream:  # 仅测试夹具故意写入；产品代码不开放此入口。
            stream.seek(-1, 2)
            stream.write(b'X')
        self.assertFalse(self.case.verify())
        with self.assertRaises(RuntimeError):
            self.case.export(next(e for e in entries if e['path'] == 'README.TXT'))
        self.assertIn('不通过', self.case.report().read_text(encoding='utf-8'))

    def test_audit_edit_detected(self):
        log = self.case.folder / 'audit.jsonl'
        log.write_text(log.read_text(encoding='utf-8').replace('TEST-001','TEST-999'), encoding='utf-8')
        self.case.close()
        with self.assertRaises(RuntimeError):
            Case(self.case.folder)

    def test_east_8_display_with_legacy_audit(self):
        historical = '2026-11-10T20:11:06.783706+00:00'
        converted = '2026-11-11T04:11:06.783706+08:00'
        with patch('forensic.core.now', return_value=historical):
            self.case.log('TEST', '旧记录', '成功')
        record = self.case.check_audit()[-1]
        self.assertTrue(self.case.data['created'].endswith('+08:00'))
        self.assertEqual(display_time(record['timestamp']), converted)
        self.assertEqual(display_time(converted), converted)
        self.assertEqual(display_time(0, compact=True), '未记录')
        self.load_scan()
        self.assertEqual(display_time(1788249900, compact=True), '2026-09-01 16:05:00')
        self.assertIn('2026-09-01T16:05:00+08:00', [row['time'] for row in self.case.timeline_events()])
        report = self.case.report().read_text(encoding='utf-8')
        self.assertIn(converted, report)
        self.assertNotIn(historical, report)
        self.assertIn(record, self.case.check_audit())

    def test_audit_truncation_detected(self):
        self.case.log('TEST', 'object', '成功')
        log = self.case.folder / 'audit.jsonl'
        log.write_text(log.read_text(encoding='utf-8').splitlines()[0]+'\n', encoding='utf-8')
        self.case.close()
        with self.assertRaises(RuntimeError):
            Case(self.case.folder)

    def test_case_isolation(self):
        other = Case.create(self.root / 'cases', 'TEST-001', '同编号人员', '另一对象')
        self.addCleanup(other.close)
        self.assertNotEqual(self.case.folder, other.folder)
        inside = self.case.folder.parent / 'inside.dd'
        inside.write_bytes(b'not an image')
        with self.assertRaises(ValueError):
            self.case.load(inside)

    def test_case_folder_name_and_collision(self):
        library = self.case.folder.parent
        first = Case.create(library, '123', '23', '4')
        self.addCleanup(first.close)
        second = Case.create(library, '123', '23', '4')
        self.addCleanup(second.close)
        self.assertEqual(first.folder, library / '123-23-4')
        self.assertEqual(second.folder, library / '123-23-4 (2)')
        self.assertNotEqual(first.data['id'], second.data['id'])
        self.assertEqual(len(first.check_audit()), 1)

    def test_case_folder_keeps_inputs_inside_library(self):
        library = self.case.folder.parent
        case = Case.create(library, '../01', '张/三', '甲:硬盘')
        self.addCleanup(case.close)
        self.assertEqual(case.folder, library / '.._01-张_三-甲_硬盘')
        self.assertEqual(case.data['examiner'], '张/三')
        self.assertEqual(case.data['target'], '甲:硬盘')

    def test_invalid_image_audited(self):
        bad = self.root / 'bad.dd'
        bad.write_bytes(b'not a filesystem')
        with self.assertRaises(RuntimeError):
            self.case.load(bad)
        self.assertIsNone(self.case.data['evidence'])
        self.assertEqual(self.case.check_audit()[-1]['result'], '失败')

    def test_directory_export_rejected(self):
        entries = self.load_scan()
        with self.assertRaises(ValueError):
            self.case.export(next(e for e in entries if e['directory']))

    def test_export_preserves_name_on_collision(self):
        entry = next(e for e in self.load_scan() if e['path'] == 'README.TXT')
        name = '取证 照片 (原件) #1.TXT'
        entry['path'] = f'素材/{name}'
        first = self.case.export(entry)
        second = self.case.export(entry)
        self.assertEqual(first, self.case.folder / 'exports' / name)
        self.assertEqual(second.name, name)
        self.assertEqual(second.parent.parent, first.parent)
        self.assertEqual(sha256(first), self.manifest['README.TXT']['sha256'])
        self.assertEqual(sha256(second), sha256(first))
        self.assertEqual(self.case.data['exports'][-1]['path'], str(second))
        self.assertEqual(self.case.check_audit()[-1]['details']['path'], str(second))

    def test_export_filename_windows_limits(self):
        long_name = '中' * 230 + '.png'
        self.assertEqual(export_filename('素材/' + long_name), long_name)
        self.assertEqual(export_filename('素材/NUL.txt'), '_NUL.txt')
        self.assertEqual(export_filename('素材/原稿:彩色?.jpg'), '原稿_彩色_.jpg')
        self.assertEqual(export_filename('素材/..'), 'file')

    def test_case_lock_and_invalid_metadata(self):
        with self.assertRaisesRegex(RuntimeError, '占用'):
            Case(self.case.folder)
        self.case.close()
        (self.case.folder / 'case.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, '案件数据损坏'):
            Case(self.case.folder)

    def test_failed_save_preserves_state(self):
        with patch('forensic.core.save_json', side_effect=OSError('磁盘已满')):
            with self.assertRaises(OSError):
                self.case.load(self.image)
        self.assertIsNone(self.case.data['evidence'])
        self.assertIsNone(json.loads((self.case.folder/'case.json').read_text('utf8'))['evidence'])

    def test_scan_image_changed(self):
        self.case.load(self.image)
        tool = TSK()
        original = tool.files
        def change(*args):
            entries = original(*args)
            with self.image.open('ab') as output:
                output.write(b'x')
            return entries
        with patch.object(tool, 'files', change), self.assertRaisesRegex(RuntimeError, '扫描期间'):
            self.case.scan(2048, tool)
        self.assertEqual(self.case.data['inventory'], [])

    def test_partial_export_cleanup(self):
        entry = next(e for e in self.load_scan() if e['path'] == 'README.TXT')
        def fail(image, offset, inode, destination):
            destination.write_bytes(b'partial')
            raise OSError('写入失败')
        with patch.object(TSK, 'export', side_effect=fail), self.assertRaises(OSError):
            self.case.export(entry)
        self.assertFalse(any((self.case.folder/'exports').iterdir()))
        self.assertFalse(self.case.data['exports'])
        self.assertEqual(self.case.check_audit()[-1]['result'], '失败')

    def test_missing_tool_and_timeout(self):
        tool = TSK()
        tool.bin = self.root
        with self.assertRaisesRegex(RuntimeError, '缺少'):
            tool.command('icat', [])
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('fls', 300)):
            with self.assertRaisesRegex(TimeoutError, '超时'):
                TSK().text('fls', [])

    def test_stream_hash(self):
        data = self.root / 'large.bin'
        data.write_bytes(bytes(range(256))*20000)
        calls = []
        self.assertEqual(sha256(data, lambda a,b: calls.append((a,b))), hashlib.sha256(data.read_bytes()).hexdigest())
        self.assertGreater(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
