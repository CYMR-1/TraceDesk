"""全部分区扫描、不可读分区保留和跨分区文件定位回归。"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from forensic.core.case import Case
from forensic.engines.tsk import TSK
from forensic.paths import TEST_WORK_DIR
from tests.fixtures import create_multi_partition_image


class PartitionTests(unittest.TestCase):
    def setUp(self):
        TEST_WORK_DIR.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=TEST_WORK_DIR)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.case = Case.create(self.root / 'cases', 'MULTI', '测试', '多分区镜像')
        self.addCleanup(self.case.close)

    def test_gpt_and_dos_partition_slots_are_both_recognized(self):
        for slot in ('000', '000:000'):
            tool = TSK()
            output = ('000: Meta 0000000000 0000000033 0000000034 Table\n'
                      '001: ------- 0000000034 0000002047 0000002014 Unallocated\n'
                      f'002: {slot} 0000002048 0000018431 0000016384 FAT16\n')
            with self.subTest(slot=slot), patch.object(tool, 'text', return_value=output):
                _, partitions = tool.inspect('fixture.dd')
            self.assertEqual(partitions, [dict(offset=2048, description='FAT16')])

    def test_scan_all_preserves_partitions_export_sources_and_reopened_inventory(self):
        image = self.root / 'multi.dd'
        expected = create_multi_partition_image(image)
        self.case.load(image)
        self.assertTrue(self.case.needs_partition_scan())
        entries = self.case.scan_all()
        self.assertFalse(self.case.needs_partition_scan())
        self.assertEqual({e['offset'] for e in entries}, set(expected))
        files = [e for e in entries if e['path'] == 'README.TXT']
        self.assertEqual(len(files), 2)
        self.assertEqual(files[0]['inode'], files[1]['inode'])
        for entry in files:
            self.assertEqual(self.case.export(entry).read_bytes(), expected[entry['offset']])
        self.assertNotEqual(*expected.values())
        self.assertEqual({e['offset'] for e in self.case.timeline_events()}, set(expected))
        report = self.case.report().read_text(encoding='utf-8')
        self.assertIn('| 分区偏移 | 路径 |', report)
        for offset in expected:
            self.assertIn(f'| {offset} | README.TXT |', report)
        self.case.close()
        reopened = Case(self.case.folder)
        self.addCleanup(reopened.close)
        self.assertFalse(reopened.needs_partition_scan())
        self.assertEqual(reopened.data['inventory'], entries)

    def test_bad_partition_does_not_hide_readable_partitions(self):
        image = self.root / 'partial.dd'
        expected = create_multi_partition_image(image, unreadable=True)
        self.case.load(image)
        self.assertEqual(len(self.case.data['evidence']['partitions']), 3)
        entries = self.case.scan_all()
        self.assertEqual({e['offset'] for e in entries}, set(expected))
        scans = {p['offset']: p for p in self.case.data['partition_scans']}
        self.assertEqual(scans[38912]['status'], 'error')
        self.assertTrue(scans[38912]['error'])
        self.assertEqual([scans[o]['status'] for o in expected], ['ready', 'ready'])
        self.assertIn('无法读取', self.case.report().read_text(encoding='utf-8'))

    def test_image_change_during_scan_does_not_replace_saved_inventory(self):
        image = self.root / 'changed.dd'
        create_multi_partition_image(image)
        self.case.load(image)
        original = self.case.scan_all()
        tool = TSK()
        files = tool.files

        def change_after_read(path, offset):
            entries = files(path, offset)
            with image.open('r+b') as stream:
                stream.seek(1024)
                stream.write(b'changed')
            return entries

        with patch.object(tool, 'files', side_effect=change_after_read):
            with self.assertRaisesRegex(RuntimeError, '扫描期间镜像变化'):
                self.case.scan_all(tool)
        self.assertEqual(self.case.data['inventory'], original)
