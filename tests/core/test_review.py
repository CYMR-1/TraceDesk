import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from forensic.core.case import Case
from forensic.core.content_search import matches, pattern, search, SearchControl
from forensic.core.coverage import assess, source_status
from forensic.core.file_tools import record_note
from forensic.core.review import build_bundle
from forensic.engines.ewf import segments
from forensic.paths import TEST_WORK_DIR
from scripts.make_demo import create
from scripts.verify_bundle import verify_bundle


class ReviewTests(unittest.TestCase):
    def setUp(self):
        TEST_WORK_DIR.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=TEST_WORK_DIR)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_volume_bounds_do_not_confuse_hash_with_acquisition(self):
        image = self.root / 'test.dd'
        boot = bytearray(512)
        boot[3:11], boot[510:] = b'NTFS    ', b'\x55\xaa'
        struct.pack_into('<H', boot, 11, 512)
        struct.pack_into('<Q', boot, 40, 300)
        image.write_bytes(boot)
        row = assess(image, [dict(offset=0)])['volumes'][0]
        self.assertEqual(row['missing_bytes'], 299 * 512)
        self.assertEqual(row['status'], '声明范围超出镜像')
        image.write_bytes(bytes(512))
        self.assertEqual(assess(image,[dict(offset=0)])['volumes'][0]['status'], '无法判定卷范围')

    def test_overlapping_and_multibyte_search_across_chunks(self):
        for codec in ('UTF-8', 'UTF-16LE', 'GBK'):
            needle = pattern('取证',codec)
            stream = io.BytesIO(b'abc' + needle + needle)
            self.assertEqual([r[0] for r in matches(stream,len(stream.getvalue()),needle,SearchControl(),chunk=3)],
                             [3, 3+len(needle)])
        self.assertEqual([r[0] for r in matches(io.BytesIO(b'aaaa'),4,pattern('61 61','HEX'),SearchControl(),chunk=2)], [0,1,2])

    def test_missing_middle_segment_rejected(self):
        first = self.root/'sample.E01'
        first.touch()
        (self.root/'sample.E03').touch()
        with self.assertRaisesRegex(ValueError,'分段'):
            segments(first)

    def test_search_and_independent_review(self):
        image = self.root/'sample.dd'
        create(image)
        case = Case.create(self.root/'cases','1','test','demo')
        self.addCleanup(case.close)
        case.load(image)
        case.scan_all()
        case.register_source(dict(source='handoff', expected_sha256='0'*64))
        self.assertIn('不一致', source_status(case.data['evidence']))
        case.register_source(dict(source='handoff', expected_sha256=hashlib.sha256(image.read_bytes()).hexdigest()))
        record, hits, name = search(case,'forensic','UTF-8', SearchControl(), lambda *_:None)
        entry, pos, _, _ = next(h for h in hits if h[0]['path']=='README.TXT')
        exported = case.export(entry)
        self.assertEqual(exported.read_bytes()[pos:pos+8],b'forensic')
        record_note(case,entry,'复核命中')
        bundle = build_bundle(case)
        self.assertGreater(verify_bundle(bundle,hashlib.sha256(bundle.read_bytes()).hexdigest()), 3)
        with self.assertRaisesRegex(ValueError, '外部'):
            verify_bundle(bundle,'0'*64)
        with ZipFile(bundle) as z:
            for member,digest in json.loads(z.read('SHA256SUMS.json')).items():
                self.assertEqual(hashlib.sha256(z.read(member)).hexdigest(),digest)
            manifest = json.loads(z.read('manifest.json'))
            self.assertTrue(manifest['findings'])
            self.assertEqual(json.loads(z.read('searches/'+name)),record)
            self.assertEqual(z.read(manifest['exports'][0]['member']),exported.read_bytes())
            self.assertNotIn('sample.dd',z.namelist())
        control = SearchControl()
        control.cancel()
        cancelled, hits, _ = search(case,'a','UTF-8',control,lambda *_:None)
        self.assertFalse(hits)
        self.assertIn('取消',cancelled['status'])
        exported.write_bytes(b'altered')
        with self.assertRaisesRegex(ValueError,'摘要不一致'):
            build_bundle(case)
