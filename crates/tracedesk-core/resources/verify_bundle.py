"""独立核验复核包，无需安装 TraceDesk 或解压材料。"""
import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile


def digest_stream(stream):
    digest = hashlib.sha256()
    while block := stream.read(1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def verify_bundle(path, expected=None):
    path = Path(path)
    if expected:
        with path.open('rb') as stream:
            if digest_stream(stream) != expected.strip().lower():
                raise ValueError('复核包外部 SHA-256 不匹配')
    with ZipFile(path) as archive:
        names = archive.namelist()
        checks = json.loads(archive.read('SHA256SUMS.json'))
        if len(set(names)) != len(names) or set(names) != set(checks) | {'SHA256SUMS.json'}:
            raise ValueError('成员重复或与清单不一致')
        for name, expected_digest in checks.items():
            with archive.open(name) as stream:
                if digest_stream(stream) != expected_digest:
                    raise ValueError(f'成员摘要不匹配：{name}')
        previous = '0' * 64
        with archive.open('audit.jsonl') as log:
            for index, line in enumerate(log, 1):
                record = json.loads(line)
                recorded = record.pop('hash')
                raw = json.dumps(record,sort_keys=True,ensure_ascii=False,separators=(',', ':')).encode()
                if record['seq'] != index or record['previous'] != previous or hashlib.sha256(raw).hexdigest() != recorded:
                    raise ValueError(f'审计链不一致：{index}')
                previous = recorded
        manifest = json.loads(archive.read('manifest.json'))
        if archive.read('audit.head').decode() != previous or manifest['audit_head'] != previous:
            raise ValueError('审计链尾不匹配')
        for item in manifest['exports']:
            member = item['member']
            if checks[member] != item['sha256'] or archive.getinfo(member).file_size != item['size']:
                raise ValueError(f'导出记录不匹配：{member}')
        return len(checks)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle')
    parser.add_argument('--sha256', help='独立取得的交付摘要')
    args = parser.parse_args()
    print(f'核验通过：{verify_bundle(args.bundle,args.sha256)} 份材料及审计链。')
