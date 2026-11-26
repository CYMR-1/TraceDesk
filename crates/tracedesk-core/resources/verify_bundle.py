"""独立核验复核包，无需安装 TraceDesk 或解压材料。"""
import argparse
import hashlib
import json
import re
from pathlib import Path
from zipfile import ZipFile

# 归类为取证发现的审计操作代码（与 TraceDesk Rust 核心保持一致）
FINDING_OPERATIONS = {'FILE_NOTE', 'FILE_HASH', 'FILE_COMPARE'}
HEX64_RE = re.compile(r'^[0-9a-fA-F]{64}$')


def digest_stream(stream):
    """流式计算 SHA-256 摘要及读取字节数。"""
    digest = hashlib.sha256()
    total = 0
    while block := stream.read(1024 * 1024):
        digest.update(block)
        total += len(block)
    return digest.hexdigest(), total


def read_sidecar_sha256(path):
    """自动读取伴随 `.sha256` 文件中的 64 位十六进制摘要；不存在或格式无效时返回 None。"""
    sidecar = Path(f'{path}.sha256')
    if not sidecar.is_file():
        return None
    try:
        text = sidecar.read_text(encoding='utf-8-sig').strip()
    except OSError:
        return None
    if not text:
        return None
    token = text.split()[0]
    if HEX64_RE.match(token):
        return token.lower()
    return None


def _is_html_report_record(record):
    """判断 REPORT_GENERATE 审计记录是否对应 HTML 报告。"""
    details = record.get('details')
    if isinstance(details, dict):
        fmt = details.get('format')
        if isinstance(fmt, str) and fmt.strip().lower() == 'html':
            return True
    subject = record.get('subject')
    return isinstance(subject, str) and subject.strip().lower().endswith('.html')


def verify_bundle(path, expected=None):
    """核验复核包外部摘要、成员摘要、审计哈希链、manifest 清单及跨文件交叉一致性。"""
    path = Path(path)
    if expected:
        with path.open('rb') as stream:
            actual_zip_sha, _ = digest_stream(stream)
            if actual_zip_sha != expected.strip().lower():
                raise ValueError('复核包外部 SHA-256 不匹配')

    with ZipFile(path) as archive:
        names = archive.namelist()
        if 'SHA256SUMS.json' not in names:
            raise ValueError('复核包缺少 SHA256SUMS.json')
        checks = json.loads(archive.read('SHA256SUMS.json'))
        if len(set(names)) != len(names) or set(names) != set(checks) | {'SHA256SUMS.json'}:
            raise ValueError('成员重复或与清单不一致')

        actual_sizes = {}
        for name, expected_digest in checks.items():
            info = archive.getinfo(name)
            with archive.open(name) as stream:
                actual_digest, actual_len = digest_stream(stream)
                if actual_digest != expected_digest or actual_len != info.file_size:
                    raise ValueError(f'成员摘要不匹配：{name}')
                actual_sizes[name] = actual_len

        # 校验 audit.jsonl 完整 SHA-256 审计哈希链，同时收集跨文件交叉校验所需索引
        previous = '0' * 64
        audit_records = []
        with archive.open('audit.jsonl') as log:
            for index, line in enumerate(log, 1):
                record = json.loads(line)
                recorded = record.pop('hash')
                raw = json.dumps(
                    record, sort_keys=True, ensure_ascii=False, separators=(',', ':')
                ).encode()
                if (
                    record['seq'] != index
                    or record['previous'] != previous
                    or hashlib.sha256(raw).hexdigest() != recorded
                ):
                    raise ValueError(f'审计链不一致：{index}')
                record['hash'] = recorded
                audit_records.append(record)
                previous = recorded

        manifest = json.loads(archive.read('manifest.json'))
        if archive.read('audit.head').decode() != previous or manifest['audit_head'] != previous:
            raise ValueError('审计链尾不匹配')

        # 核验 manifest.exports 与 exports/* 成员一致
        manifest_export_members = set()
        for item in manifest['exports']:
            member = item['member']
            manifest_export_members.add(member)
            if (
                member not in checks
                or checks[member] != item['sha256']
                or actual_sizes.get(member) != item['size']
            ):
                raise ValueError(f'导出记录不匹配：{member}')
        for member in checks:
            if member.startswith('exports/') and member not in manifest_export_members:
                raise ValueError(f'导出成员未在 manifest.json 中登记：{member}')

        # 提取审计链中的 REPORT_GENERATE、CONTENT_SEARCH 与取证发现记录
        last_md_report_sha = None
        last_html_report_sha = None
        audit_searches = {}
        audit_search_names = set()
        audit_findings = []
        for rec in audit_records:
            action = rec.get('action', '')
            result = rec.get('result', '')
            subject = rec.get('subject', '')
            details = rec.get('details') if isinstance(rec.get('details'), dict) else {}
            sha = details.get('sha256') if isinstance(details.get('sha256'), str) else ''

            if action == 'REPORT_GENERATE' and result == '成功' and sha:
                if _is_html_report_record(rec):
                    last_html_report_sha = sha
                else:
                    last_md_report_sha = sha
            elif action == 'CONTENT_SEARCH' and subject:
                audit_search_names.add(subject)
                if sha:
                    audit_searches[subject] = sha
            elif action in FINDING_OPERATIONS:
                audit_findings.append(rec)

        # 交叉核验 report.md 与审计链 REPORT_GENERATE 摘要（旧版无摘要记录时温和兼容）
        if 'report.md' not in checks:
            raise ValueError('复核包缺少取证报告 report.md')
        if last_md_report_sha and checks['report.md'] != last_md_report_sha:
            raise ValueError('报告摘要不匹配：report.md 与审计链记录不一致')

        # 交叉核验可选 report.html 与 manifest.html_report 及审计链 HTML REPORT_GENERATE 摘要
        html_meta = manifest.get('html_report')
        if isinstance(html_meta, dict):
            html_member = html_meta.get('member', 'report.html')
            if html_member not in checks:
                raise ValueError(f'HTML 报告成员缺失：{html_member}')
            if html_meta.get('sha256') and checks[html_member] != html_meta['sha256']:
                raise ValueError(f'HTML 报告清单摘要不匹配：{html_member}')
            if (
                isinstance(html_meta.get('size'), int)
                and actual_sizes.get(html_member) != html_meta['size']
            ):
                raise ValueError(f'HTML 报告长度不匹配：{html_member}')
        if 'report.html' in checks and last_html_report_sha:
            if checks['report.html'] != last_html_report_sha:
                raise ValueError('HTML 报告摘要不匹配：report.html 与审计链记录不一致')

        # 交叉核验 searches/*.json 与 CONTENT_SEARCH 审计记录及 omitted_searches
        omitted_search_names = {
            item['name']
            for item in manifest.get('omitted_searches', [])
            if isinstance(item, dict) and isinstance(item.get('name'), str)
        }
        for member, actual_sha in checks.items():
            if member.startswith('searches/'):
                search_name = member[len('searches/'):]
                if search_name in audit_searches:
                    if audit_searches[search_name] != actual_sha:
                        raise ValueError(f'搜索记录不匹配：{member}')
                elif search_name not in audit_search_names:
                    raise ValueError(f'搜索记录未在审计链中登记：{member}')
        for search_name, expected_sha in audit_searches.items():
            member = f'searches/{search_name}'
            if member in checks:
                if checks[member] != expected_sha:
                    raise ValueError(f'搜索记录不匹配：{member}')
            elif search_name not in omitted_search_names:
                raise ValueError(f'搜索记录缺失且未在 omitted_searches 登记：{member}')

        # 交叉核验 manifest.findings 与 audit.jsonl 取证发现记录一致性
        if 'findings' in manifest:
            manifest_findings = manifest['findings']
            if not isinstance(manifest_findings, list) or len(manifest_findings) != len(audit_findings):
                raise ValueError('取证发现不一致：manifest.json 中的 findings 与 audit.jsonl 数量不匹配')
            for mf, af in zip(manifest_findings, audit_findings):
                if (
                    not isinstance(mf, dict)
                    or mf.get('seq') != af.get('seq')
                    or mf.get('action') != af.get('action')
                    or mf.get('subject') != af.get('subject')
                    or mf.get('result') != af.get('result')
                    or (mf.get('hash') is not None and mf.get('hash') != af.get('hash'))
                ):
                    raise ValueError(
                        f"取证发现不一致：manifest.json 中的 findings（seq={mf.get('seq') if isinstance(mf, dict) else '?'}）与 audit.jsonl 不匹配"
                    )

        return len(checks)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle')
    parser.add_argument('--sha256', help='独立取得的交付摘要（未提供时自动探测伴随 .sha256 文件）')
    args = parser.parse_args()
    expected_sha = args.sha256 or read_sidecar_sha256(args.bundle)
    print(f'核验通过：{verify_bundle(args.bundle, expected_sha)} 份材料及审计链。')
