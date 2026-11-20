"""生成可移交的复核包；打包时复算每个副本和搜索记录的摘要。"""
import hashlib
import json
import sys
from pathlib import Path
from zipfile import ZipFile

from .case import sha256
from .coverage import source_status
from .findings import OPERATIONS
from ..engines.tsk import TSK


def resolve_export_path(case, item):
    """解析历史导出记录对应的本地副本路径，并限制在案件 exports 目录内。"""
    original = Path(item['path'])
    # 案件移动后按原导出目录内的相对位置寻找副本。
    relative = (Path(original.parent.name, original.name)
                if original.parent.name.startswith('同名副本-') else Path(original.name))
    exports_root = (case.folder / 'exports').resolve()
    path = (exports_root / relative).resolve()
    if not path.is_relative_to(exports_root):
        raise ValueError('导出副本不在案件目录内')
    return path, relative


def inspect_bundle_exports(case):
    """核查案件全部历史导出副本的本地存在状态，供界面勾选和打包前校验使用。"""
    rows = []
    for index, item in enumerate(case.data['exports'], 1):
        path, relative = resolve_export_path(case, item)
        exists = path.is_file()
        rel_text = f'exports\\{relative}'
        rows.append(dict(
            index=index,
            item=item,
            path=path,
            relative=str(relative),
            display_path=rel_text,
            source=item['source'],
            offset=item['offset'],
            inode=item['inode'],
            size=item['size'],
            sha256=item['sha256'],
            time=item.get('time', ''),
            exists=exists,
            missing_reason='' if exists else f'本地副本缺失（{rel_text}）',
        ))
    return rows


def format_missing_exports(missing_rows):
    """生成清晰的中文缺失副本清单文本。"""
    lines = [f'以下 {len(missing_rows)} 条历史导出记录在本地 exports 目录中缺失（可能已被删除或被安全软件隔离）：']
    for row in missing_rows:
        lines.append(
            f'- #{row["index"]} {row["display_path"]}（镜像内路径：{row["source"]}，{row["size"]:,} 字节）'
        )
    return '\n'.join(lines)


def build_bundle(case, *, selected_indices=None, skip_missing=False):
    export_rows = inspect_bundle_exports(case)
    if selected_indices is not None:
        chosen = set(selected_indices)
        valid_indices = {row['index'] for row in export_rows}
        invalid = sorted(chosen - valid_indices)
        if invalid:
            raise ValueError('指定的导出序号无效：' + ', '.join(map(str, invalid)))
    else:
        chosen = {row['index'] for row in export_rows}

    missing_selected = [row for row in export_rows if row['index'] in chosen and not row['exists']]
    if missing_selected and not skip_missing:
        raise FileNotFoundError(
            format_missing_exports(missing_selected)
            + '\n请恢复缺失副本，或在复核包选项中取消勾选缺失项后再导出。'
        )

    report = case.report()
    if not case.data['verification']['ok']:
        raise ValueError('当前镜像与案件固定值不符，不能生成复核包')
    records = case.check_audit()
    data = case.data
    evidence = data['evidence']
    target = report.with_suffix('.zip')
    temporary = target.with_suffix('.partial')
    checksums = {}
    def put(archive, name, raw):
        if isinstance(raw, str):
            raw = raw.encode('utf-8')
        archive.writestr(name, raw)
        checksums[name] = hashlib.sha256(raw).hexdigest()

    def copy(archive, path, name, expected):
        digest = hashlib.sha256()
        with path.open('rb') as source, archive.open(name, 'w', force_zip64=True) as dest:
            while block := source.read(1024 * 1024):
                dest.write(block)
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError(f'材料摘要不一致：{path.name}')
        checksums[name] = expected

    try:
        with ZipFile(temporary, 'x') as archive:
            copy(archive, report, 'report.md', records[-1]['details']['sha256'])
            exports = []
            omitted_exports = []
            for row in export_rows:
                index = row['index']
                item = row['item']
                if index not in chosen:
                    omitted_exports.append({
                        **item,
                        'export_index': index,
                        'reason': '本地副本缺失' if not row['exists'] else '导出复核包时未勾选',
                    })
                    continue
                if not row['exists']:
                    omitted_exports.append({
                        **item,
                        'export_index': index,
                        'reason': '本地副本缺失',
                    })
                    continue
                path = row['path']
                name = f'exports/{index}/{path.name}'
                copy(archive, path, name, item['sha256'])
                exports.append({**item, 'member': name, 'recorded_size': item.get('recorded_size', item['size'])})
            for record in records:
                if record['action'] == 'CONTENT_SEARCH':
                    name = record['subject']
                    if Path(name).name != name:
                        raise ValueError('搜索记录名称无效')
                    copy(archive, case.folder / 'reports' / name, 'searches/' + name, record['details']['sha256'])
            put(archive, 'audit.jsonl', (case.folder / 'audit.jsonl').read_bytes())
            put(archive, 'audit.head', records[-1]['hash'])
            put(archive, 'verify_bundle.py', (Path(__file__).resolve().parents[2] / 'scripts' / 'verify_bundle.py').read_bytes())
            manifest = dict(format_version=1, case_id=data['id'], number=data['number'], examiner=data['examiner'],
                            python_version=sys.version.split()[0],
                            tsk_version=TSK().text('fls', ['-V']).strip(), evidence=evidence,
                            verification=data['verification'], source_comparison=source_status(evidence),
                            exports=exports, omitted_exports=omitted_exports,
                            findings=[r for r in records if r['action'] in OPERATIONS],
                            audit_head=records[-1]['hash'])
            put(archive, 'manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
            instructions = (
                '1. 与交付方单独保存的 ZIP SHA-256 比对；包内清单不能证明签名身份。\n'
                '2. 可使用独立取得的 scripts/verify_bundle.py 核验 ZIP（包中也附一份），或解压后逐项核对 SHA256SUMS.json。\n'
                '3. 原始镜像不在包内。独立取得镜像，核对 manifest.json 中的 SHA-256、覆盖范围和交付方摘要。\n'
                '4. 用 TSK icat -i raw -o 分区扇区偏移 镜像 inode 提取内容；EWF 改用 -i ewf 并指定 E01 首段；删除且未重分配时加 -r。\n'
                '5. 搜索命中 file_byte 是文件流内从零起的字节偏移；按 needle 的十六进制字节复查。\n'
                '6. 核对 exports 的来源、实际长度、摘要及删除恢复限制，按序号关联 findings 与 audit.jsonl。'
            )
            if omitted_exports:
                instructions += (
                    f'\n7. 本次复核包按需纳入 {len(exports)} 个导出副本，另有 {len(omitted_exports)} 条历史导出记录未打入'
                    '（未勾选或本地副本缺失），完整明细与原因见 manifest.json 的 omitted_exports 字段。'
                )
            put(archive, '复核说明.txt', instructions)
            archive.writestr('SHA256SUMS.json', json.dumps(checksums, ensure_ascii=False, indent=2).encode())
        temporary.rename(target)
        digest = sha256(target)
        target.with_suffix('.zip.sha256').write_text(digest + '  ' + target.name + '\n', encoding='utf-8')
        missing_count = sum(1 for item in omitted_exports if item['reason'] == '本地副本缺失')
        case.log('REVIEW_EXPORT', target.name, '成功', sha256=digest,
                 included_exports=len(exports), omitted_exports=len(omitted_exports),
                 missing_exports=missing_count)
        return target
    finally:
        temporary.unlink(missing_ok=True)
