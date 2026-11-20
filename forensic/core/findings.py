"""从已核验的操作记录生成按文件归组的取证发现，并支持一键导出证据文件与汇总清单。"""
import hashlib
import uuid

from .formatting import display_time, now
from ..engines.tsk import can_export


OPERATIONS = {'FILE_NOTE': '取证笔记', 'FILE_HASH': '计算摘要', 'FILE_COMPARE': '比对副本'}
ACTION_TITLES = {
    'CONTENT_SEARCH': '搜索文件内容', 'SOURCE_REGISTER': '登记证据来源', 'REVIEW_EXPORT': '生成复核包',
    'CASE_CREATE': '新建案件', 'CASE_OPEN': '打开案件', 'IMAGE_LOAD_BEGIN': '开始载入镜像',
    'IMAGE_LOAD': '载入镜像', 'HASH_FIXED': '固定镜像摘要', 'HASH_VERIFY': '校验镜像完整性',
    'FILE_BROWSE': '读取分区文件', 'PARTITIONS_SCAN': '扫描所有分区', 'FILE_FILTER': '筛选文件',
    'FILE_EXPORT': '导出文件', 'TIMELINE': '生成时间线', 'REPORT_GENERATE': '生成报告',
    'FILE_NOTE': '记录取证发现', 'FILE_COMPARE': '比对文件副本', 'FILE_HASH': '计算文件摘要',
    'FINDINGS_EXPORT': '导出取证发现',
}


def group_findings(records):
    groups = {}
    for record in records:
        if record['action'] not in OPERATIONS:
            continue
        d = record['details']
        key = (record['subject'], d['offset'], d['inode'], d['deleted'], d['image_sha256'])
        groups.setdefault(key, []).append(record)
    return groups


def findings_text(records):
    groups = {}
    for record in records:
        if record['action'] not in OPERATIONS:
            continue
        d = record['details']
        key = (record['subject'], d['offset'], d['inode'], d['deleted'], d['image_sha256'])
        groups.setdefault(key, []).append(record)

    sections = []
    for (path, offset, inode, deleted, image_hash), items in groups.items():
        status = '已删除' if deleted else '现存'
        lines = [f'{path}  ·  分区偏移 {offset} 扇区  ·  inode {inode}  ·  {status}',
                 f'来源镜像 SHA-256：{image_hash or "记录时待固定"}']
        for r in items:
            d = r['details']
            lines.append(f"#{r['seq']}  {display_time(r['timestamp'], compact=True)}  "
                         f"{r['actor']}  {OPERATIONS[r['action']]}  {r['result']}")
            if 'size' in d:
                lines.append(f"  读取 {d['size']} / {d['recorded_size']} 字节")
            for key, label in (('note', '笔记'), ('sha256', '读取内容 SHA-256'),
                               ('comparison', '对照文件'), ('comparison_sha256', '对照 SHA-256'),
                               ('source_note', '来源状态'), ('source_verification', '操作时的完整性状态'),
                               ('read_note', '读取说明'), ('error', '错误')):
                if d.get(key):
                    lines.append(f'  {label}：{d[key]}')
        sections.append('\n'.join(lines))
    return '\n\n'.join(sections)


def export_findings(case, groups):
    """一键导出取证发现中对应的镜像文件副本及 Markdown 汇总清单。"""
    if not groups:
        raise ValueError('当前没有可导出的取证发现。')
    if not case.data.get('evidence'):
        raise ValueError('当前案件尚未加载镜像。')

    entry_map = {}
    for entry in case.displayed_entries():
        key = (entry['path'], entry['offset'], str(entry['inode']), bool(entry.get('deleted', False)))
        entry_map.setdefault(key, entry)

    results = []
    exported_count = 0
    failed = []
    for items in groups:
        first = items[0]
        d = first['details']
        key = (first['subject'], d['offset'], str(d['inode']), bool(d['deleted']))
        entry = entry_map.get(key)
        if entry is None or not can_export(entry):
            reason = '当前文件清单中未找到对应条目（大镜像请先建立完整文件索引或进入所在目录）'
            failed.append((first['subject'], reason))
            results.append((items, None, reason))
            continue
        try:
            dest = case.export(entry)
            exported_count += 1
            results.append((items, dest, None))
        except Exception as error:
            reason = str(error)
            failed.append((first['subject'], reason))
            results.append((items, None, reason))

    summary_name = f'取证发现汇总_{uuid.uuid4().hex[:8]}.md'
    summary = case.folder / 'exports' / summary_name
    data = case.data
    lines = [
        f"# 取证发现一键导出汇总 · {data['number']}",
        '',
        f"- 导出时间（UTC+8）：{display_time(now(), compact=True)}",
        f"- 取证人员：{data['examiner']} · 对象：{data['target']}",
        f"- 发现文件数：{len(groups)} · 成功导出文件：{exported_count} · 跳过/失败：{len(failed)}",
        '',
        '## 导出清单',
        '',
        '| 序号 | 镜像内路径 | 状态 | 分区偏移 | inode | 导出结果 |',
        '| --- | --- | --- | --- | --- | --- |',
    ]
    for index, (items, dest, error) in enumerate(results, 1):
        first = items[0]
        d = first['details']
        status = '已删除' if d['deleted'] else '现存'
        outcome = str(dest.relative_to(case.folder)) if dest is not None else f'未导出：{error}'
        safe_path = first['subject'].replace('|', '\\|')
        safe_out = outcome.replace('|', '\\|')
        lines.append(f"| {index} | `{safe_path}` | {status} | {d['offset']} | `{d['inode']}` | {safe_out} |")

    lines.extend(['', '## 取证记录明细', ''])
    for index, (items, dest, error) in enumerate(results, 1):
        first = items[0]
        d = first['details']
        status = '已删除' if d['deleted'] else '现存'
        lines.append(f"### {index}. {first['subject']}")
        lines.append(f"- 状态：{status} · 分区偏移：{d['offset']} 扇区 · inode：`{d['inode']}`")
        lines.append(f"- 来源镜像 SHA-256：`{d['image_sha256'] or '记录时待固定'}`")
        if dest is not None:
            lines.append(f"- 导出副本：`{dest}`")
        elif error:
            lines.append(f"- 导出说明：{error}")
        for r in items:
            rd = r['details']
            lines.append(f"  - `#{r['seq']}` {display_time(r['timestamp'], compact=True)} · {r['actor']} · {OPERATIONS[r['action']]} · {r['result']}")
            for field, title in (('note', '笔记'), ('file_byte', '文件内字节偏移'), ('sha256', 'SHA-256'),
                                 ('comparison', '对照文件'), ('comparison_sha256', '对照 SHA-256'),
                                 ('source_note', '来源状态'), ('source_verification', '完整性状态'),
                                 ('read_note', '读取说明'), ('error', '错误')):
                if field in rd and rd[field] != '':
                    lines.append(f"    - {title}：{rd[field]}")
        lines.append('')

    raw = '\n'.join(lines).encode('utf-8')
    summary.write_bytes(raw)
    case.log('FINDINGS_EXPORT', summary.name, '部分导出' if failed else '成功',
             total=len(groups), exported=exported_count, failed=len(failed),
             sha256=hashlib.sha256(raw).hexdigest())
    return summary, exported_count, failed
