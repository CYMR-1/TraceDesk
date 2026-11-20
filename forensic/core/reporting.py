"""Markdown 报告内容生成；不进行证据读写、校验或审计写入。"""
from .coverage import SOURCE_FIELDS, coverage_text, source_status
from .findings import ACTION_TITLES, OPERATIONS, group_findings
from .formatting import deleted_export_summary, display_time, now
from ..engines.tsk import entry_status


def _cell(value):
    return (str(value).replace('|', '\\|').replace('\n', ' ')
            .replace('\r', ' ').replace('<', '&lt;').replace('>', '&gt;'))


def _format_size(size):
    units = (('TiB', 1 << 40), ('GiB', 1 << 30), ('MiB', 1 << 20), ('KiB', 1 << 10))
    for unit, scale in units:
        if size >= scale:
            return f'{size:,} 字节（{size / scale:.2f} {unit}）'
    return f'{size:,} 字节'


def render_report(data, records, conclusion):
    evidence = data['evidence']
    inventory = data.get('inventory', [])
    exports = data.get('exports', [])
    groups = group_findings(records)
    searches = [r for r in records if r['action'] == 'CONTENT_SEARCH']

    active_files = sum(1 for row in inventory if not row.get('deleted') and not row.get('directory'))
    deleted_items = sum(1 for row in inventory if row.get('deleted'))
    directories = sum(1 for row in inventory if row.get('directory'))

    lines = [
        '# 电子数据取证报告',
        '',
        f'> 生成时间（UTC+8）：{display_time(now(), compact=True)} · 工作模式：应用层只读',
        '',
        '## 案件信息',
        '',
        '| 项目 | 内容 |',
        '| --- | --- |',
        f'| 案件编号 | {_cell(data["number"])} |',
        f'| 取证人员 | {_cell(data["examiner"])} |',
        f'| 取证对象 | {_cell(data["target"])} |',
        f'| 案件建立时间（UTC+8） | {display_time(data["created"])} |',
        f'| 核心统计 | {len(evidence["partitions"])} 个分区 · 清单 {len(inventory):,} 项 · '
        f'内容搜索 {len(searches)} 次 · 导出副本 {len(exports)} 个 · 取证发现 {len(groups)} 个文件 · 审计记录 {len(records)} 条 |',
        '',
        '## 原始证据与完整性',
        '',
        f'> **完整性校验结论**：{_cell(conclusion)}',
        '',
        '| 校验与来源项 | 内容 |',
        '| --- | --- |',
        f'| 镜像路径 | `{_cell(evidence["path"])}` |',
        f'| 镜像格式 | {_cell(evidence.get("format", "RAW"))} |',
        f'| 逻辑介质大小 | {_format_size(evidence["size"])} |',
    ]
    if evidence.get('format') == 'EWF' and evidence.get('segments'):
        segs = evidence['segments']
        encap_size = sum(item['size'] for item in segs)
        lines.append(f'| EWF 分段封装 | 共 {len(segs)} 段 · 封装总大小 {_format_size(encap_size)} |')

    actual_label = ('已核验分段对应的逻辑摘要（本次未重新解码）'
                    if evidence.get('format') == 'EWF' else '当前复算 SHA-256')
    lines.extend([
        f'| 初始逻辑介质 SHA-256 | `{evidence["sha256"] or "待固定"}` |',
        f'| {actual_label} | `{data["verification"]["actual"] or "无法确认"}` |',
        f'| 完整读取时间（UTC+8） | {display_time(data["verification"]["time"])} |',
        f'| 校验方式 | {_cell(data["verification"].get("method", "复算 RAW SHA-256"))} |',
        f'| 声明范围判定 | {_cell(coverage_text(evidence.get("coverage")))} |',
        f'| 交付方摘要比对 | {_cell(source_status(evidence))} |',
    ])
    provenance = evidence.get('provenance', {})
    for key, label in SOURCE_FIELDS.items():
        lines.append(f'| {label} | {_cell(provenance.get(key, "") or "未登记")} |')

    # 分区与文件清单摘要
    lines.extend([
        '',
        '## 文件清单摘要',
        '',
        f'已识别 **{len(evidence["partitions"])}** 个分区，当前清单共 **{len(inventory):,}** 项'
        f'（现存文件 {active_files:,} 项 · 已删除记录 {deleted_items:,} 项 · 目录 {directories:,} 项；下方最多展示前 200 项）。',
    ])
    if data.get('index_verification'):
        lines.extend(['', f'- 建立清单时的完整性状态：{_cell(data["index_verification"])}'])

    scans = {p['offset']: p for p in data.get('partition_scans', [])}
    lines.extend([
        '',
        '### 分区概览',
        '',
        '| 分区偏移（扇区） | 分区说明 | 扫描状态 |',
        '| ---: | --- | --- |',
    ])
    for partition in evidence['partitions']:
        scan = scans.get(partition['offset'])
        state = (f'已读取 {scan["count"]:,} 项' if scan['status'] == 'ready'
                 else f'无法读取：{scan["error"]}') if scan else '未完成全部分区读取'
        lines.append(f'| {partition["offset"]} | {_cell(partition["description"])} | {_cell(state)} |')

    if inventory:
        lines.extend([
            '',
            '### 文件清单抽样（前 200 项）',
            '',
            '| 分区偏移 | 路径 | 状态 | inode | 字节数 | M (UTC+8) | A (UTC+8) | C (UTC+8) | B (UTC+8) |',
            '| ---: | --- | --- | --- | ---: | --- | --- | --- | --- |',
        ])
        for row in inventory[:200]:
            dates = [display_time(row[k], compact=True) for k in ('mtime', 'atime', 'ctime', 'crtime')]
            fields = [row['offset'], row['path'], entry_status(row), row['inode'], row['size'], *dates]
            lines.append('| ' + ' | '.join(map(_cell, fields)) + ' |')
    else:
        lines.extend(['', '尚未建立完整文件清单。'])

    # 导出副本
    lines.extend(['', '## 导出副本', ''])
    if exports:
        lines.extend([
            '| 序号 | 分区偏移 | 镜像内路径 | 导出路径 | 字节数 | SHA-256 | 说明 |',
            '| ---: | ---: | --- | --- | ---: | --- | --- |',
        ])
        for index, row in enumerate(exports, 1):
            notes = []
            if row.get('source_verification'):
                notes.append('完整性状态：' + row['source_verification'])
            if row.get('deleted'):
                notes.append(deleted_export_summary(row))
            fields = [
                index, row['offset'], row['source'], row['path'],
                f'{row["size"]:,}', f'`{row["sha256"]}`', '；'.join(notes) or '正常导出',
            ]
            lines.append('| ' + ' | '.join(_cell(v) if i != 5 else v for i, v in enumerate(fields)) + ' |')
    else:
        lines.append('本案件尚未导出文件副本。')

    # 内容搜索记录（放在“文件取证发现”之前，保持“文件取证发现”紧邻“审计日志摘要”）
    if searches:
        lines.extend([
            '',
            '## 内容搜索记录',
            '',
            '| 序号 | 时间 (UTC+8) | 搜索内容 | 编码 | 状态 | 已处理/总数 | 命中数 | 失败数 | 详情清单 |',
            '| ---: | --- | --- | --- | --- | --- | ---: | ---: | --- |',
        ])
        for index, row in enumerate(searches, 1):
            d = row.get('details', {})
            visited = f"{d.get('visited', 0):,}/{d.get('eligible', 0):,}"
            fields = [
                index, display_time(row['timestamp'], compact=True),
                d.get('query', ''), d.get('encoding', ''), row['result'],
                visited, d.get('hits', 0), d.get('failed', 0), f'reports/{row["subject"]}',
            ]
            lines.append('| ' + ' | '.join(map(_cell, fields)) + ' |')

    # 文件取证发现（结构化 Markdown 概览 + 分文件明细）
    if groups:
        lines.extend([
            '',
            '## 文件取证发现',
            '',
            f'共涉及 **{len(groups)}** 个文件，均来自已通过哈希链校验的操作记录。',
            '',
            '| 序号 | 镜像内路径 | 状态 | 分区偏移 | inode | 记录数 | 最近记录 (UTC+8) |',
            '| ---: | --- | --- | ---: | --- | ---: | --- |',
        ])
        for index, ((path, offset, inode, deleted, _), items) in enumerate(groups.items(), 1):
            status = '已删除' if deleted else '现存'
            latest = display_time(items[-1]['timestamp'], compact=True)
            lines.append('| ' + ' | '.join(map(_cell, [index, path, status, offset, inode, len(items), latest])) + ' |')

        for index, ((path, offset, inode, deleted, image_hash), items) in enumerate(groups.items(), 1):
            status = '已删除' if deleted else '现存'
            lines.extend([
                '',
                f'### {index}. {_cell(path)}',
                '',
                f'- **文件定位**：分区偏移 {offset} 扇区 · inode `{_cell(inode)}` · 状态：{status}',
                f'- **来源镜像 SHA-256**：`{image_hash or "记录时待固定"}`',
            ])
            for r in items:
                d = r['details']
                lines.append(
                    f'- **`#{r["seq"]}` {display_time(r["timestamp"], compact=True)}** · '
                    f'{_cell(r["actor"])} · {OPERATIONS[r["action"]]} · **{_cell(r["result"])}**'
                )
                if 'size' in d:
                    lines.append(f'  - 读取长度：{d["size"]:,} / {d["recorded_size"]:,} 字节')
                if 'file_byte' in d:
                    lines.append(f'  - 命中字节偏移：`{d["file_byte"]}`（`0x{d["file_byte"]:X}`）')
                for key, label in (
                    ('note', '笔记'), ('sha256', '读取内容 SHA-256'),
                    ('comparison', '对照文件'), ('comparison_sha256', '对照 SHA-256'),
                    ('before', '前文 HEX'), ('after', '后文 HEX'),
                    ('search_record', '关联搜索记录'), ('source_note', '来源状态'),
                    ('source_verification', '操作时的完整性状态'), ('read_note', '读取说明'), ('error', '错误'),
                ):
                    if d.get(key):
                        val = f'`{_cell(d[key])}`' if key in ('sha256', 'comparison_sha256', 'before', 'after') else _cell(d[key])
                        lines.append(f'  - {label}：{val}')

    # 审计日志摘要
    shown_audit = records[-100:]
    lines.extend([
        '',
        '## 审计日志摘要',
        '',
        f'审计链验证通过；共 **{len(records)}** 条记录'
        + (f'（下方展示最近 {len(shown_audit)} 条）' if len(records) > len(shown_audit) else '')
        + f'；尾部哈希锚点：`{records[-1]["hash"]}`。',
        '',
        '| 序号 | 时间 (UTC+8) | 操作人员 | 操作 | 对象 | 结果 |',
        '| ---: | --- | --- | --- | --- | --- |',
    ])
    for row in shown_audit:
        title = ACTION_TITLES.get(row['action'], row['action'])
        fields = [row['seq'], display_time(row['timestamp']), row['actor'], title, row['subject'], row['result']]
        lines.append('| ' + ' | '.join(map(_cell, fields)) + ' |')

    lines.extend([
        '',
        '## 取证人员确认',
        '',
        '| 角色 | 签名 | 日期 |',
        '| --- | --- | --- |',
        '| 取证人员 | ________________ | ________________ |',
        '| 复核人员 | ________________ | ________________ |',
        '',
        '## 适用边界',
        '',
        '- 本工具为教学原型，实施应用层只读约束，不替代硬件写保护器或法定资质认证。',
        '- MACB 时间来自文件系统元数据，可能被修改；C 表示元数据变更时间，并非通用的创建时间。',
        '- 日志哈希链和本地锚点可发现意外修改或单独截断，不能抵抗同时重写全部案件数据的攻击者。',
        '- 案件库与镜像位于独立目录；若要求不同物理介质，需由操作人员另行安排。',
        '',
    ])
    return '\n'.join(lines)
