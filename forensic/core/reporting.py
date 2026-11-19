"""Markdown 报告内容生成；不进行证据读写、校验或审计写入。"""
from .formatting import now, display_time, deleted_export_summary
from ..engines.tsk import entry_status
from .findings import findings_text
from .coverage import coverage_text, source_status, SOURCE_FIELDS


def render_report(data, records, conclusion):
    e = data['evidence']
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ').replace('<', '&lt;').replace('>', '&gt;')
    lines = ['# 电子数据取证报告', '', f'生成时间（东八区）：{now()}', '', '## 案件信息', '']
    for label, key in [('案件编号','number'), ('取证人员','examiner'), ('取证对象','target')]:
        lines.append(f'- {label}：{cell(data[key])}')
    lines.append(f'- 建立时间：{display_time(data["created"])}')
    lines += ['', '## 原始证据与完整性', '', f'- 路径：{cell(e["path"])}', f'- 字节数：{e["size"]}',
              f'- 初始逻辑介质 SHA-256：`{e["sha256"]}`',
              f'- {"与已核验分段对应的逻辑摘要（本次未重新解码）" if e.get("format") == "EWF" else "当前 SHA-256"}：`{data["verification"]["actual"] or "无法确认"}`',
              f'- 校验方式：{data["verification"].get("method", "复算 RAW SHA-256")}',
              f'- 校验结论：{conclusion}', f'- 声明范围：{coverage_text(e.get("coverage"))}',
              f'- 来源校验：{source_status(e)}',
              *[f'- {label}：{cell(e.get("provenance", {}).get(key, "") or "未登记")}' for key,label in SOURCE_FIELDS.items()],
              '', '## 文件清单摘要', '',
              f'已识别 {len(e["partitions"])} 个分区；当前清单共 {len(data["inventory"])} 项（最多列出 200 项）。', '']
    scans = {p['offset']: p for p in data.get('partition_scans', [])}
    for partition in e['partitions']:
        scan = scans.get(partition['offset'])
        state = (f'已读取 {scan["count"]} 项' if scan['status'] == 'ready'
                 else f'无法读取：{scan["error"]}') if scan else '未完成全部分区读取'
        lines.append(f'- 分区偏移 {partition["offset"]}：{cell(partition["description"])}；{cell(state)}')
    lines += ['', '| 分区偏移 | 路径 | 状态 | inode | 字节数 | M (UTC+8) | A (UTC+8) | C (UTC+8) |',
              '| ---: | --- | --- | --- | ---: | --- | --- | --- |']
    for row in data['inventory'][:200]:
        dates = [display_time(row[k]) for k in ('mtime','atime','ctime')]
        lines.append('| ' + ' | '.join(map(cell, [row['offset'], row['path'], entry_status(row), row['inode'], row['size'], *dates])) + ' |')
    lines += ['', '## 导出副本', '']
    for row in data['exports']:
        lines.append(f'- 分区偏移 {row["offset"]} · {cell(row["source"])} → {cell(row["path"])}；SHA-256：`{row["sha256"]}`')
        if row.get('deleted'):
            lines.append('  ' + cell(deleted_export_summary(row)))
    findings = findings_text(records)
    if findings:
        lines += ['', '## 文件取证发现', '']
        lines.extend('    ' + line for line in findings.splitlines())
    lines += ['', '## 审计日志摘要', '', f'审计链验证通过；当前 {len(records)} 条；锚点：`{records[-1]["hash"]}`。', '',
              '| 时间 (UTC+8) | 主体 | 操作 | 对象 | 结果 |', '| --- | --- | --- | --- | --- |']
    for row in records[-100:]:
        fields = [display_time(row['timestamp']), row['actor'], row['action'], row['subject'], row['result']]
        lines.append('| ' + ' | '.join(map(cell, fields)) + ' |')
    lines += ['', '## 取证人员确认', '', '确认人：________________    日期：________________', '',
              '## 适用边界', '', '本工具为教学原型，实施应用层只读约束，不替代硬件写保护器或法定资质认证。',
              'MAC 时间来自文件系统元数据，可能被修改；C 表示元数据变更时间，并非通用的创建时间。',
              '日志哈希链和本地锚点可发现意外修改或单独截断，不能抵抗同时重写全部案件数据的攻击者。',
              '案件库与镜像位于独立目录；若要求不同物理介质，需由操作人员另行安排。', '']
    return '\n'.join(lines)
