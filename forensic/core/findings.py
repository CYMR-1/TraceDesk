"""从已核验的操作记录生成按文件归组的取证发现。"""
from .formatting import display_time


OPERATIONS = {'FILE_NOTE': '取证笔记', 'FILE_HASH': '计算摘要', 'FILE_COMPARE': '比对副本'}


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
                               ('source_note', '来源状态'), ('source_verification', '操作时的完整性状态'), ('read_note', '读取说明'), ('error', '错误')):
                if d.get(key):
                    lines.append(f'  {label}：{d[key]}')
        sections.append('\n'.join(lines))
    return '\n\n'.join(sections)
