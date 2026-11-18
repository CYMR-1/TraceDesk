"""文件右键菜单中的取证记录、摘要计算与副本比较。"""
from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox
from ..core.file_tools import examine, record_note
from ..engines.tsk import can_export
from .api import Action, Feature


def record(context):
    if not context.available():
        return
    entry = context.selected_entry()
    text, ok = QInputDialog.getMultiLineText(context.root, '记录取证发现', entry['path'])
    if ok and text.strip():
        context.task('保存取证记录', lambda: record_note(context.case(), entry, text))


def inspect_file(context, compare=False):
    if not context.available():
        return
    case, entry = context.case(), context.selected_entry()
    other = None
    if compare:
        other, _ = QFileDialog.getOpenFileName(context.root, '选择与镜像内文件比较的本地副本',
                                              str(case.folder / 'exports'))
        if not other:
            return
    title = '校验文件一致性' if compare else '计算文件 SHA-256'

    def show(output):
        result, data = output
        lines = [entry['path'], result, f"读取 {data['size']} / {data['recorded_size']} 字节",
                 f"镜像内文件 SHA-256：{data['sha256']}"]
        if other:
            lines.extend([other, f"本地文件 SHA-256：{data['comparison_sha256']}"])
        lines.extend(filter(None, (data.get('read_note'), data.get('source_note'))))
        QMessageBox.information(context.root, title, '\n'.join(lines))

    context.task(title, lambda: examine(case, entry, other), show)


FEATURE = Feature('file_tools', requires=('files',), actions=(
    Action('file_note', record, '记录取证发现', 'file_menu', accepts_entry=can_export),
    Action('file_hash', inspect_file, '计算哈希值（SHA-256）', 'file_menu', accepts_entry=can_export),
    Action('compare_file', lambda ctx: inspect_file(ctx, True), '校验一致性…', 'file_menu', accepts_entry=can_export),
))
