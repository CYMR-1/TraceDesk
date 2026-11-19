"""导出副本及导出结果弹窗。"""
from PySide6.QtWidgets import QMessageBox

from ..core.formatting import deleted_export_summary
from ..engines.tsk import can_export
from ..ui.views import ExportResultDialog
from .api import Action, Feature


def export(context):
    if not context.available():
        return
    entry = context.selected_entry()
    if not entry or not can_export(entry):
        QMessageBox.information(context.root, '导出文件', '请选择一个现存或已删除的文件。')
        return

    def done(path):
        record = next(r for r in reversed(context.case().data['exports']) if r['path'] == str(path))
        title = '部分导出' if record['size'] < entry['size'] else '导出成功'
        ExportResultDialog(context.root, path, title, ' · '.join(filter(None, (deleted_export_summary(record), record.get('source_verification'))))).exec()

    context.task('校验并导出证据副本', lambda: context.case().export(entry), done)


FEATURE = Feature('export', requires=('files',), actions=(
    Action('export', export, '导出所选文件', 'preview', 'soft', accepts_entry=can_export),
))
