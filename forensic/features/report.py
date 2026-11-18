"""报告生成入口。报告内容由 core.reporting 负责。"""
from PySide6.QtWidgets import QMessageBox

from .api import Action, Feature


def report(context):
    if context.available():
        context.task('校验并生成 Markdown 报告', context.case().report,
                     lambda path: QMessageBox.information(context.root, '报告已生成', str(path)))


FEATURE = Feature('report', requires=('cases',), actions=(
    Action('report', report, '生成 Markdown 报告', 'header', 'violet'),
))
