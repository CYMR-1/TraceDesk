"""新建、打开和切换案件。"""
from functools import partial
from pathlib import Path

from PySide6.QtWidgets import QMessageBox

from ..core.case import Case
from ..paths import CASES_DIR
from ..ui.views import NewCaseDialog
from ..ui.dialogs import choose_file
from .api import Action, Feature


def create_case(context, folder, number, examiner, target, *, folder_name=None):
    context.replace_case(Case.create(folder, number, examiner, target, folder_name=folder_name))


def new_case(context):
    if context.available(False):
        NewCaseDialog(context.root, partial(create_case, context)).exec()


def open_case(context):
    if not context.available(False):
        return
    path = choose_file(context.root, '打开案件 case.json', str(CASES_DIR), '案件元数据 (case.json)')
    if path:
        try:
            case = Case(Path(path).parent)
            case.log('CASE_OPEN', path, '成功')
            context.replace_case(case)
        except Exception as error:
            QMessageBox.critical(context.root, '打开失败', str(error))


FEATURE = Feature('cases', actions=(
    Action('new_case', new_case, '新建案件', 'header'),
    Action('open_case', open_case, '打开案件', 'header'),
    Action('create_case', create_case),
))
