"""新建、打开和切换案件。"""
from functools import partial
from pathlib import Path

from ..core.case import Case
from ..core.browser_index import prepare
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
        def read_case():
            case = Case(Path(path).parent)
            try:
                if len(case.data['inventory']) > 1000:
                    case.browser_index = prepare(case.data['inventory'])
                case.log('CASE_OPEN', path, '成功')
            except Exception:
                case.close()
                raise
            return case
        context.task('打开案件并读取清单', read_case, context.replace_case, False)


FEATURE = Feature('cases', actions=(
    Action('new_case', new_case, '新建案件', 'header'),
    Action('open_case', open_case, '打开案件', 'header'),
    Action('create_case', create_case),
))
