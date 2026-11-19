"""文件筛选和选择；文件树控件只处理展示与定位。"""
from ..engines.tsk import entry_status
from .api import Action, Feature


def filter_files(context):
    if context.available():
        browser = context.browser()
        suffix, keyword = browser.suffix.text(), browser.keyword.text()
        context.task('筛选文件', lambda: context.case().filtered(suffix, keyword), browser.apply_filter)


def select(context, event=None):
    browser = context.browser()
    selected, entry = browser.tree.selectedItems(), context.selected_entry()
    if entry is None:
        browser.preview.clear('请选择目录中的文件' if selected else '请选择文件')
        if selected:
            browser.detail.setText(selected[0].text(0))
        return
    browser.detail.setText(f'{entry["path"]}  ·  {entry_status(entry)}  ·  inode {entry["inode"]}'
                          f'  ·  {entry["size"]} 字节  ·  分区偏移 {entry["offset"]}')
    if entry['directory'] or entry['mode'].startswith('V/'):
        browser.preview.clear('请选择目录中的文件')
    else:
        case = context.case()
        if (getattr(case, 'data', {}).get('evidence') or {}).get('large_image'):
            browser.preview.open_file(case.image(), entry, validate=case.check_source)
        else:
            browser.preview.open_file(case.image(), entry)


FEATURE = Feature('files', requires=('cases', 'evidence'), actions=(
    Action('filter', filter_files), Action('select', select),
))
