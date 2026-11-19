"""时间线页面；刷新不会写入额外审计记录。"""
from .api import Feature, Panel
from ..ui.analysis_panels import TimelinePanel


def render(context):
    case = context.case()
    if case is None:
        return '尚未打开案件', []
    if (case.data.get('evidence') or {}).get('large_image') and case.browsing_directories:
        return '请先在文件浏览中建立完整文件索引以生成全案时间线。', []
    def build():
        rows = case.timeline_events()
        hint = f'MACB 时间线 · {len(rows)} 条事件 · UTC+8 · C 为元数据变更，B 为创建；FAT 不保存 C 时间'
        return (hint, rows, context.task) if len(case.data['inventory']) > 1000 else (hint, rows)
    if len(case.data['inventory']) > 1000:
        return lambda ready: context.task('生成时间线', build, ready)
    return build()


def version(context):
    case = context.case()
    return (id(case), id(case.data['inventory'])) if case else None


FEATURE = Feature('timeline', requires=('cases',), panels=(
    Panel('timeview', 'MACB 时间线', render, version, TimelinePanel),
))
