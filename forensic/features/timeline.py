"""时间线页面；刷新不会写入额外审计记录。"""
from .api import Feature, Panel
from ..ui.analysis_panels import TimelinePanel


def render(context):
    case = context.case()
    if case is None:
        return '尚未打开案件', []
    rows = case.timeline_events()
    return f'MAC/B 时间线 · {len(rows)} 条事件 · UTC+8 · C 为元数据变更，B 为创建；FAT 不保存 C 时间', rows


def version(context):
    case = context.case()
    return (id(case), id(case.data['inventory'])) if case else None


FEATURE = Feature('timeline', requires=('cases',), panels=(
    Panel('timeview', 'MAC 时间线', render, version, TimelinePanel),
))
