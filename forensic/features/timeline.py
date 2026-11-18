"""时间线页面；刷新不会写入额外审计记录。"""
from .api import Feature, Panel


def render(context):
    case = context.case()
    if case is None:
        return '尚未打开案件'
    return 'MAC/B 时间线 · 东八区（UTC+8）\n\n' + '\n'.join(
        f"{row['time']}  {row['event']}  {row['path']}  ·  分区偏移 {row['offset']}"
        f"  ·  {row['status']}  ·  inode {row['inode']}" for row in case.timeline_events())


def version(context):
    case = context.case()
    return (id(case), id(case.data['inventory'])) if case else None


FEATURE = Feature('timeline', requires=('cases',), panels=(
    Panel('timeview', 'MAC 时间线', render, version),
))
