"""审计日志页面；底层审计保护不依赖此页面是否启用。"""
from ..core.formatting import display_time
from .api import Feature, Panel


def render(context):
    case = context.case()
    if case is None:
        return '尚未打开案件'
    records = case.check_audit()
    return f'审计哈希链验证通过 · {len(records)} 条记录\n\n' + '\n\n'.join(
        f'#{r["seq"]} {display_time(r["timestamp"])}  {r["actor"]}\n{r["action"]}  {r["subject"]}\n'
        f'结果：{r["result"]}  哈希：{r["hash"]}' for r in records)


FEATURE = Feature('audit', requires=('cases',), panels=(Panel('audit', '审计日志', render),))
