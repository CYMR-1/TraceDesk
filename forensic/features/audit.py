"""按操作显示已验证的审计链；原始记录可逐条查看。"""
import json
from PySide6.QtCore import Qt
from ..core.findings import ACTION_TITLES as TITLES
from ..core.formatting import display_time
from ..ui.analysis_panels import RecordsPanel, page
from .api import Feature, Panel


def render(context):
    if context.case() is None:
        return '尚未打开案件', []
    try:
        records = context.case().check_audit()
    except (ValueError, KeyError, RuntimeError, OSError) as error:
        return f'日志校验失败：{error}', []
    return f'日志链校验通过 · 共 {len(records)} 条操作', records


class AuditPanel(RecordsPanel):
    def __init__(self, parent):
        super().__init__(parent, ['序号', '时间（UTC+8）', '操作人员', '操作', '结果', '对象'],
                         [68, 165, 115, 148, 110], '搜索操作、人员、对象或结果',
                         filter_columns=(2, 3, 4), sort_columns=(0, 1))
        self._chronological = []
        self._descending = True
        self._sort_column = 0
        self.header.setSortIndicator(0, Qt.SortOrder.DescendingOrder)
        self.header.sort_requested.connect(self._toggle_sort)
        for column in (0, 1):
            self.table.headerItem().setToolTip(column, '单击切换正序/倒序')
        for column in (2, 3, 4):
            self.table.headerItem().setToolTip(column, '单击下拉筛选')

    def _sorted_records(self):
        if self._sort_column == 1:
            return sorted(self._chronological,
                          key=lambda r: (display_time(r['timestamp']), r['seq']),
                          reverse=self._descending)
        return list(reversed(self._chronological)) if self._descending else list(self._chronological)

    def _toggle_sort(self, column):
        if column not in (0, 1):
            return
        self._descending = not self._descending
        self._sort_column = column
        order = Qt.SortOrder.DescendingOrder if self._descending else Qt.SortOrder.AscendingOrder
        self.header.setSortIndicator(column, order)
        self.records = self._sorted_records()
        self._populate()

    def set_text(self, result):
        status, records = result
        self._chronological = list(records)
        super().set_text((status, self._sorted_records()))

    def columns(self, record):
        return [str(record['seq']), display_time(record['timestamp'], compact=True),
                record['actor'], TITLES.get(record['action'], record['action']),
                record['result'], record['subject']]

    def details(self, record):
        seq, _, actor, action, result, subject = self.columns(record)
        sections = [('操作详情', [('时间（UTC+8）', display_time(record['timestamp'])),
                              ('操作人员', actor), ('对象', subject), ('结果', result),
                              ('操作代码', record['action'])])]
        labels = {'note': '笔记', 'error': '错误', 'sha256': 'SHA-256', 'offset': '分区偏移（扇区）',
                  'size': '字节数', 'count': '数量', 'keyword': '关键词', 'actual': '实测摘要'}
        if record['details']:
            sections.append(('操作参数与结果', [(labels.get(key, key), value if isinstance(value, str)
                             else json.dumps(value, ensure_ascii=False)) for key, value in record['details'].items()]))
        sections.append(('审计链', [('上一条记录哈希', record['previous']), ('本条记录哈希', record['hash'])]))
        return page(f'#{seq} · {action}', '审计日志 · UTC+8', sections)


FEATURE = Feature('audit', requires=('cases',), panels=(
    Panel('audit', '审计日志', render, widget_factory=AuditPanel),
))
