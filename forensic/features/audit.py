"""按操作显示已验证的审计链；原始记录可逐条查看。"""
import json
from PySide6.QtCore import Qt
from ..core.formatting import display_time
from ..ui.analysis_panels import RecordsPanel, page
from .api import Feature, Panel

TITLES = {
    'CONTENT_SEARCH': '搜索文件内容', 'SOURCE_REGISTER': '登记证据来源', 'REVIEW_EXPORT': '生成复核包',
    'CASE_CREATE': '新建案件', 'CASE_OPEN': '打开案件', 'IMAGE_LOAD_BEGIN': '开始载入镜像',
    'IMAGE_LOAD': '载入镜像', 'HASH_FIXED': '固定镜像摘要', 'HASH_VERIFY': '校验镜像完整性',
    'FILE_BROWSE': '读取分区文件', 'PARTITIONS_SCAN': '扫描所有分区', 'FILE_FILTER': '筛选文件',
    'FILE_EXPORT': '导出文件', 'TIMELINE': '生成时间线', 'REPORT_GENERATE': '生成报告',
    'FILE_NOTE': '记录取证发现', 'FILE_COMPARE': '比对文件副本', 'FILE_HASH': '计算文件摘要',
}


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
                         [68, 165, 96, 135, 100], '搜索操作、人员、对象或结果')
        self._chronological = []
        self._descending = True
        self._sort_column = 0
        header = self.table.header()
        header.setSectionsClickable(True)
        header.setSortIndicatorShown(True)
        header.setSortIndicator(0, Qt.SortOrder.DescendingOrder)
        header.sectionClicked.connect(self._toggle_sort)
        for column in (0, 1):
            self.table.headerItem().setToolTip(column, '单击切换正序/倒序')

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
        self.table.header().setSortIndicator(column, order)
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
