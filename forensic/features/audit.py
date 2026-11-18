"""按操作显示已验证的审计链；原始记录可逐条查看。"""
import json
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QLabel, QLineEdit, QPlainTextEdit, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)
from ..core.formatting import display_time
from .api import Feature, Panel

TITLES = {
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


class AuditPanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        self.search = QLineEdit()
        self.search.setPlaceholderText('搜索操作、人员、对象或结果')
        layout.addWidget(self.search)
        self.table = QTreeWidget()
        self.table.setRootIsDecorated(False)
        self.table.setAlternatingRowColors(True)
        self.table.setHeaderLabels(['序号', '时间（UTC+8）', '操作人员', '操作', '结果', '对象'])
        for index, width in enumerate((54, 153, 96, 135, 100)):
            self.table.setColumnWidth(index, width)
        layout.addWidget(self.table, 3)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlaceholderText('选择一条操作查看完整审计记录')
        layout.addWidget(self.text, 1)
        self.records = []
        self.table.currentItemChanged.connect(self._detail)
        self.search.textChanged.connect(self._populate)

    def set_text(self, result):
        status, self.records = result
        self.status.setText(status)
        self._populate()

    def _populate(self):
        current = self.table.currentItem()
        selected = current.text(0) if current else None
        self.table.clear()
        self.text.clear()
        query = self.search.text().strip().casefold()
        for record in reversed(self.records):
            columns = [str(record['seq']), display_time(record['timestamp'], compact=True),
                       record['actor'], TITLES.get(record['action'], record['action']),
                       record['result'], record['subject']]
            if query and query not in ' '.join(columns).casefold():
                continue
            item = QTreeWidgetItem(self.table, columns)
            item.setData(0, Qt.ItemDataRole.UserRole, record['seq'] - 1)
            if columns[0] == selected:
                self.table.setCurrentItem(item)

    def _detail(self, item, previous):
        if item is None:
            self.text.clear()
        else:
            record = self.records[item.data(0, Qt.ItemDataRole.UserRole)]
            note = record['details'].get('note') or record['details'].get('error') or ''
            self.text.setPlainText((note + '\n\n' if note else '') +
                                   json.dumps(record, ensure_ascii=False, indent=2))


FEATURE = Feature('audit', requires=('cases',), panels=(
    Panel('audit', '审计日志', render, widget_factory=AuditPanel),
))
