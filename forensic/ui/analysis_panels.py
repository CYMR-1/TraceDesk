"""可搜索分析列表与分层证据详情。"""
from html import escape
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QLabel, QLineEdit, QPlainTextEdit, QSplitter, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget
from ..core.formatting import display_time
from ..core.findings import OPERATIONS


def page(title, subtitle, sections):
    body = ''.join('<h3>' + escape(name) + '</h3><table width="100%" cellspacing="0" cellpadding="9">' + ''.join(
        '<tr><td width="150" bgcolor="#edf4f1"><b>' + escape(str(k)) + '</b></td><td bgcolor="#f8faf9">' + escape(str(v)).replace('\n', '<br>') + '</td></tr>' for k, v in rows) + '</table>' for name, rows in sections)
    return '<html><head><style>body{color:#24332f;}h2{color:#087f6b;}h3{color:#48635a;}</style></head><body><h2>' + escape(title) + '</h2><p>' + escape(subtitle) + '</p>' + body + '</body></html>'


class RecordsPanel(QWidget):
    def __init__(self, parent, headers, widths, placeholder):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setProperty('role', 'section')
        layout.addWidget(self.status)
        self.search = QLineEdit()
        self.search.setPlaceholderText(placeholder)
        layout.addWidget(self.search)
        split = QSplitter(Qt.Orientation.Vertical)
        self.split = split
        self.table = QTreeWidget()
        self.table.setRootIsDecorated(False)
        self.table.setAlternatingRowColors(True)
        self.table.setUniformRowHeights(True)
        self.table.setHeaderLabels(headers)
        self.table.setHorizontalScrollMode(QTreeWidget.ScrollMode.ScrollPerPixel)
        for i, width in enumerate(widths):
            self.table.setColumnWidth(i, width)
        self.text = QTextBrowser()
        self.text.setOpenExternalLinks(False)
        split.addWidget(self.table)
        split.addWidget(self.text)
        split.setSizes([430, 240])
        layout.addWidget(split, 1)
        self.records = []
        self.search.textChanged.connect(self._populate)
        self.table.currentItemChanged.connect(self._detail)

    def set_text(self, result):
        status, self.records = result
        self.status.setText(status)
        self._populate()

    def _populate(self):
        current = self.table.currentItem()
        selected = current.data(0, Qt.ItemDataRole.UserRole) if current else None
        self.table.clear()
        self.text.clear()
        query = self.search.text().strip().casefold()
        for record in self.records:
            columns = self.columns(record)
            if query and query not in (' '.join(columns) + ' ' + str(record)).casefold():
                continue
            item = QTreeWidgetItem(self.table, columns)
            item.setData(0, Qt.ItemDataRole.UserRole, record)
            if record == selected:
                self.table.setCurrentItem(item)
        if self.table.currentItem() is None:
            self.text.setHtml(page('选择一条记录查看详情', f'当前显示 {self.table.topLevelItemCount()} 条', []))

    def _detail(self, item, previous):
        if item is None:
            self.text.clear()
        else:
            self.text.setHtml(self.details(item.data(0, Qt.ItemDataRole.UserRole)))


class TimelinePanel(RecordsPanel):
    def __init__(self, parent):
        super().__init__(parent, ['时间（UTC+8）', '事件', '状态', '分区偏移', 'inode', '镜像内路径'], [175, 150, 120, 100, 100], '搜索时间、事件、路径、状态或分区')

    def columns(self, r):
        return [display_time(r['time'], compact=True), r['event'], r['status'], str(r['offset']), str(r['inode']), r['path']]

    def details(self, r):
        return page(r['path'], '文件系统时间 · UTC+8', [('事件详情', list(zip(['时间', '事件', '状态', '分区偏移（扇区）', 'inode', '路径'], self.columns(r))))])


class FindingsPanel(RecordsPanel):
    def __init__(self, parent):
        super().__init__(parent, ['镜像内路径', '状态', '分区偏移', 'inode', '记录数', '最近记录（UTC+8）'], [340, 100, 100, 100, 80], '搜索文件、笔记、摘要、人员或比对结果')
        self.split.setSizes([240, 430])

    def columns(self, items):
        r = items[-1]
        d = r['details']
        return [r['subject'], '已删除' if d['deleted'] else '现存', str(d['offset']), str(d['inode']), str(len(items)), display_time(r['timestamp'], compact=True)]

    def details(self, items):
        first = items[0]
        d = first['details']
        sections = [('证据来源', [('分区偏移（扇区）', d['offset']), ('inode', d['inode']), ('镜像 SHA-256', d['image_sha256'])])]
        for r in reversed(items):
            details = r['details']
            rows = [('时间', display_time(r['timestamp'], compact=True)), ('操作人员', r['actor']), ('结果', r['result'])]
            for key, title in [('note', '笔记'), ('size', '读取字节数'), ('recorded_size', '目录记录字节数'), ('sha256', '读取内容 SHA-256'), ('comparison', '对照文件'), ('comparison_sha256', '对照 SHA-256'), ('source_note', '来源状态'), ('read_note', '读取说明'), ('error', '错误')]:
                if key in details:
                    rows.append((title, details[key]))
            sections.append((f"#{r['seq']} · {OPERATIONS[r['action']]}", rows))
        return page(first['subject'], '取证记录 · 笔记 / 摘要 / 副本比对', sections)


class EvidencePanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        split = QSplitter(Qt.Orientation.Vertical)
        self.summary = QTextBrowser()
        self.summary.setOpenExternalLinks(False)
        split.addWidget(self.summary)
        raw = QWidget()
        raw_layout = QVBoxLayout(raw)
        raw_layout.setContentsMargins(0, 6, 0, 0)
        raw_layout.addWidget(QLabel('分区布局与文件系统 · 原始解析结果'))
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        raw_layout.addWidget(self.text)
        split.addWidget(raw)
        split.setSizes([400, 300])
        layout.addWidget(split)

    def set_text(self, data):
        evidence = data.get('evidence') if data else None
        if not evidence:
            self.summary.setHtml(page('镜像与文件系统', '加载 RAW 镜像后查看证据摘要、分区状态与解析结果。', []))
            self.text.clear()
            return
        scans = {s['offset']: s for s in data.get('partition_scans', [])}
        sections = [('证据固定', [('镜像路径', evidence['path']), ('大小', f"{evidence['size']:,} 字节"), ('固定时间（UTC+8）', display_time(evidence['fixed_at'], compact=True)), ('SHA-256', evidence['sha256'])])]
        rows = []
        for p in evidence['partitions']:
            scan = scans.get(p['offset'], {})
            state = f"已读取 {scan.get('count', 0)} 项" if scan.get('status') == 'ready' else scan.get('error', '待读取')
            rows.append((f"偏移 {p['offset']} 扇区", p['description'] + ' · ' + state))
        sections.append(('分区概览', rows))
        self.summary.setHtml(page('镜像与文件系统', f"{len(rows)} 个分区 · {len(data.get('inventory', []))} 个条目 · 应用层只读", sections))
        self.text.setPlainText(evidence.get('layout', '') + '\n\n' + data.get('fsstat', ''))
