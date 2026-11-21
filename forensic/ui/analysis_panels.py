"""可搜索分析列表与分层证据详情。"""
from html import escape
import re

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QSplitter, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from ..core.coverage import SOURCE_FIELDS, coverage_text, source_status
from ..core.findings import OPERATIONS, audit_origin_label
from ..core.formatting import display_time
from . import theme
from .delegates import ForensicItemDelegate
from .filter_header import FilterHeaderView
from .icons import ui_icon
from .metrics import CONTROL_GAP, PANEL_GAP, ROW_HEIGHT_TABLE
from .pagination import PageLabel

_HEX_DIGEST_RE = re.compile(r'^[0-9a-fA-F]{32,128}$')
_WINDOWS_PATH_RE = re.compile(r'^[A-Za-z]:[\\/]')
_MUTED_VALUES = frozenset({'—', '未登记', '未记录'})
_PILL_KEYS = frozenset({'结果', '状态', '操作来源', '交付方摘要比对', '事件', '操作时的完整性状态'})
_MONO_KEY_TOKENS = (
    'SHA-256', '哈希', '路径', '偏移', 'inode', '代码', '字节', '大小',
    '时间', '对照文件', '实测摘要', '分段数',
)


def _format_dossier_value(key, value):
    raw = '' if value is None else str(value)
    stripped = raw.strip()
    escaped = escape(raw).replace('\n', '<br>')
    if not stripped:
        return '<span class="muted">—</span>'
    if stripped in _MUTED_VALUES:
        return f'<span class="muted">{escaped}</span>'

    key_str = str(key)
    if key_str == '交付方摘要比对':
        if '不一致' in stripped:
            return f'<span class="pill-danger">{escaped}</span>'
        if '一致' in stripped:
            return f'<span class="pill-ok">{escaped}</span>'
        if '待固定' in stripped:
            return f'<span class="pill-warn">{escaped}</span>'
        return f'<span class="muted">{escaped}</span>'

    if key_str in _PILL_KEYS or stripped in (
        '成功', '失败', '已取消', '部分导出', '现存', '已删除', '已删除·重分配',
        'MCP', '人工', '一致', '不一致', '通过', '校验通过', '校验失败',
        '待固定', '记录时待固定',
    ):
        pill = theme.semantic_pill(stripped)
        if pill is not None:
            cls = {
                theme.PILL_OK: 'pill-ok',
                theme.PILL_DANGER: 'pill-danger',
                theme.PILL_WARN: 'pill-warn',
                theme.PILL_SYSTEM: 'pill-system',
            }.get(pill)
            if cls:
                return f'<span class="{cls}">{escaped}</span>'

    is_mono = (
        bool(_HEX_DIGEST_RE.match(stripped))
        or stripped.startswith('/')
        or bool(_WINDOWS_PATH_RE.match(stripped))
        or ('\\' in stripped and ' ' not in stripped)
        or (any(token in key_str for token in _MONO_KEY_TOKENS) and '\n' not in stripped)
    )
    if is_mono:
        return f'<span class="mono">{escaped}</span>'
    return escaped


def page(title, subtitle, sections):
    parts = [
        f'<html><head><style>{theme.DOSSIER_CSS}</style></head><body>',
        f'<h2>{escape(str(title))}</h2>',
        f'<p class="subtitle">{escape(str(subtitle))}</p>',
    ]
    if sections:
        parts.append('<hr>')
    for name, rows in sections:
        parts.append(f'<h3>{escape(str(name))}</h3>')
        parts.append('<table width="100%" cellspacing="0" cellpadding="0">')
        for k, v in rows:
            parts.append(
                f'<tr><td class="key">{escape(str(k))}</td>'
                f'<td class="val">{_format_dossier_value(k, v)}</td></tr>'
            )
        parts.append('</table>')
    parts.append('</body></html>')
    return ''.join(parts)


class RecordsPanel(QWidget):
    def __init__(self, parent, headers, widths, placeholder, *, filter_columns=(), sort_columns=()):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.top_bar = QFrame(self)
        self.top_bar.setObjectName('panelTopBar')
        self.top_layout = QHBoxLayout(self.top_bar)
        self.top_layout.setContentsMargins(14, 8, 14, 8)
        self.top_layout.setSpacing(CONTROL_GAP)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        self.status.setProperty('role', 'section')
        self.top_layout.addWidget(self.status, 1)
        layout.addWidget(self.top_bar)

        self.search_bar = QFrame(self)
        self.search_bar.setObjectName('panelSubBar')
        search_layout = QHBoxLayout(self.search_bar)
        search_layout.setContentsMargins(14, 7, 14, 7)
        search_layout.setSpacing(CONTROL_GAP)
        self.search = QLineEdit()
        self.search.setPlaceholderText(placeholder)
        self.search.setClearButtonEnabled(True)
        self.search.addAction(
            ui_icon('search', color=theme.TEXT_MUTED, size=14),
            QLineEdit.ActionPosition.LeadingPosition,
        )
        search_layout.addWidget(self.search, 1)
        layout.addWidget(self.search_bar)

        split = QSplitter(Qt.Orientation.Vertical)
        split.setHandleWidth(PANEL_GAP)
        self.split = split
        self.table = QTreeWidget()
        self.table.setProperty('flush', True)
        self.table.setRootIsDecorated(False)
        self.table.setAlternatingRowColors(True)
        self.table.setUniformRowHeights(True)
        if filter_columns or sort_columns:
            self.header = FilterHeaderView(self.table, filter_columns=filter_columns, sort_columns=sort_columns)
            self.table.setHeader(self.header)
            if sort_columns:
                self.header.setSortIndicatorShown(True)
            self.header.filter_changed.connect(self._on_header_filter)
        else:
            self.header = self.table.header()
            self.header.setObjectName('recordHeader')
        self.table.setHeaderLabels(headers)
        self.table.setHorizontalScrollMode(QTreeWidget.ScrollMode.ScrollPerPixel)
        for i, width in enumerate(widths):
            self.table.setColumnWidth(i, width)
        self.text = QTextBrowser()
        self.text.setProperty('flush', True)
        self.text.setOpenExternalLinks(False)
        self.text.document().setDocumentMargin(14)
        split.addWidget(self.table)
        split.addWidget(self.text)
        split.setSizes([430, 240])
        layout.addWidget(split, 1)
        self.records = []
        self.text.hide()
        self.search.textChanged.connect(self._populate)
        self.table.currentItemChanged.connect(self._detail)
        self.table.itemDoubleClicked.connect(self._open_detail)

    def _on_header_filter(self, column, value):
        self._populate()

    def _refresh_filter_options(self):
        if not isinstance(self.header, FilterHeaderView) or not self.header.filter_columns():
            return
        buckets = {column: set() for column in self.header.filter_columns()}
        for record in self.records:
            cols = self.columns(record)
            for column, seen in buckets.items():
                if column < len(cols) and cols[column] != '':
                    seen.add(cols[column])
        for column, seen in buckets.items():
            values = sorted(seen, key=lambda v: (0, int(v)) if v.isdigit() else (1, v))
            self.header.set_filter_options(column, values)

    def set_text(self, result):
        status, self.records = result
        self.status.setText(status)
        self._refresh_filter_options()
        self._populate()

    def _populate(self):
        current = self.table.currentItem()
        selected = current.data(0, Qt.ItemDataRole.UserRole) if current else None
        self.table.clear()
        self.text.clear()
        query = self.search.text().strip().casefold()
        for record in self.page_records(query):
            columns = self.columns(record)
            item = QTreeWidgetItem(self.table, columns)
            item.setData(0, Qt.ItemDataRole.UserRole, record)
            self.style_item(item, record)
            if record == selected:
                self.table.setCurrentItem(item)
        if not self.table.topLevelItemCount():
            self.text.hide()
        elif self.table.currentItem() is None and not self.text.isHidden():
            self.text.setHtml(page('选择一条记录查看详情', f'当前显示 {self.table.topLevelItemCount()} 条', []))

    def style_item(self, item, record):
        """子类可覆盖以自定义单行单元格样式。"""

    def page_records(self, query):
        filters = self.header.active_filters() if isinstance(self.header, FilterHeaderView) else {}
        if not query and not filters:
            return self.records
        matched = []
        for record in self.records:
            cols = self.columns(record)
            if any(cols[column] != value for column, value in filters.items()):
                continue
            if query and query not in (' '.join(cols) + ' ' + str(record)).casefold():
                continue
            matched.append(record)
        return matched

    def _detail(self, item, previous):
        if item is None:
            self.text.clear()
        elif not self.text.isHidden():
            self.text.setHtml(self.details(item.data(0, Qt.ItemDataRole.UserRole)))

    def _open_detail(self, item, column):
        needs_space = self.text.isHidden() or self.split.sizes()[1] == 0
        self.text.show()
        self._detail(item, None)
        if needs_space:
            height = max(200, self.split.height())
            self.split.setSizes([height * 2 // 3, height // 3])


class TimelinePanel(RecordsPanel):
    def __init__(self, parent):
        super().__init__(parent, ['序号', '时间（UTC+8）', '事件', '状态', '分区偏移', 'inode', '镜像内路径'],
                         [78, 178, 148, 128, 115, 100], '搜索时间、事件、路径、状态或分区',
                         filter_columns=(2, 3, 4), sort_columns=(0, 1))
        self.table.setItemDelegate(ForensicItemDelegate(
            self.table,
            pill_columns={2, 3},
            mono_columns={0, 1, 4, 5},
            accent_column=0,
            row_height=ROW_HEIGHT_TABLE,
        ))
        self.search.textChanged.disconnect(self._populate)
        self.search.setPlaceholderText('输入时间、事件、路径、状态或分区，按回车搜索')
        self.search.returnPressed.connect(self._search)
        self.status.setObjectName('timelineStatus')
        self.status.setWordWrap(False)
        self.build = QPushButton('生成时间线')
        self.build.setProperty('role', 'soft')
        self.back = QPushButton('上一页')
        self.forward = QPushButton('下一页')
        for button in (self.back, self.forward):
            button.setProperty('role', 'pager')
        self.page_label = PageLabel(self._jump)
        self.page_label.setProperty('role', 'pageBadge')
        for widget in (self.build, self.back, self.page_label, self.forward):
            self.top_layout.addWidget(widget)
        self.build.clicked.connect(lambda: self._start(self.set_text))
        self.back.clicked.connect(lambda: self._move(-1))
        self.forward.clicked.connect(lambda: self._move(1))
        self._matches = []
        self._offset = 0
        self._descending = False
        self._sort_column = 0
        self.header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        self.header.sort_requested.connect(self._toggle_sort)
        for column in (0, 1):
            self.table.headerItem().setToolTip(column, '单击切换正序/倒序')
        for column in (2, 3, 4):
            self.table.headerItem().setToolTip(column, '单击下拉筛选')

    def _toggle_sort(self, column):
        if column not in (0, 1):
            return
        self._descending = not self._descending
        self._sort_column = column
        order = Qt.SortOrder.DescendingOrder if self._descending else Qt.SortOrder.AscendingOrder
        self.header.setSortIndicator(column, order)
        self._offset = 0
        self._populate()

    def _refresh_filter_options(self):
        if hasattr(self.records, 'filter_options'):
            events, statuses, offsets = self.records.filter_options()
        else:
            events = sorted({r['event'] for r in self.records})
            statuses = sorted({r['status'] for r in self.records})
            offsets = [str(o) for o in sorted({r['offset'] for r in self.records})]
        self.header.set_filter_options(2, events)
        self.header.set_filter_options(3, statuses)
        self.header.set_filter_options(4, offsets)

    def _on_header_filter(self, column, value):
        self._search()

    def set_text(self, result):
        self._start = result if callable(result) else None
        self.build.setVisible(self._start is not None)
        self.search.clear()
        self.header.clear_filters(emit=False)
        self._offset = 0
        self._descending = False
        self._sort_column = 0
        self.header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        if self._start:
            result = ('大清单 · 点击生成时间线，在后台整理事件。', [])
        hint, records, *task = result
        self._search_task = task[0] if task else None
        self._matches = range(len(records)) if self._search_task else records
        self.status.setToolTip(hint)
        self._numbers = {} if self._search_task else {id(row): n for n, row in enumerate(records, 1)}
        self._current_number = '—'
        super().set_text((hint, records))

    @staticmethod
    def _row_matches(row, query, filters):
        if filters:
            if 2 in filters and row['event'] != filters[2]:
                return False
            if 3 in filters and row['status'] != filters[3]:
                return False
            if 4 in filters and str(row['offset']) != filters[4]:
                return False
        if not query:
            return True
        return query in str(row).casefold() or query in str(row['time']).replace('T', ' ').casefold()

    def _search(self):
        query = self.search.text().strip().casefold()
        filters = self.header.active_filters()
        if self._search_task:
            records = self.records
            if query or filters:
                if hasattr(records, 'matching'):
                    self._search_task('筛选时间线', lambda: records.matching(query, filters), self._set_matches)
                else:
                    self._search_task('筛选时间线',
                                      lambda: [i for i, r in enumerate(records) if self._row_matches(r, query, filters)],
                                      self._set_matches)
            else:
                self._set_matches(range(len(records)))
            return
        self._matches = ([r for r in self.records if self._row_matches(r, query, filters)]
                         if (query or filters) else self.records)
        self._offset = 0
        self._populate()

    def _set_matches(self, positions):
        self._matches = positions
        self._offset = 0
        self._populate()

    def _move(self, pages):
        self._jump(self._offset // 100 + pages)

    def _jump(self, index):
        self._offset = index * 100
        self._populate()

    def _detail(self, item, previous):
        if item is not None:
            self._update_status(item.text(0))
        super()._detail(item, previous)

    def _update_status(self, number=None):
        if number is not None:
            self._current_number = number
        self.status.setText(f'MAC/B 时间线·UTC+8·当前 {self._current_number}/{len(self.records)}' if self.records else self.status.toolTip())

    def page_records(self, query):
        count = len(self._matches)
        self.page_label.set_pages(self._offset // 100 + 1, (count + 99) // 100)
        self.back.setEnabled(self._offset > 0)
        self.forward.setEnabled(self._offset + 100 < count)
        self._update_status()
        if self._descending:
            end = count - self._offset
            start = max(0, end - 100)
            rows = list(reversed(self._matches[start:end]))
        else:
            rows = self._matches[self._offset:self._offset + 100]
        if self._search_task:
            return [dict(self.records[index], number=index + 1) for index in rows]
        return rows

    def columns(self, r):
        return [str(r['number'] if self._search_task else self._numbers[id(r)]), display_time(r['time'], compact=True), r['event'], r['status'], str(r['offset']), str(r['inode']), r['path']]

    def details(self, r):
        fields = [('时间', display_time(r['time'], compact=True)), ('事件', r['event']), ('状态', r['status']),
                  ('分区偏移（扇区）', r['offset']), ('inode', r['inode']), ('路径', r['path'])]
        return page(r['path'], '文件系统时间 · UTC+8', [('事件详情', fields)])


class FindingsPanel(RecordsPanel):
    def __init__(self, parent):
        super().__init__(parent, ['序号', '镜像内路径', '状态', '分区偏移', 'inode', '记录数', '最近记录（UTC+8）'],
                         [68, 340, 118, 115, 100, 82], '搜索文件、笔记、摘要、人员或比对结果',
                         filter_columns=(2, 3), sort_columns=(0, 6))
        self.table.setItemDelegate(ForensicItemDelegate(
            self.table,
            pill_columns={2},
            mono_columns={0, 3, 4, 5, 6},
            accent_column=0,
            row_height=ROW_HEIGHT_TABLE,
        ))
        self.split.setSizes([240, 430])
        self._export_callback = None
        self._original = []
        self._numbers = {}
        self._descending = False
        self._sort_column = 6
        self.header.setSortIndicator(6, Qt.SortOrder.AscendingOrder)
        self.header.sort_requested.connect(self._toggle_sort)
        self.export_button = QPushButton('一键导出')
        self.export_button.setProperty('role', 'soft')
        self.export_button.setIcon(ui_icon('export', color=theme.ACCENT_SOFT_TEXT, size=14))
        self.export_button.setIconSize(QSize(14, 14))
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_visible)
        self.top_layout.addWidget(self.export_button)
        for column in (0, 6):
            self.table.headerItem().setToolTip(column, '单击切换正序/倒序')
        for column in (2, 3):
            self.table.headerItem().setToolTip(column, '单击下拉筛选')

    def _sorted_records(self):
        if self._sort_column == 6:
            return sorted(self._original,
                          key=lambda items: (display_time(items[-1]['timestamp']), self._numbers[id(items)]),
                          reverse=self._descending)
        return list(reversed(self._original)) if self._descending else list(self._original)

    def _toggle_sort(self, column):
        if column not in (0, 6):
            return
        self._descending = not self._descending
        self._sort_column = column
        order = Qt.SortOrder.DescendingOrder if self._descending else Qt.SortOrder.AscendingOrder
        self.header.setSortIndicator(column, order)
        self.records = self._sorted_records()
        self._populate()

    def set_text(self, result):
        status, records, *extra = result
        self._export_callback = extra[0] if extra else None
        self._original = sorted(
            records,
            key=lambda items: (display_time(items[-1]['timestamp']), items[-1]['seq']),
        )
        self._numbers = {id(items): index for index, items in enumerate(self._original, 1)}
        super().set_text((status, self._sorted_records()))

    def _populate(self):
        super()._populate()
        self.export_button.setEnabled(bool(self._export_callback and self.table.topLevelItemCount()))

    def _export_visible(self):
        if not self._export_callback:
            return
        groups = [self.table.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)
                  for i in range(self.table.topLevelItemCount())]
        self._export_callback(groups)

    def columns(self, items):
        r = items[-1]
        d = r['details']
        return [str(self._numbers.get(id(items), '')), r['subject'], '已删除' if d['deleted'] else '现存',
                str(d['offset']), str(d['inode']), str(len(items)), display_time(r['timestamp'], compact=True)]

    def details(self, items):
        first = items[0]
        d = first['details']
        sections = [('证据来源', [('分区偏移（扇区）', d['offset']), ('inode', d['inode']), ('镜像 SHA-256', d['image_sha256'] or '记录时待固定')])]
        for r in reversed(items):
            details = r['details']
            rows = [('时间', display_time(r['timestamp'], compact=True)),
                    ('操作来源', audit_origin_label(r)), ('操作人员', r['actor']), ('结果', r['result'])]
            for key, title in [('note', '笔记'), ('size', '读取字节数'), ('recorded_size', '目录记录字节数'), ('sha256', '读取内容 SHA-256'), ('comparison', '对照文件'), ('comparison_sha256', '对照 SHA-256'), ('source_note', '来源状态'), ('read_note', '读取说明'), ('source_verification', '操作时的完整性状态'), ('error', '错误')]:
                if key in details:
                    rows.append((title, details[key]))
            sections.append((f"#{r['seq']} · {OPERATIONS[r['action']]}", rows))
        return page(first['subject'], '取证记录 · 笔记 / 摘要 / 副本比对', sections)


class EvidencePanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self._register_source = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        top_bar = QFrame(self)
        top_bar.setObjectName('panelTopBar')
        top = QHBoxLayout(top_bar)
        top.setContentsMargins(14, 8, 14, 8)
        top.setSpacing(CONTROL_GAP)
        header_label = QLabel('镜像摘要与证据来源')
        header_label.setProperty('role', 'section')
        top.addWidget(header_label)
        top.addStretch(1)
        self.source_button = QPushButton('登记证据来源')
        self.source_button.setProperty('role', 'soft')
        self.source_button.setEnabled(False)
        self.source_button.clicked.connect(lambda: self._register_source() if self._register_source else None)
        top.addWidget(self.source_button)
        layout.addWidget(top_bar)

        split = QSplitter(Qt.Orientation.Vertical)
        split.setHandleWidth(PANEL_GAP)
        self.summary = QTextBrowser()
        self.summary.setProperty('flush', True)
        self.summary.setOpenExternalLinks(False)
        self.summary.document().setDocumentMargin(14)
        split.addWidget(self.summary)

        raw = QWidget()
        raw_layout = QVBoxLayout(raw)
        raw_layout.setContentsMargins(0, 0, 0, 0)
        raw_layout.setSpacing(0)
        section_bar = QFrame(raw)
        section_bar.setObjectName('panelSectionBar')
        controls = QHBoxLayout(section_bar)
        controls.setContentsMargins(14, 6, 14, 6)
        controls.setSpacing(CONTROL_GAP)
        section_label = QLabel('分区布局与文件系统 · 原始解析结果')
        section_label.setProperty('role', 'section')
        controls.addWidget(section_label)
        controls.addStretch(1)
        self.partition = QComboBox()
        self.details = QPushButton('导出完整 fsstat')
        self.details.setIcon(ui_icon('export', color=theme.TEXT_SECONDARY, size=14))
        self.details.setIconSize(QSize(14, 14))
        self.details.clicked.connect(lambda: self._export(self.partition.currentData()))
        controls.addWidget(self.partition)
        controls.addWidget(self.details)
        raw_layout.addWidget(section_bar)

        self.text = QPlainTextEdit()
        self.text.setProperty('surface', 'raw')
        self.text.setReadOnly(True)
        self.text.setFont(theme.mono_font(9.5, cjk_fallback=True))
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        raw_layout.addWidget(self.text, 1)
        split.addWidget(raw)
        split.setSizes([400, 300])
        layout.addWidget(split, 1)

    def set_text(self, data):
        evidence = data.get('evidence') if data else None
        self._export = data.get('export_fsstat') if data else None
        self._register_source = data.get('register_source') if data else None
        self.source_button.setEnabled(bool(evidence and self._register_source))
        large = bool(evidence and evidence.get('large_image') and self._export)
        self.details.setVisible(large)
        self.partition.setVisible(large)
        selected = self.partition.currentData()
        self.partition.clear()
        if large:
            for p in evidence['partitions']:
                self.partition.addItem(f"偏移 {p['offset']} 扇区", p['offset'])
            self.partition.setCurrentIndex(max(0, self.partition.findData(selected)))
        if not evidence:
            self.summary.setHtml(page('镜像与文件系统', '加载 RAW 镜像或 E01 首段后查看摘要与覆盖范围。', []))
            self.text.clear()
            return
        scans = {s['offset']: s for s in data.get('partition_scans', [])}
        sections = [('证据固定', [('镜像路径', evidence['path']), ('大小', f"{evidence['size']:,} 字节"), ('固定时间（UTC+8）', display_time(evidence['fixed_at'], compact=True) if evidence['fixed_at'] else '待固定'), ('SHA-256', evidence['sha256'] or '待固定')])]
        rows = []
        if evidence.get('format') == 'EWF':
            sections.append(('EWF 分段镜像', [('分段数', len(evidence['segments'])),
                ('封装总大小（字节）',sum(r['size'] for r in evidence['segments'])),
                ('逻辑介质大小（字节）',evidence['size']), ('校验方式','首次解码整个逻辑磁盘，后续逐段复算封装摘要')]))
        sections.append(('覆盖范围与证据来源', [('范围判断', coverage_text(evidence.get('coverage'))),
            ('交付方摘要比对', source_status(evidence)), *[(title, evidence.get('provenance', {}).get(key, '') or '未登记')
            for key, title in SOURCE_FIELDS.items()]]))
        for p in evidence['partitions']:
            scan = scans.get(p['offset'], {})
            state = f"已读取 {scan.get('count', 0)} 项" if scan.get('status') == 'ready' else scan.get('error', '待读取')
            rows.append((f"偏移 {p['offset']} 扇区", p['description'] + ' · ' + state))
        sections.append(('分区概览', rows))
        self.summary.setHtml(page('镜像与文件系统', f"{len(rows)} 个分区 · {len(data.get('inventory', []))} 个条目 · 应用层只读", sections))
        self.text.setPlainText(evidence.get('layout', '') + '\n\n' + data.get('fsstat', ''))
