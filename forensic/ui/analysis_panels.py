"""可搜索分析列表与分层证据详情。"""
from html import escape
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QPushButton, QLabel, QLineEdit, QPlainTextEdit, QSplitter, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget
from ..core.formatting import display_time
from ..core.findings import OPERATIONS
from ..core.coverage import coverage_text, source_status, SOURCE_FIELDS
from .filter_header import FilterHeaderView
from .pagination import PageLabel


def page(title, subtitle, sections):
    body = ''.join('<h3>' + escape(name) + '</h3><table width="100%" cellspacing="0" cellpadding="9">' + ''.join(
        '<tr><td width="150" bgcolor="#edf4f1"><b>' + escape(str(k)) + '</b></td><td bgcolor="#f8faf9">' + escape(str(v)).replace('\n', '<br>') + '</td></tr>' for k, v in rows) + '</table>' for name, rows in sections)
    return '<html><head><style>body{color:#24332f;}h2{color:#087f6b;}h3{color:#48635a;}</style></head><body><h2>' + escape(title) + '</h2><p>' + escape(subtitle) + '</p>' + body + '</body></html>'


class RecordsPanel(QWidget):
    def __init__(self, parent, headers, widths, placeholder, *, filter_columns=(), sort_columns=()):
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
        self.text.setOpenExternalLinks(False)
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
            if record == selected:
                self.table.setCurrentItem(item)
        if not self.table.topLevelItemCount():
            self.text.hide()
        elif self.table.currentItem() is None and not self.text.isHidden():
            self.text.setHtml(page('选择一条记录查看详情', f'当前显示 {self.table.topLevelItemCount()} 条', []))

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
                         [78, 175, 155, 125, 115, 100], '搜索时间、事件、路径、状态或分区',
                         filter_columns=(2, 3, 4), sort_columns=(0, 1))
        self.search.textChanged.disconnect(self._populate)
        self.search.setPlaceholderText('输入时间、事件、路径、状态或分区，按回车搜索')
        self.search.returnPressed.connect(self._search)
        controls = QHBoxLayout()
        self.layout().removeWidget(self.status)
        self.status.setObjectName('timelineStatus')
        self.status.setWordWrap(False)
        controls.addWidget(self.status)
        controls.addStretch(1)
        self.build = QPushButton('生成时间线')
        self.back = QPushButton('上一页')
        self.forward = QPushButton('下一页')
        for button in (self.back, self.forward):
            button.setProperty('role', 'pager')
        self.page_label = PageLabel(self._jump)
        for button in (self.build, self.back, self.page_label, self.forward):
            controls.addWidget(button)
        self.layout().insertLayout(0, controls)
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
        super().__init__(parent, ['镜像内路径', '状态', '分区偏移', 'inode', '记录数', '最近记录（UTC+8）'],
                         [340, 115, 115, 100, 80], '搜索文件、笔记、摘要、人员或比对结果',
                         filter_columns=(1, 2))
        self.split.setSizes([240, 430])
        self._export_callback = None
        controls = QHBoxLayout()
        self.layout().removeWidget(self.status)
        controls.addWidget(self.status, 1)
        self.export_button = QPushButton('一键导出')
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_visible)
        controls.addWidget(self.export_button)
        self.layout().insertLayout(0, controls)
        for column in (1, 2):
            self.table.headerItem().setToolTip(column, '单击下拉筛选')

    def set_text(self, result):
        status, records, *extra = result
        self._export_callback = extra[0] if extra else None
        super().set_text((status, records))

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
        return [r['subject'], '已删除' if d['deleted'] else '现存', str(d['offset']), str(d['inode']), str(len(items)), display_time(r['timestamp'], compact=True)]

    def details(self, items):
        first = items[0]
        d = first['details']
        sections = [('证据来源', [('分区偏移（扇区）', d['offset']), ('inode', d['inode']), ('镜像 SHA-256', d['image_sha256'] or '记录时待固定')])]
        for r in reversed(items):
            details = r['details']
            rows = [('时间', display_time(r['timestamp'], compact=True)), ('操作人员', r['actor']), ('结果', r['result'])]
            for key, title in [('note', '笔记'), ('size', '读取字节数'), ('recorded_size', '目录记录字节数'), ('sha256', '读取内容 SHA-256'), ('comparison', '对照文件'), ('comparison_sha256', '对照 SHA-256'), ('source_note', '来源状态'), ('read_note', '读取说明'), ('source_verification', '操作时的完整性状态'), ('error', '错误')]:
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
        controls = QHBoxLayout()
        controls.addWidget(QLabel('分区布局与文件系统 · 原始解析结果'))
        controls.addStretch()
        self.partition = QComboBox()
        self.details = QPushButton('导出完整 fsstat')
        self.details.clicked.connect(lambda: self._export(self.partition.currentData()))
        controls.addWidget(self.partition)
        controls.addWidget(self.details)
        raw_layout.addLayout(controls)
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
        self._export = data.get('export_fsstat') if data else None
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
