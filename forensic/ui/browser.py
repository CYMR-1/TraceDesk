"""完整文件树、当前目录列表与内容区；不负责证据读写。"""
from pathlib import Path
import re

from PySide6.QtCore import QSignalBlocker, QSize, QTimer, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFrame, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMenu,
                               QPushButton, QSplitter, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core.formatting import display_time
from .preview import FilePreview
from ..core.browser_index import prepare
from .pagination import PageLabel
from .icons import entry_icon_kind, outline_icon
from .metrics import CONTROL_GAP, PANEL_GAP, PANEL_PADDING, SECTION_GAP
from ..engines.tsk import entry_name, entry_status


def label(text, role=None):
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if role:
        widget.setProperty('role', role)
    return widget


class FileBrowserView(QWidget):
    PAGE_SIZE = 100
    PAGING_THRESHOLD = 1000
    ROW_ROLE = Qt.ItemDataRole.UserRole + 1
    SCOPE_ROLE = Qt.ItemDataRole.UserRole + 2
    OFFSET_ROLE = Qt.ItemDataRole.UserRole + 3

    def __init__(self, parent, appearance, commands, preview_actions=(), menu_actions=()):
        super().__init__(parent)
        self.appearance, self.commands = appearance, commands
        self.entries, self._items, self._nav_items, self._nodes = {}, {}, {}, {}
        self._scope, self._scope_offset, self._allowed = None, None, None
        self._remaining = iter(())
        self._total = self._visible_count = 0
        self._busy = False
        self._image_name = '尚未加载镜像'
        self._evidence, self._scans = None, {}
        self._filesystems = {}
        self.partition_nodes = {}
        self._icons = {name: outline_icon(name) for name in ('file', 'folder', 'disk', 'image', 'table', 'system')}
        self._batch_timer = QTimer(self)
        self._batch_timer.setSingleShot(True)
        self._batch_timer.timeout.connect(self._insert_batch)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, SECTION_GAP, 0, 0)
        layout.setSpacing(SECTION_GAP)
        self.horizontal_split = QSplitter(Qt.Orientation.Horizontal)
        self.horizontal_split.setChildrenCollapsible(False)
        self.horizontal_split.setHandleWidth(PANEL_GAP)
        layout.addWidget(self.horizontal_split, 1)
        nav_panel = QFrame()
        nav_panel.setObjectName('navigationPanel')
        nav_panel.setMinimumWidth(190)
        nav_layout = QVBoxLayout(nav_panel)
        nav_layout.setContentsMargins(PANEL_PADDING, PANEL_PADDING, PANEL_PADDING, PANEL_PADDING)
        nav_layout.setSpacing(SECTION_GAP)
        nav_layout.addWidget(label('数据源 / 完整文件树', 'section'))
        self.navigation = QTreeWidget()
        self.navigation.setObjectName('evidenceTree')
        self.navigation.setHeaderHidden(True)
        self.navigation.setUniformRowHeights(True)
        self.navigation.setIconSize(QSize(18, 18))
        self.navigation.setIndentation(16)
        self.navigation.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.navigation.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.navigation.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.navigation.header().setStretchLastSection(False)
        self.navigation.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.navigation.itemSelectionChanged.connect(self._navigation_selected)
        self.navigation.itemExpanded.connect(self._expand_branch)
        nav_buttons = QHBoxLayout()
        self.expand_button = self._button('全部展开', self._expand_all)
        self.collapse_button = self._button('全部折叠', self.navigation.collapseAll)
        nav_buttons.addWidget(self.expand_button)
        nav_buttons.addWidget(self.collapse_button)
        nav_layout.addLayout(nav_buttons)
        nav_layout.addWidget(self.navigation, 1)
        self.tree_count = label('尚未读取文件树', 'muted')
        self.tree_count.setWordWrap(True)
        nav_layout.addWidget(self.tree_count)
        self.horizontal_split.addWidget(nav_panel)
        self.split = QSplitter(Qt.Orientation.Vertical)
        self.split.setChildrenCollapsible(False)
        self.split.setHandleWidth(PANEL_GAP)
        self.split.setMinimumWidth(500)
        self.horizontal_split.addWidget(self.split)
        self.horizontal_split.setStretchFactor(0, 0)
        self.horizontal_split.setStretchFactor(1, 1)
        self.horizontal_split.setSizes([270, 1000])
        results = QFrame()
        results.setObjectName('resultsPanel')
        result_layout = QVBoxLayout(results)
        result_layout.setContentsMargins(PANEL_PADDING, PANEL_PADDING, PANEL_PADDING, 1)
        result_layout.setSpacing(SECTION_GAP)
        filters = QHBoxLayout()
        self.suffix = QLineEdit()
        self.suffix.setPlaceholderText('后缀，如 .txt')
        self.suffix.setAccessibleName('文件后缀')
        self.suffix.setMaximumWidth(120)
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText('当前目录内的路径关键词')
        self.keyword.setAccessibleName('路径关键词')
        self.keyword.setClearButtonEnabled(True)
        for field in (self.suffix, self.keyword):
            field.returnPressed.connect(commands['filter'])
        filters.addWidget(self.suffix)
        filters.addWidget(self.keyword, 1)
        self.status_filter = QComboBox()
        self.status_filter.setAccessibleName('文件状态')
        self.status_filter.addItems(['全部状态', '现存文件', '已删除'])
        self.status_filter.currentIndexChanged.connect(self._apply_visibility)
        filters.addWidget(self.status_filter)
        self.filter_button = self._button('筛选', commands['filter'])
        self.filter_button.setProperty('role', 'soft')
        self.reset_button = self._button('重置', self.reset_filter)
        filters.addWidget(self.filter_button)
        filters.addWidget(self.reset_button)
        result_layout.addLayout(filters)
        self.breadcrumb = label('加载镜像后自动展示所有分区', 'muted')
        self.breadcrumb.setObjectName('breadcrumb')
        self.breadcrumb.setWordWrap(True)
        result_layout.addWidget(self.breadcrumb)
        self.tree = QTreeWidget()
        self.tree.setObjectName('fileResults')
        self.tree.setRootIsDecorated(False)
        self.tree.setColumnCount(9)
        self.tree.setHeaderLabels(['文件名称 / 镜像内路径', '状态', '字节数', 'inode',
                                   'M 修改 (UTC+8)', 'A 访问 (UTC+8)', 'C 变更 (UTC+8)', 'B 创建 (UTC+8)', '分区偏移（扇区）'])
        self.tree.headerItem().setToolTip(6, 'C 为元数据变更时间。FAT 不保存此时间；创建时间请查看 B 列。')
        self.tree.setUniformRowHeights(True)
        self.tree.setIconSize(QSize(18, 18))
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.tree.setMinimumHeight(110)
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        for column, width in enumerate((260, 120, 120, 120, 170, 170, 170, 170, 140)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            self.tree.setColumnWidth(column, width)
        for column in (2, 3):
            self.tree.headerItem().setTextAlignment(column, Qt.AlignmentFlag.AlignCenter)
        self.tree.itemSelectionChanged.connect(self._result_selected)
        self.tree.itemDoubleClicked.connect(self._open_directory)
        result_layout.addWidget(self.tree, 1)
        self.result_count = label('0 项', 'muted')
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 0, 0, 0)
        footer.setSpacing(3)
        self.result_count.setObjectName('fileResultCount')
        footer.addWidget(self.result_count, 1)
        self.previous_page = self._button('上一页', lambda: self._show_page(self._page - 1))
        self.next_page = self._button('下一页', lambda: self._show_page(self._page + 1))
        for button in (self.previous_page, self.next_page):
            button.setProperty('role', 'pager')
        footer.addWidget(self.previous_page)
        self.page_label = PageLabel(self._show_page)
        self.page_label.setObjectName('filePageNumber')
        footer.addWidget(self.page_label)
        footer.addWidget(self.next_page)
        result_layout.addLayout(footer)
        self.split.addWidget(results)
        content = QFrame()
        content.setObjectName('previewPanel')
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(PANEL_PADDING, PANEL_PADDING, PANEL_PADDING, PANEL_PADDING)
        content_layout.setSpacing(SECTION_GAP)
        content_header = QHBoxLayout()
        content_header.addWidget(label('内容预览', 'section'))
        content_header.addStretch()
        content_header.setSpacing(CONTROL_GAP)
        self.preview_actions = preview_actions
        self.file_action_buttons = {}
        for action in preview_actions:
            button = self._button(action.title, commands[action.key])
            if action.role:
                button.setProperty('role', action.role)
            self.file_action_buttons[action.key] = button
            content_header.addWidget(button)
        self.export_button = self.file_action_buttons.get('export')
        content_layout.addLayout(content_header)
        self.preview = FilePreview(content)
        self.preview.setMinimumHeight(160)
        content_layout.addWidget(self.preview, 1)
        self.split.addWidget(content)
        self.split.setStretchFactor(0, 3)
        self.split.setStretchFactor(1, 2)
        self.split.setSizes([370, 290])
        self.detail = label('选择目录定位文件；拖动分隔条调整树、列表和内容区域。', 'muted')
        self.detail.setWordWrap(False)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.menu_actions = (*preview_actions, *menu_actions)
        for view in (self.navigation, self.tree):
            view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            view.customContextMenuRequested.connect(lambda pos, view=view: self._file_menu(view, pos))
        self.detail_label = self.detail
        self.display([])

    @staticmethod
    def _button(text, callback):
        button = QPushButton(text)
        button.clicked.connect(lambda checked=False: callback())
        return button

    def _update_file_actions(self, entry=None):
        for action in self.preview_actions:
            enabled = (not self._busy and entry is not None
                       and (action.accepts_entry is None or action.accepts_entry(entry)))
            self.file_action_buttons[action.key].setEnabled(enabled)

    def _file_menu(self, view, pos):
        item = view.itemAt(pos)
        if self._busy or item is None:
            return
        key = item.data(0, self.ROW_ROLE)
        entry = self._inventory_by_id.get(key) if self._paged else self.entries.get(key)
        if entry is None or entry['directory']:
            return
        view.setCurrentItem(item)
        menu = QMenu(self)
        for action in self.menu_actions:
            if action.accepts_entry is None or action.accepts_entry(entry):
                menu.addAction(action.title, lambda checked=False, key=action.key: self.commands[key]())
        if menu.actions():
            menu.exec(view.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def set_context(self, evidence, scans=(), fsstat=''):
        self._evidence = evidence
        self._filesystems = {}
        # 兼容旧案件：从已保存的各分区 fsstat 识别时间能力，无须重扫证据。
        offset = (evidence or {}).get('partitions', [{}])[0].get('offset', 0) if (evidence or {}).get('partitions') else 0
        for line in fsstat.splitlines():
            part = re.match(r'分区偏移 (\d+) 扇区', line)
            kind = re.match(r'File System Type:\s*(\S+)', line)
            if part:
                offset = int(part[1])
            if kind:
                self._filesystems[offset] = kind[1]
        self._scans = {p['offset']: p for p in scans}
        self._image_name = Path(evidence['path']).name if evidence else '尚未加载镜像'
        self.image_node.setText(0, self._image_name)
        self.image_node.setToolTip(0, evidence['path'] if evidence else '')
        for offset in self.partition_nodes:
            self._update_partition(offset)
        self._update_counts()

    def _update_partition(self, offset):
        node = self.partition_nodes[offset]
        scan = self._scans.get(offset)
        state = (f'已读取 {scan["count"]} 项' if scan['status'] == 'ready'
                 else '无法读取') if scan else '待读取'
        index = list(self.partition_nodes).index(offset) + 1
        node.setText(0, f'分区 {index} · 偏移 {offset} · {state}')
        partition = next((p for p in (self._evidence or {}).get('partitions', [])
                          if p['offset'] == offset), {})
        node.setToolTip(0, f'{partition.get("description", "")}\n偏移 {offset} 扇区\n'
                       + (scan.get('error', state) if scan else state))

    def display(self, entries, prepared=None):
        self.cancel_display()
        self.preview.clear()
        self.detail.setText('选择目录定位文件；拖动分隔条调整树、列表和内容区域。')
        self._update_file_actions()
        with QSignalBlocker(self.tree), QSignalBlocker(self.navigation):
            self.tree.clear()
            self.navigation.clear()
            self.image_node = QTreeWidgetItem(self.navigation, [self._image_name])
            self.image_node.setIcon(0, self._icons['disk'])
            self.image_node.setToolTip(0, self._evidence['path'] if self._evidence else '')
            self.image_node.setExpanded(True)
            self.partition_nodes, self._nodes = {}, {}
            offsets = list(dict.fromkeys([p['offset'] for p in (self._evidence or {}).get('partitions', [])]
                                         + (list({key[0] for key in prepared[2]}) if prepared else [e['offset'] for e in entries])))
            for offset in offsets:
                node = QTreeWidgetItem(self.image_node)
                node.setIcon(0, self._icons['disk'])
                node.setData(0, self.OFFSET_ROLE, offset)
                node.setExpanded(True)
                self.partition_nodes[offset] = node
                self._update_partition(offset)
                if self._scans.get(offset, {}).get('status') != 'error':
                    root = QTreeWidgetItem(node, ['/ 根目录'])
                    root.setIcon(0, self._icons['folder'])
                    root.setData(0, self.SCOPE_ROLE, '')
                    root.setData(0, self.OFFSET_ROLE, offset)
                    root.setExpanded(True)
                    self._nodes[(offset, '')] = root
        self.entries, self._items, self._nav_items = {}, {}, {}
        self._scope, self._scope_offset, self._allowed = None, None, None
        self.suffix.clear()
        self.keyword.clear()
        with QSignalBlocker(self.status_filter):
            self.status_filter.setCurrentIndex(0)
        prepared = prepared or (prepare(entries) if len(entries) > self.PAGING_THRESHOLD else None)
        ordered = prepared[0] if prepared else sorted(entries, key=lambda e: (e['offset'], e['path'].count('/'), e['mode'].lower().startswith('v/'),
                                                 not e['directory'], e['path'], e.get('deleted', False)))
        self._total, self._visible_count = len(ordered), 0
        self._paged = self._total > self.PAGING_THRESHOLD
        self.previous_page.setVisible(self._paged)
        self.next_page.setVisible(self._paged)
        self.page_label.setVisible(self._paged)
        self._ordered = ordered if self._paged else []
        self._matching = []
        self._branches, self._inventory_by_id, self._tree_by_id = {}, {}, {}
        self._children = {}
        self._groups, self._entry_groups, self._directory_groups = {}, {}, {}
        if self._paged:
            _, self._branches, self._children, self._inventory_by_id = prepared
            for node in list(self._nodes.values()):
                self._expand_branch(node)
            self._matching = ordered
            self._show_page(0)
            return
        self._remaining = iter(ordered)
        self._insert_batch()

    def _expand_branch(self, node):
        if not getattr(self, '_paged', False):
            return
        offset, scope = node.data(0, self.OFFSET_ROLE), node.data(0, self.SCOPE_ROLE)
        if node in self._groups:
            children = self._groups.pop(node)
        elif self._nodes.get((offset, scope)) is node:
            children = self._branches.pop((offset, scope), ())
        else:
            return
        if len(children) > 2048:
            for start in range(0, len(children), 256):
                group_rows = children[start:start + 256]
                group = QTreeWidgetItem(node, [f'条目 {start + 1}–{start + len(group_rows)}'])
                group.setData(0, self.OFFSET_ROLE, offset)
                group.setData(0, self.SCOPE_ROLE, scope)
                group.setChildIndicatorPolicy(QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator)
                self._groups[group] = group_rows
                for path, row in group_rows:
                    if row:
                        self._entry_groups[id(row)] = group
                    if row is None or row['directory']:
                        self._directory_groups.setdefault((offset,path),group)
            return
        for path, row in children:
            directory = row is None or row['directory']
            name = entry_name(row) if row else path.rpartition('/')[2]
            if row and row.get('deleted'):
                name += f'  [已删除 · {row["inode"] or "—"}]'
            child = QTreeWidgetItem(node, [name or '/'])
            child.setIcon(0, self._icons[entry_icon_kind(row) if row else 'folder'])
            child.setData(0, self.OFFSET_ROLE, offset)
            child.setToolTip(0, path)
            if row:
                child.setData(0, self.ROW_ROLE, id(row))
                self._tree_by_id[id(row)] = child
            if directory:
                child.setData(0, self.SCOPE_ROLE, path)
                owner = self._nodes.setdefault((offset, path), child)
                if owner is child and (offset, path) in self._branches:
                    child.setChildIndicatorPolicy(QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator)

    def _expand_all(self):
        if self._paged:
            pending = list(self._nodes.values())
            while pending:
                node = pending.pop()
                self._expand_branch(node)
                node.setExpanded(True)
                pending.extend(node.child(i) for i in range(node.childCount()) if node.child(i) not in self._groups
                               and node.child(i).data(0, self.SCOPE_ROLE) is not None)
            self.image_node.setExpanded(True)
            for node in self.partition_nodes.values():
                node.setExpanded(True)
            return
        self.navigation.expandAll()

    def _locate_entry(self, entry):
        offset = entry['offset']
        parent = ''
        for part in self._path(entry).split('/')[:-1]:
            self._expand_branch(self._nodes[(offset, parent)])
            parent = f'{parent}/{part}' if parent else part
            if (offset,parent) not in self._nodes:
                self._expand_branch(self._directory_groups[(offset,parent)])
        self._expand_branch(self._nodes[(offset, parent)])
        if id(entry) not in self._tree_by_id:
            self._expand_branch(self._entry_groups[id(entry)])
        return self._tree_by_id[id(entry)]

    def _parent_node(self, offset, path):
        if not path or path == '.':
            return self._nodes[(offset, '')]
        key = (offset, path)
        if key not in self._nodes:
            parent, _, name = path.rpartition('/')
            node = QTreeWidgetItem(self._parent_node(offset, parent), [name])
            node.setData(0, self.SCOPE_ROLE, path)
            node.setData(0, self.OFFSET_ROLE, offset)
            node.setIcon(0, self._icons['folder'])
            node.setExpanded(True)
            self._nodes[key] = node
        return self._nodes[key]

    @staticmethod
    def _path(entry):
        return entry['path'].strip('/')

    def _insert_entry(self, entry):
        path = self._path(entry)
        dates = [display_time(entry.get(key, 0), compact=True) for key in ('mtime', 'atime', 'ctime', 'crtime')]
        filesystem = entry.get('filesystem') or self._filesystems.get(entry['offset'], '')
        if not entry.get('ctime') and filesystem.upper() in ('FAT12', 'FAT16', 'FAT32', 'EXFAT'):
            dates[2] = '不支持（' + filesystem + '）'
        item = QTreeWidgetItem(self.tree, [entry_name(entry) or '/', entry_status(entry),
                                          str(entry['size']), str(entry['inode'] or '—'), *dates, str(entry['offset'])])
        key = id(entry) if self._paged else id(item)
        item.setData(0, Qt.ItemDataRole.UserRole, entry)
        item.setData(0, self.ROW_ROLE, key)
        item.setToolTip(0, f'{entry["path"]}\n分区偏移 {entry["offset"]} 扇区')
        for column in (2, 3):
            item.setTextAlignment(column, Qt.AlignmentFlag.AlignCenter)
        icon = self._icons[entry_icon_kind(entry)]
        item.setIcon(0, icon)
        if entry.get('deleted'):
            item.setForeground(1, QColor(self.appearance.DELETED))
        elif entry['mode'].lower().startswith('v/'):
            item.setForeground(1, QColor('#7352b8'))
        if self._paged:
            self.entries[key], self._items[key] = entry, item
            return
        nav_name = entry_name(entry) or '/'
        if entry.get('deleted'):
            nav_name += f'  [已删除 · {entry["inode"] or "—"}]'
        node = QTreeWidgetItem(self._parent_node(entry['offset'], path.rpartition('/')[0]), [nav_name])
        node.setIcon(0, icon)
        node.setToolTip(0, f'{entry["path"]}\n{entry_status(entry)} · inode {entry["inode"] or "—"}')
        node.setData(0, self.ROW_ROLE, key)
        node.setData(0, self.OFFSET_ROLE, entry['offset'])
        if entry['directory']:
            node.setData(0, self.SCOPE_ROLE, path)
            self._nodes.setdefault((entry['offset'], path), node)
        node.setExpanded(True)
        self.entries[key], self._items[key], self._nav_items[key] = entry, item, node
        visible = self._matches(entry)
        item.setHidden(not visible)
        self._visible_count += int(visible)

    def _insert_batch(self):
        self.tree.setUpdatesEnabled(False)
        self.navigation.setUpdatesEnabled(False)
        try:
            for _ in range(200):
                entry = next(self._remaining, None)
                if entry is None:
                    return
                self._insert_entry(entry)
            self._batch_timer.start(1)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.navigation.setUpdatesEnabled(True)
            self._update_counts()

    def _matches(self, entry):
        if self._scope_offset is not None and entry['offset'] != self._scope_offset:
            return False
        if self._scope is not None and self._path(entry).rpartition('/')[0] != self._scope:
            return False
        if self._allowed is not None and id(entry) not in self._allowed:
            return False
        state = self.status_filter.currentIndex()
        if state == 1:
            return not entry.get('deleted') and not entry['directory'] and not entry['mode'].lower().startswith('v/')
        return state != 2 or bool(entry.get('deleted'))

    def apply_filter(self, entries):
        # Case.filtered 返回原清单记录；筛选不重建左侧树。
        self._allowed = {id(entry) for entry in entries}
        self._apply_visibility()

    def reset_filter(self):
        self._allowed = None
        self.suffix.clear()
        self.keyword.clear()
        with QSignalBlocker(self.status_filter):
            self.status_filter.setCurrentIndex(0)
        self._apply_visibility()

    def _apply_visibility(self, *_):
        if self._paged:
            scoped = self._scope is not None and self._scope_offset is not None
            pool = self._children.get((self._scope_offset, self._scope), []) if scoped else self._ordered
            if self._allowed is None and self.status_filter.currentIndex() == 0 and (scoped or self._scope_offset is None):
                self._matching = pool
            else:
                self._matching = [entry for entry in pool if self._matches(entry)]
            self._show_page(0)
            return
        self._visible_count = 0
        self.tree.setUpdatesEnabled(False)
        try:
            with QSignalBlocker(self.tree):
                for key, entry in self.entries.items():
                    visible = self._matches(entry)
                    self._items[key].setHidden(not visible)
                    self._visible_count += int(visible)
                current = self.tree.currentItem()
                if current is not None and current.isHidden():
                    self.tree.clearSelection()
                    self.tree.setCurrentItem(None)
        finally:
            self.tree.setUpdatesEnabled(True)
        self._update_counts()
        if not self.tree.selectedItems():
            self._update_file_actions()
            self.preview.clear('没有匹配项' if not self._visible_count else '请选择文件')
            self.detail.setText('当前目录没有匹配项，左侧保留完整文件树。' if not self._visible_count
                                else '请选择文件查看内容。')

    def _show_page(self, page):
        self._page = max(0, min(page, (len(self._matching) - 1) // self.PAGE_SIZE))
        start = self._page * self.PAGE_SIZE
        with QSignalBlocker(self.tree), QSignalBlocker(self.navigation):
            self.tree.clear()
            self.entries.clear()
            self._items.clear()
            self._nav_items.clear()
            for entry in self._matching[start:start + self.PAGE_SIZE]:
                self._insert_entry(entry)
        self._visible_count = len(self._matching)
        self.preview.clear('请选择文件' if self._matching else '没有匹配项')
        self.detail.setText('双击目录进入；筛选会搜索当前范围的所有页。')
        self._update_file_actions()
        self._update_counts()
        self.previous_page.setEnabled(self._page > 0)
        self.next_page.setEnabled(start + self.PAGE_SIZE < self._visible_count)

    def _update_counts(self):
        scope = '全部条目（含子目录）' if self._scope is None else '/' + self._scope
        partition = '所有分区' if self._scope_offset is None else f'分区偏移 {self._scope_offset}'
        self.breadcrumb.setText(f'{self._image_name}  /  {partition}  /  {scope}')
        self.result_count.setText(f'当前范围 {self._visible_count} 项 · 完整清单 {self._total} 项 · 时间 UTC+8')
        self.tree_count.setText(f'{len(self.partition_nodes)} 个分区 · 完整清单 {len(self.entries)} / {self._total} 项\n含目录、删除记录与系统区域')
        if self._paged:
            pages = max(1, (self._visible_count + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
            self.page_label.set_pages(self._page + 1, pages)
            self.tree_count.setText(f'{len(self.partition_nodes)} 个分区 · 完整清单 {self._total} 项\n展开目录可查看全部子项')

    def _navigation_selected(self):
        selected = self.navigation.selectedItems()
        if not selected:
            return
        node = selected[0]
        self._scope_offset = node.data(0, self.OFFSET_ROLE)
        key = node.data(0, self.ROW_ROLE)
        entry = self._inventory_by_id.get(key) if self._paged else self.entries.get(key)
        if entry is not None and not entry['directory']:
            self._scope = self._path(entry).rpartition('/')[0]
            self.reset_filter()
            if self._paged and key not in self._items:
                position = next(i for i, row in enumerate(self._matching) if row is entry)
                self._show_page(position // self.PAGE_SIZE)
            self.tree.setCurrentItem(self._items[key])
            self.tree.scrollToItem(self._items[key])
        else:
            self._scope = node.data(0, self.SCOPE_ROLE)
            with QSignalBlocker(self.tree):
                self.tree.clearSelection()
                self.tree.setCurrentItem(None)
            self.reset_filter()
            node.setExpanded(True)
            self.detail.setText('双击右侧目录进入；选择文件查看内容。')
            scan = self._scans.get(self._scope_offset, {})
            if scan.get('status') == 'error':
                message = f'此分区无法读取：{scan["error"]}'
                self.detail.setText(message)
                self.preview.clear(message)

    def _result_selected(self):
        selected = self.tree.selectedItems()
        entry = selected[0].data(0, Qt.ItemDataRole.UserRole) if selected else None
        if entry is None:
            self._update_file_actions()
        else:
            key = selected[0].data(0, self.ROW_ROLE)
            node = self._locate_entry(self.entries[key]) if self._paged else self._nav_items[key]
            with QSignalBlocker(self.navigation):
                self.navigation.setCurrentItem(node)
                parent = node.parent()
                while parent is not None:
                    parent.setExpanded(True)
                    parent = parent.parent()
                self.navigation.scrollToItem(node)
            self._update_file_actions(entry)
        self.commands['select']()

    def _open_directory(self, item, _column):
        entry = item.data(0, Qt.ItemDataRole.UserRole)
        if entry and entry['directory']:
            self._scope_offset = entry['offset']
            self._scope = self._path(entry)
            with QSignalBlocker(self.tree):
                self.tree.clearSelection()
                self.tree.setCurrentItem(None)
            self.reset_filter()

    def cancel_display(self):
        self._batch_timer.stop()
        self._remaining = iter(())

    def set_busy(self, busy):
        self._busy = busy
        for widget in (self.filter_button,
                       self.reset_button, self.suffix, self.keyword, self.status_filter,
                       self.navigation, self.tree, self.expand_button, self.collapse_button):
            widget.setEnabled(not busy)
        selected = self.tree.selectedItems()
        entry = selected[0].data(0, Qt.ItemDataRole.UserRole) if selected else None
        self._update_file_actions(entry)
