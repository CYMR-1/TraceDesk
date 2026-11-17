"""完整文件树、当前目录列表与内容区；不负责证据读写。"""
from pathlib import Path

from PySide6.QtCore import QSignalBlocker, QTimer, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFrame, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit,
                               QPushButton, QSizePolicy, QSplitter, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core.case import display_time
from .preview import FilePreview
from ..engines.tsk import can_export, entry_name, entry_status


def label(text, role=None):
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if role:
        widget.setProperty('role', role)
    return widget


def outline_icon(kind):
    pixmap = QPixmap(32, 32)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor('#666666'), 2))
    if kind == 'folder':
        painter.drawRoundedRect(3, 9, 26, 19, 3, 3)
        painter.drawLine(4, 9, 4, 5)
        painter.drawLine(4, 5, 14, 5)
        painter.drawLine(14, 5, 19, 9)
    elif kind == 'disk':
        painter.drawRoundedRect(3, 6, 26, 22, 4, 4)
        painter.drawLine(4, 20, 28, 20)
        painter.drawPoint(23, 24)
    else:
        painter.drawRoundedRect(7, 3, 19, 26, 2, 2)
        painter.drawLine(12, 12, 21, 12)
        painter.drawLine(12, 18, 21, 18)
    painter.end()
    return QIcon(pixmap)


class FileBrowserView(QWidget):
    ROW_ROLE = Qt.ItemDataRole.UserRole + 1
    SCOPE_ROLE = Qt.ItemDataRole.UserRole + 2

    def __init__(self, parent, appearance, commands):
        super().__init__(parent)
        self.appearance, self.commands = appearance, commands
        self.entries, self._items, self._nav_items, self._nodes = {}, {}, {}, {}
        self._scope, self._allowed = None, None
        self._remaining = iter(())
        self._total = self._visible_count = 0
        self._busy = False
        self._context = ('尚未加载镜像', '尚未读取分区')
        self._icons = {name: outline_icon(name) for name in ('file', 'folder', 'disk')}
        self._batch_timer = QTimer(self)
        self._batch_timer.setSingleShot(True)
        self._batch_timer.timeout.connect(self._insert_batch)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 8)
        layout.setSpacing(8)
        controls = QHBoxLayout()
        controls.addWidget(label('分析分区'))
        self.partition = QComboBox()
        self.partition.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.partition.setMinimumContentsLength(12)
        self.partition.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        controls.addWidget(self.partition, 1)
        self.scan_button = self._button('读取文件树', commands['scan'])
        self.scan_button.setProperty('role', 'accent')
        self.load_button = self._button('加载 RAW 镜像', commands['load'])
        self.verify_button = self._button('校验完整性', commands['verify'])
        for button in (self.scan_button, self.load_button, self.verify_button):
            controls.addWidget(button)
        layout.addLayout(controls)
        self.horizontal_split = QSplitter(Qt.Orientation.Horizontal)
        self.horizontal_split.setChildrenCollapsible(False)
        self.horizontal_split.setHandleWidth(5)
        layout.addWidget(self.horizontal_split, 1)
        nav_panel = QFrame()
        nav_panel.setObjectName('navigationPanel')
        nav_panel.setMinimumWidth(190)
        nav_layout = QVBoxLayout(nav_panel)
        nav_layout.setContentsMargins(8, 10, 8, 8)
        nav_layout.addWidget(label('数据源 / 完整文件树', 'section'))
        self.navigation = QTreeWidget()
        self.navigation.setObjectName('evidenceTree')
        self.navigation.setHeaderHidden(True)
        self.navigation.setUniformRowHeights(True)
        self.navigation.setIndentation(16)
        self.navigation.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.navigation.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.navigation.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.navigation.header().setStretchLastSection(False)
        self.navigation.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.navigation.itemSelectionChanged.connect(self._navigation_selected)
        nav_buttons = QHBoxLayout()
        self.expand_button = self._button('全部展开', self.navigation.expandAll)
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
        self.split.setHandleWidth(5)
        self.split.setMinimumWidth(500)
        self.horizontal_split.addWidget(self.split)
        self.horizontal_split.setStretchFactor(0, 0)
        self.horizontal_split.setStretchFactor(1, 1)
        self.horizontal_split.setSizes([270, 1000])
        results = QWidget()
        result_layout = QVBoxLayout(results)
        result_layout.setContentsMargins(6, 0, 0, 0)
        result_layout.setSpacing(7)
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
        self.reset_button = self._button('重置', self.reset_filter)
        filters.addWidget(self.filter_button)
        filters.addWidget(self.reset_button)
        result_layout.addLayout(filters)
        self.breadcrumb = label('请选择镜像并读取文件树', 'muted')
        self.breadcrumb.setWordWrap(True)
        result_layout.addWidget(self.breadcrumb)
        self.tree = QTreeWidget()
        self.tree.setObjectName('fileResults')
        self.tree.setRootIsDecorated(False)
        self.tree.setColumnCount(7)
        self.tree.setHeaderLabels(['文件名称 / 镜像内路径', '状态', '字节数', 'inode',
                                   'M 修改 (UTC+8)', 'A 访问 (UTC+8)', 'C 变更 (UTC+8)'])
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.tree.setMinimumHeight(110)
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        for column, width in enumerate((260, 120, 120, 120, 170, 170, 170)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            self.tree.setColumnWidth(column, width)
        for column in (2, 3):
            self.tree.headerItem().setTextAlignment(column, Qt.AlignmentFlag.AlignCenter)
        self.tree.itemSelectionChanged.connect(self._result_selected)
        self.tree.itemDoubleClicked.connect(self._open_directory)
        result_layout.addWidget(self.tree, 1)
        self.result_count = label('0 项', 'muted')
        result_layout.addWidget(self.result_count)
        self.split.addWidget(results)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(6, 2, 0, 0)
        content_layout.setSpacing(6)
        content_header = QHBoxLayout()
        content_header.addWidget(label('内容预览', 'section'))
        content_header.addStretch()
        self.export_button = self._button('导出所选文件', commands['export'])
        content_header.addWidget(self.export_button)
        content_layout.addLayout(content_header)
        self.preview = FilePreview(content)
        self.preview.setMinimumHeight(160)
        content_layout.addWidget(self.preview, 1)
        self.split.addWidget(content)
        self.split.setStretchFactor(0, 3)
        self.split.setStretchFactor(1, 2)
        self.split.setSizes([370, 290])
        self.detail = label('选择目录定位文件；拖动分隔条调整树、列表和内容区域。', 'muted')
        self.detail.setWordWrap(True)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.detail)
        self.detail_label = self.detail
        self.display([])

    @staticmethod
    def _button(text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        return button

    def set_context(self, evidence, offset=None):
        self._context = (Path(evidence['path']).name if evidence else '尚未加载镜像',
                         f'已读取分区 · 偏移 {offset} 扇区' if offset is not None else '尚未读取分区')
        self.image_node.setText(0, self._context[0])
        self.image_node.setToolTip(0, evidence['path'] if evidence else '')
        self.partition_node.setText(0, self._context[1])
        self._update_counts()

    def display(self, entries):
        self.cancel_display()
        self.preview.clear()
        self.detail.setText('选择目录定位文件；拖动分隔条调整树、列表和内容区域。')
        self.export_button.setEnabled(False)
        with QSignalBlocker(self.tree), QSignalBlocker(self.navigation):
            self.tree.clear()
            self.navigation.clear()
            self.image_node = QTreeWidgetItem(self.navigation, [self._context[0]])
            self.image_node.setIcon(0, self._icons['disk'])
            self.partition_node = QTreeWidgetItem(self.image_node, [self._context[1]])
            self.partition_node.setIcon(0, self._icons['disk'])
            self.root_node = QTreeWidgetItem(self.partition_node, ['/ 根目录'])
            self.root_node.setIcon(0, self._icons['folder'])
            self.root_node.setData(0, self.SCOPE_ROLE, '')
            for node in (self.image_node, self.partition_node, self.root_node):
                node.setExpanded(True)
        self.entries, self._items, self._nav_items = {}, {}, {}
        self._nodes = {'': self.root_node}
        self._scope, self._allowed = None, None
        self.suffix.clear()
        self.keyword.clear()
        with QSignalBlocker(self.status_filter):
            self.status_filter.setCurrentIndex(0)
        ordered = sorted(entries, key=lambda e: (e['path'].count('/'), e['mode'].lower().startswith('v/'),
                                                 not e['directory'], e['path'], e.get('deleted', False)))
        self._total, self._visible_count = len(ordered), 0
        self._remaining = iter(ordered)
        self._insert_batch()

    def _parent_node(self, path):
        if not path or path == '.':
            return self.root_node
        if path not in self._nodes:
            parent, _, name = path.rpartition('/')
            node = QTreeWidgetItem(self._parent_node(parent), [name])
            node.setData(0, self.SCOPE_ROLE, path)
            node.setIcon(0, self._icons['folder'])
            node.setExpanded(True)
            self._nodes[path] = node
        return self._nodes[path]

    @staticmethod
    def _path(entry):
        return entry['path'].strip('/')

    def _insert_entry(self, entry):
        path = self._path(entry)
        dates = [display_time(entry[key], compact=True) for key in ('mtime', 'atime', 'ctime')]
        item = QTreeWidgetItem(self.tree, [entry_name(entry) or '/', entry_status(entry),
                                          str(entry['size']), str(entry['inode'] or '—'), *dates])
        key = id(item)
        item.setData(0, Qt.ItemDataRole.UserRole, entry)
        item.setData(0, self.ROW_ROLE, key)
        item.setToolTip(0, entry['path'])
        for column in (2, 3):
            item.setTextAlignment(column, Qt.AlignmentFlag.AlignCenter)
        icon = self._icons['folder' if entry['directory'] else 'file']
        item.setIcon(0, icon)
        nav_name = entry_name(entry) or '/'
        if entry.get('deleted'):
            nav_name += f'  [已删除 · {entry["inode"] or "—"}]'
        node = QTreeWidgetItem(self._parent_node(path.rpartition('/')[0]), [nav_name])
        node.setIcon(0, icon)
        node.setToolTip(0, f'{entry["path"]}\n{entry_status(entry)} · inode {entry["inode"] or "—"}')
        node.setData(0, self.ROW_ROLE, key)
        if entry['directory']:
            node.setData(0, self.SCOPE_ROLE, path)
            self._nodes.setdefault(path, node)
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
            self.export_button.setEnabled(False)
            self.preview.clear('没有匹配项' if not self._visible_count else '请选择文件')
            self.detail.setText('当前目录没有匹配项，左侧保留完整文件树。' if not self._visible_count
                                else '请选择文件查看内容。')

    def _update_counts(self):
        scope = '全部条目（含子目录）' if self._scope is None else '/' + self._scope
        self.breadcrumb.setText(f'{self._context[0]}  /  {scope}')
        self.result_count.setText(f'当前目录 {self._visible_count} 项 · 完整清单 {self._total} 项 · 时间 UTC+8')
        self.tree_count.setText(f'完整清单 {len(self.entries)} / {self._total} 项\n含目录、删除记录与系统区域')

    def _navigation_selected(self):
        selected = self.navigation.selectedItems()
        if not selected:
            return
        node = selected[0]
        key = node.data(0, self.ROW_ROLE)
        entry = self.entries.get(key)
        if entry is not None and not entry['directory']:
            self._scope = self._path(entry).rpartition('/')[0]
            self.reset_filter()
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

    def _result_selected(self):
        selected = self.tree.selectedItems()
        entry = selected[0].data(0, Qt.ItemDataRole.UserRole) if selected else None
        if entry is None:
            self.export_button.setEnabled(False)
        else:
            node = self._nav_items[selected[0].data(0, self.ROW_ROLE)]
            with QSignalBlocker(self.navigation):
                self.navigation.setCurrentItem(node)
                parent = node.parent()
                while parent is not None:
                    parent.setExpanded(True)
                    parent = parent.parent()
                self.navigation.scrollToItem(node)
            self.export_button.setEnabled(not self._busy and can_export(entry))
        self.commands['select']()

    def _open_directory(self, item, _column):
        entry = item.data(0, Qt.ItemDataRole.UserRole)
        if entry and entry['directory']:
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
        for widget in (self.scan_button, self.filter_button, self.load_button, self.verify_button,
                       self.reset_button, self.partition, self.suffix, self.keyword, self.status_filter,
                       self.navigation, self.tree, self.expand_button, self.collapse_button):
            widget.setEnabled(not busy)
        selected = self.tree.selectedItems()
        entry = selected[0].data(0, Qt.ItemDataRole.UserRole) if selected else None
        self.export_button.setEnabled(not busy and entry is not None and can_export(entry))
