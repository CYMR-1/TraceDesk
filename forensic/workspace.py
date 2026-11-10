"""Qt 工作台布局与文件浏览组件；不负责案件读写和取证操作。"""
from PySide6.QtCore import QEvent, QObject, QSignalBlocker, QTimer, Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QFrame, QGridLayout,
                               QHBoxLayout, QHeaderView, QLabel, QLineEdit,
                               QProgressBar, QPushButton, QSizePolicy, QSplitter,
                               QTabWidget, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget)

from .core import display_time
from .preview import FilePreview
from .tsk import entry_name, entry_status
from .views import ReadOnlyTextPanel


class FileBrowserView(QWidget):
    """封装文件树、筛选条件、内容预览和可取消的分批显示。"""

    def __init__(self, parent, appearance, commands):
        super().__init__(parent)
        self.appearance = appearance
        self.entries, self._nodes = {}, {}
        self._items = {}
        self._remaining = iter(())
        self._batch_timer = QTimer(self)
        self._batch_timer.setSingleShot(True)
        self._batch_timer.timeout.connect(self._insert_batch)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 8)
        layout.setSpacing(8)
        controls = QGridLayout()
        controls.setHorizontalSpacing(10)
        controls.setVerticalSpacing(8)
        controls.addWidget(QLabel('分析分区'), 0, 0)
        self.partition = QComboBox()
        self.partition.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.partition.setMinimumContentsLength(15)
        self.partition.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        controls.addWidget(self.partition, 0, 1)
        self.scan_button = QPushButton('读取文件树')
        self.scan_button.setProperty('role', 'accent')
        self.scan_button.clicked.connect(commands['scan'])
        controls.addWidget(self.scan_button, 0, 2)
        controls.setColumnStretch(1, 1)
        layout.addLayout(controls)

        filters = QHBoxLayout()
        filters.setSpacing(10)
        filters.addWidget(QLabel('文件后缀'))
        self.suffix = QLineEdit()
        self.suffix.setPlaceholderText('例如 .txt')
        self.suffix.setMaximumWidth(150)
        self.suffix.returnPressed.connect(commands['filter'])
        filters.addWidget(self.suffix)
        filters.addSpacing(8)
        filters.addWidget(QLabel('路径关键词'))
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText('输入路径中的文字')
        self.keyword.returnPressed.connect(commands['filter'])
        filters.addWidget(self.keyword, 1)
        self.filter_button = QPushButton('筛选')
        self.filter_button.clicked.connect(commands['filter'])
        filters.addWidget(self.filter_button)
        layout.addLayout(filters)

        self.split = QSplitter(Qt.Orientation.Vertical)
        self.split.setChildrenCollapsible(False)
        self.split.setHandleWidth(7)
        layout.addWidget(self.split, 1)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(7)
        self.tree.setHeaderLabels(['镜像内路径 / 文件目录', '状态', '字节数', 'inode',
                                   'M 内容修改 (UTC+8)', 'A 访问 (UTC+8)', 'C 元数据变更 (UTC+8)'])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.tree.setMinimumHeight(105)
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setMinimumSectionSize(80)
        for column, width in enumerate((290, 130, 120, 120, 195, 195, 205)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
            self.tree.setColumnWidth(column, width)
        for column in (2, 3):
            self.tree.headerItem().setTextAlignment(column, Qt.AlignmentFlag.AlignCenter)
        self.tree.itemSelectionChanged.connect(commands['select'])
        self.split.addWidget(self.tree)
        self.preview = FilePreview(self.split)
        self.preview.setMinimumHeight(135)
        self.split.addWidget(self.preview)
        self.split.setStretchFactor(0, 3)
        self.split.setStretchFactor(1, 2)
        self.split.setSizes([330, 230])
        self.detail = QLabel('选择文件可预览、导出副本。拖动中间分隔条可调整预览区域。')
        self.detail.setProperty('role', 'muted')
        self.detail.setWordWrap(True)
        self.detail.setTextFormat(Qt.TextFormat.PlainText)
        self.detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.detail)
        self.detail_label = self.detail

    def display(self, entries):
        self.cancel_display()
        self.preview.clear()
        with QSignalBlocker(self.tree):
            self.tree.clear()
        self.entries, self._nodes = {}, {}
        self._items = {}
        ordered = sorted(entries, key=lambda e: (e['path'].count('/'), e['mode'].lower().startswith('v/'),
                                                 not e['directory'], e['path'], e.get('deleted', False)))
        self._remaining = iter(ordered)
        self._insert_batch()
        self.detail.setText(f'当前显示 {len(ordered)} 项。M：内容修改，A：访问，C：元数据变更；时间为东八区（UTC+8）。')

    def _parent_node(self, path):
        if not path or path == '.':
            return self.tree.invisibleRootItem()
        if path not in self._nodes:
            parent, _, name = path.rpartition('/')
            item = QTreeWidgetItem(self._parent_node(parent), [name])
            item.setExpanded(True)
            self._nodes[path] = item
        return self._nodes[path]

    def _insert_entry(self, entry):
        path = entry['path'].rstrip('/')
        dates = [display_time(entry[key], compact=True) for key in ('mtime', 'atime', 'ctime')]
        item = QTreeWidgetItem(self._parent_node(path.rpartition('/')[0]),
                               [entry_name(entry) or '/', entry_status(entry), str(entry['size']),
                                str(entry['inode'] or '—'), *dates])
        item.setData(0, Qt.ItemDataRole.UserRole, entry)
        item.setToolTip(0, entry['path'])
        item.setExpanded(True)
        for column in (2, 3):
            item.setTextAlignment(column, Qt.AlignmentFlag.AlignCenter)
        if entry.get('deleted'):
            for column in range(7):
                item.setForeground(column, QBrush(QColor(self.appearance.DELETED)))
        # 同名删除项分别保留 inode；路径仅用于父目录定位。
        if entry['directory']:
            self._nodes.setdefault(path, item)
        self.entries[id(item)] = entry
        self._items[id(item)] = item

    def _insert_batch(self):
        self.tree.setUpdatesEnabled(False)
        try:
            for _ in range(200):
                entry = next(self._remaining, None)
                if entry is None:
                    return
                self._insert_entry(entry)
            self._batch_timer.start(1)
        finally:
            self.tree.setUpdatesEnabled(True)

    def cancel_display(self):
        self._batch_timer.stop()
        self._remaining = iter(())

    def set_busy(self, busy):
        for button in (self.scan_button, self.filter_button):
            button.setEnabled(not busy)
        for field in (self.partition, self.suffix, self.keyword):
            field.setEnabled(not busy)


class WorkbenchView(QObject):
    """主窗口布局；控制器注入命令，组件之间不调用案件逻辑。"""

    def __init__(self, root, appearance, commands):
        super().__init__(root)
        self.root, self.appearance = root, appearance
        self._toolbar_columns = None
        root.setWindowTitle('TraceDesk · 电子数据取证工作台')
        appearance.fit_window()
        self.central = QWidget()
        self.central.setObjectName('workbench')
        root.setCentralWidget(self.central)
        layout = QVBoxLayout(self.central)
        layout.setContentsMargins(24, 16, 24, 10)
        layout.setSpacing(12)

        self.header = QWidget()
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(24)
        self.title_label = QLabel('TraceDesk  取证工作台')
        self.title_label.setProperty('role', 'title')
        title_font = QFont(root.font())
        title_font.setPointSize(20)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        header_layout.addWidget(self.title_label)
        self.subtitle_label = QLabel('RAW 镜像分析   /   SHA-256 证据固定   /   全流程审计')
        self.subtitle_label.setProperty('role', 'muted')
        self.subtitle_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        header_layout.addWidget(self.subtitle_label)
        header_layout.addStretch(1)
        self.header.installEventFilter(self)
        layout.addWidget(self.header)

        self.toolbar = QWidget()
        self.toolbar.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.toolbar_layout = QGridLayout(self.toolbar)
        self.toolbar_layout.setContentsMargins(0, 0, 0, 0)
        self.toolbar_layout.setHorizontalSpacing(8)
        self.toolbar_layout.setVerticalSpacing(6)
        self.buttons = []
        for index, (label, key) in enumerate([('新建案件', 'new_case'), ('打开案件', 'open_case'),
                                             ('加载 RAW 镜像', 'load'), ('校验完整性', 'verify'),
                                             ('导出所选文件', 'export'), ('生成 Markdown 报告', 'report')]):
            button = QPushButton(label)
            if index in (0, 2):
                button.setProperty('role', 'accent')
            button.clicked.connect(commands[key])
            self.buttons.append(button)
        self.toolbar.installEventFilter(self)
        layout.addWidget(self.toolbar)
        self._layout_toolbar(root.width() - 48)

        self.card = QFrame()
        self.card.setProperty('role', 'card')
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(14, 10, 14, 10)
        self.summary = QLabel('尚未打开案件。新建案件后加载镜像，或打开已有案件继续分析。')
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        card_layout.addWidget(self.summary)
        layout.addWidget(self.card)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setUsesScrollButtons(True)
        layout.addWidget(self.tabs, 1)
        self.browser = FileBrowserView(self.tabs, appearance, commands)
        self.tabs.addTab(self.browser, '文件浏览')
        self.panels = {}
        for key, title in [('info', '镜像与文件系统'), ('audit', '审计日志'),
                            ('timeview', 'MAC 时间线'), ('help', '操作说明')]:
            panel = ReadOnlyTextPanel(self.tabs)
            self.panels[key] = panel
            self.tabs.addTab(panel, title)

        footer = QHBoxLayout()
        self.status = QLabel('就绪 · 应用层只读模式 · 东八区 UTC+8')
        self.status.setProperty('role', 'muted')
        self.status.setWordWrap(True)
        footer.addWidget(self.status, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(180)
        self.progress.setFixedHeight(7)
        footer.addWidget(self.progress)
        layout.addLayout(footer)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Type.Resize:
            if watched is self.toolbar:
                self._layout_toolbar(event.size().width())
            elif watched is self.header:
                needed = self.title_label.sizeHint().width() + self.subtitle_label.sizeHint().width() + 24
                self.subtitle_label.setVisible(event.size().width() >= needed)
        return super().eventFilter(watched, event)

    def _layout_toolbar(self, width):
        needed = sum(button.sizeHint().width() for button in self.buttons) + 5 * 8
        columns = 6 if width >= needed else 3
        if columns == self._toolbar_columns:
            return
        self._toolbar_columns = columns
        for column in range(6):
            self.toolbar_layout.setColumnStretch(column, 1 if column < columns else 0)
        for button in self.buttons:
            self.toolbar_layout.removeWidget(button)
        for index, button in enumerate(self.buttons):
            self.toolbar_layout.addWidget(button, index // columns, index % columns)

    def set_busy(self, busy):
        for button in self.buttons:
            button.setEnabled(not busy)
        self.browser.set_busy(busy)
        self.progress.setRange(0, 0 if busy else 100)
        if not busy:
            self.progress.setValue(0)
