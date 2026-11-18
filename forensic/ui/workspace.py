"""顶部案件工具、模块导航与工作台布局。"""
from PySide6.QtCore import QObject, QSize, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QHBoxLayout, QProgressBar, QPushButton,
                               QVBoxLayout, QWidget)

from .browser import FileBrowserView, label
from .tabs import TabbedView
from .views import ReadOnlyTextPanel
from .metrics import CONTROL_GAP, SECTION_GAP, WINDOW_MARGIN


class WorkbenchView(QObject):
    def __init__(self, root, appearance, features):
        super().__init__(root)
        self.root, self.appearance = root, appearance
        commands = features.commands
        self.action_buttons = {}
        root.setWindowTitle('TraceDesk · 电子数据取证工作台')
        appearance.fit_window(width=1440, height=940, min_width=1000, min_height=720)
        self.central = QWidget()
        self.central.setObjectName('workbench')
        root.setCentralWidget(self.central)
        layout = QVBoxLayout(self.central)
        layout.setContentsMargins(WINDOW_MARGIN, WINDOW_MARGIN, WINDOW_MARGIN, SECTION_GAP)
        layout.setSpacing(SECTION_GAP)
        header = QHBoxLayout()
        header.setSpacing(CONTROL_GAP)
        brand = label('')
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand.setPixmap(root.windowIcon().pixmap(QSize(38, 38), root.devicePixelRatioF()))
        brand.setFixedSize(38, 38)
        header.addWidget(brand)
        self.title_label = label('TraceDesk', 'title')
        title_font = QFont(root.font())
        title_font.setPointSize(19)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        header.addWidget(self.title_label)
        header.addWidget(label('电子数据取证工作台', 'muted'))
        header.addStretch(1)
        self.buttons = []
        for action in features.actions_at('header'):
            button = self._action_button(action, commands)
            self.buttons.append(button)
            header.addWidget(button)
        layout.addLayout(header)
        self.summary = label('尚未打开案件。新建案件并加载镜像，或打开已有案件继续分析。', 'muted')
        self.summary.setObjectName('caseSummary')
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.tabs = TabbedView()
        self.tabs.tabBar().setObjectName('moduleTabs')
        layout.addWidget(self.tabs, 1)
        self.browser = FileBrowserView(self.tabs, appearance, commands, features.actions_at('preview'),
                                       features.actions_at('file_menu'))
        self.tabs.addTab(self.browser, '文件浏览')
        self.image_actions = QWidget(self.tabs)
        actions_layout = QHBoxLayout(self.image_actions)
        actions_layout.setContentsMargins(CONTROL_GAP, 0, 0, 0)
        actions_layout.setSpacing(CONTROL_GAP)
        actions_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        evidence_buttons = []
        for action in features.actions_at('evidence'):
            button = self._action_button(action, commands)
            evidence_buttons.append(button)
            actions_layout.addWidget(button)
        self.tabs.set_actions(self.image_actions, evidence_buttons)
        # 保留现有脚本的公开控件入口；控件装配和启用状态由工作台统一维护。
        self.browser.load_button = self.action_buttons['load']
        self.browser.verify_button = self.action_buttons['verify']
        self.panels = {}
        for spec in features.panels.values():
            panel = ReadOnlyTextPanel(self.tabs)
            self.panels[spec.key] = panel
            self.tabs.addTab(panel, spec.title)
        footer = QHBoxLayout()
        self.status = label('就绪 · 应用层只读 · 本地处理 · UTC+8', 'muted')
        self.status.setWordWrap(True)
        footer.addWidget(self.status, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedSize(160, 6)
        footer.addWidget(self.progress)
        layout.addLayout(footer)

    def _action_button(self, action, commands):
        button = QPushButton(action.title)
        if action.role:
            button.setProperty('role', action.role)
        button.clicked.connect(lambda checked=False: commands[action.key]())
        self.action_buttons[action.key] = button
        return button

    def set_busy(self, busy):
        for button in self.action_buttons.values():
            button.setEnabled(not busy)
        self.browser.set_busy(busy)
        self.progress.setRange(0, 0 if busy else 100)
        if not busy:
            self.progress.setValue(0)
