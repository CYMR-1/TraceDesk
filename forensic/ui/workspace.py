"""顶部案件工具、模块导航与工作台布局。"""
from PySide6.QtCore import QObject, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QHBoxLayout, QProgressBar, QPushButton,
                               QVBoxLayout, QWidget)

from .browser import FileBrowserView, label
from .tabs import TabbedView
from .views import ReadOnlyTextPanel


class WorkbenchView(QObject):
    def __init__(self, root, appearance, commands):
        super().__init__(root)
        self.root, self.appearance = root, appearance
        root.setWindowTitle('TraceDesk · 电子数据取证工作台')
        appearance.fit_window(width=1440, height=940, min_width=1000, min_height=720)
        self.central = QWidget()
        self.central.setObjectName('workbench')
        root.setCentralWidget(self.central)
        layout = QVBoxLayout(self.central)
        layout.setContentsMargins(16, 12, 16, 8)
        layout.setSpacing(10)
        header = QHBoxLayout()
        header.setSpacing(10)
        brand = label('T')
        brand.setObjectName('brandMark')
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
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
        for title, key in [('新建案件', 'new_case'), ('打开案件', 'open_case'), ('生成 Markdown 报告', 'report')]:
            button = QPushButton(title)
            button.clicked.connect(commands[key])
            self.buttons.append(button)
            header.addWidget(button)
        self.buttons[-1].setProperty('role', 'violet')
        layout.addLayout(header)
        self.summary = label('尚未打开案件。新建案件并加载镜像，或打开已有案件继续分析。', 'muted')
        self.summary.setObjectName('caseSummary')
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        self.tabs = TabbedView()
        self.tabs.tabBar().setObjectName('moduleTabs')
        layout.addWidget(self.tabs, 1)
        self.browser = FileBrowserView(self.tabs, appearance, commands)
        self.tabs.addTab(self.browser, '文件浏览')
        self.image_actions = QWidget(self.tabs)
        actions_layout = QHBoxLayout(self.image_actions)
        actions_layout.setContentsMargins(10, 0, 0, 0)
        actions_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        actions_layout.addWidget(self.browser.load_button)
        actions_layout.addWidget(self.browser.verify_button)
        self.tabs.set_actions(self.image_actions, (self.browser.load_button, self.browser.verify_button))
        self.panels = {}
        for key, title in [('info', '镜像与文件系统'), ('timeview', 'MAC 时间线'),
                            ('audit', '审计日志'), ('help', '操作说明')]:
            panel = ReadOnlyTextPanel(self.tabs)
            self.panels[key] = panel
            self.tabs.addTab(panel, title)
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

    def set_busy(self, busy):
        for button in self.buttons:
            button.setEnabled(not busy)
        self.browser.set_busy(busy)
        self.progress.setRange(0, 0 if busy else 100)
        if not busy:
            self.progress.setValue(0)
