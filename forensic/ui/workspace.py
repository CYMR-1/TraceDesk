"""顶部案件工具、模块导航与工作台布局。"""
from PySide6.QtCore import QObject, QSize, Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QProgressBar, QPushButton, QSizePolicy,
    QVBoxLayout, QWidget,
)

from . import theme
from .branding import brand_pixmap
from .browser import FileBrowserView, label
from .icons import ui_icon
from .metrics import (
    CONTROL_GAP, CUSTODY_BAR_MIN_HEIGHT, HEADER_HEIGHT,
    STATUS_BAR_HEIGHT, WINDOW_MARGIN,
)
from .tabs import TabbedView
from .views import ReadOnlyTextPanel

_ACTION_ICONS = {
    'help': ('help', theme.HEADER_MUTED),
    'mcp': ('mcp', theme.HEADER_MUTED),
    'new_case': ('case_new', theme.HEADER_ICON),
    'open_case': ('case_open', theme.HEADER_ICON),
    'report': ('report', theme.HEADER_ICON),
    'export_bundle': ('bundle', '#FFFFFF'),
    'load': ('import_disk', '#FFFFFF'),
    'verify': ('verify', theme.TEXT_SECONDARY),
}
_DELIVERABLE_KEYS = frozenset(('report', 'export_bundle'))
_CUSTODY_STATES = frozenset(('idle', 'active', 'verified', 'warning', 'error'))


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
        layout.setContentsMargins(WINDOW_MARGIN, WINDOW_MARGIN, WINDOW_MARGIN, WINDOW_MARGIN)
        layout.setSpacing(0)

        # 顶部明净瓷白命令带（48px）
        self.header_bar = QFrame()
        self.header_bar.setObjectName('workbenchHeader')
        self.header_bar.setFixedHeight(HEADER_HEIGHT)
        header = QHBoxLayout(self.header_bar)
        header.setContentsMargins(14, 0, 14, 0)
        header.setSpacing(CONTROL_GAP)

        brand = label('')
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand.setPixmap(brand_pixmap(28, root.devicePixelRatioF()))
        brand.setFixedSize(28, 28)
        header.addWidget(brand)

        self.title_label = label('TraceDesk', 'title')
        self.title_label.setFont(theme.brand_font())
        header.addWidget(self.title_label)
        header.addWidget(self._divider('headerDivider'))
        header.addWidget(label('电子数据取证工作台', 'muted'))

        brand_actions = tuple(features.actions_at('brand'))
        if brand_actions:
            header.addSpacing(4)
        for action in brand_actions:
            button = self._action_button(action, commands, fallback_role='ghost')
            button.setFixedHeight(30)
            header.addWidget(button)

        header.addStretch(1)

        self.buttons = []
        deliverable_divider_added = False
        for action in features.actions_at('header'):
            if self.buttons and not deliverable_divider_added and action.key in _DELIVERABLE_KEYS:
                header.addWidget(self._divider('headerDivider'))
                deliverable_divider_added = True
            button = self._action_button(action, commands)
            button.setFixedHeight(30)
            self.buttons.append(button)
            header.addWidget(button)
        layout.addWidget(self.header_bar)

        # 案件与证据保管状态条（3px 左侧语义指示条）
        self.custody_bar = QFrame()
        self.custody_bar.setObjectName('caseCustodyBar')
        self.custody_bar.setProperty('custodyState', 'idle')
        self.custody_bar.setMinimumHeight(CUSTODY_BAR_MIN_HEIGHT)
        custody_layout = QHBoxLayout(self.custody_bar)
        custody_layout.setContentsMargins(0, 0, 0, 0)
        custody_layout.setSpacing(0)
        self.summary = label('尚未打开案件。新建案件并加载镜像，或打开已有案件继续分析。', 'muted')
        self.summary.setObjectName('caseSummary')
        self.summary.setWordWrap(True)
        self.summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        custody_layout.addWidget(self.summary, 1)
        layout.addWidget(self.custody_bar)

        # 模块导航标签带与工作区
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
            panel = (spec.widget_factory or ReadOnlyTextPanel)(self.tabs)
            self.panels[spec.key] = panel
            self.tabs.addTab(panel, spec.title)

        # 底部只读状态与进度遥测栏（28px）
        self.footer_bar = QFrame()
        self.footer_bar.setObjectName('workbenchFooter')
        self.footer_bar.setFixedHeight(STATUS_BAR_HEIGHT)
        footer = QHBoxLayout(self.footer_bar)
        footer.setContentsMargins(14, 0, 14, 0)
        footer.setSpacing(12)
        self.browser.detail.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        footer.addWidget(self.browser.detail, 1)
        footer.addWidget(self._divider('footerDivider'))
        self.status = label('就绪 · 应用层只读 · 本地处理 · UTC+8', 'muted')
        self.status.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        footer.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedSize(140, 5)
        self.progress.hide()
        footer.addWidget(self.progress)
        layout.addWidget(self.footer_bar)

    @staticmethod
    def _divider(object_name: str) -> QFrame:
        line = QFrame()
        line.setObjectName(object_name)
        line.setFrameShape(QFrame.Shape.NoFrame)
        return line

    def _action_button(self, action, commands, *, fallback_role=None):
        button = QPushButton(action.title)
        button.setProperty('actionKey', action.key)
        role = action.role or fallback_role
        if role:
            button.setProperty('role', role)
        icon_spec = _ACTION_ICONS.get(action.key)
        if icon_spec is not None:
            icon_name, icon_color = icon_spec
            button.setIcon(ui_icon(icon_name, icon_color, 14))
            button.setIconSize(QSize(14, 14))
        button.clicked.connect(lambda checked=False: commands[action.key]())
        self.action_buttons[action.key] = button
        return button

    def set_custody_state(self, state: str) -> None:
        normalized = state if state in _CUSTODY_STATES else 'active'
        if self.custody_bar.property('custodyState') != normalized:
            self.custody_bar.setProperty('custodyState', normalized)
            theme.repolish(self.custody_bar)
            theme.repolish(self.summary)

    def set_busy(self, busy):
        for key, button in self.action_buttons.items():
            if key not in ('help', 'mcp'):
                button.setEnabled(not busy)
        self.browser.set_busy(busy)
        self.progress.setRange(0, 0 if busy else 100)
        self.progress.setVisible(busy)
        if not busy:
            self.progress.setValue(0)
