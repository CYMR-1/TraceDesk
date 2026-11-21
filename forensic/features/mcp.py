"""工作台内 MCP 服务端状态管理与客户端接入配置弹窗。"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..mcp.runtime import (
    DEFAULT_HOST,
    DEFAULT_HTTP_PATH,
    DEFAULT_PORT,
    LocalHttpMcpManager,
    build_cli_command,
    build_http_config,
    build_stdio_config,
    format_config_json,
)
from ..mcp.server import TOOL_CATALOG
from ..ui import theme
from ..ui.delegates import ForensicItemDelegate
from ..ui.icons import ui_icon
from ..ui.metrics import CONTROL_GAP, DIALOG_MARGIN, ROW_HEIGHT_TABLE
from .api import Action, Feature


_MANAGERS: dict[int, LocalHttpMcpManager] = {}


def get_manager(context) -> LocalHttpMcpManager:
    key = id(context.root)
    manager = _MANAGERS.get(key)
    if manager is None:
        manager = LocalHttpMcpManager()
        _MANAGERS[key] = manager
    return manager


def shutdown_mcp(context) -> None:
    manager = _MANAGERS.pop(id(context.root), None)
    if manager is not None:
        manager.stop()


class McpDialog(QDialog):
    """MCP 服务端配置与本地 Streamable HTTP 启停对话框。"""

    def __init__(self, parent, manager: LocalHttpMcpManager, active_case=None, release_case=None):
        super().__init__(parent)
        self.manager = manager
        self.active_case = active_case
        self._release_case = release_case
        self.setWindowTitle('MCP 服务配置 · TraceDesk')
        self.resize(800, 600)

        mono = theme.mono_font(9.5)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        body = QWidget(self)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(DIALOG_MARGIN, 16, DIALOG_MARGIN, 14)
        layout.setSpacing(12)

        # 顶部状态与本地 HTTP 启停卡片
        card = QFrame(body)
        card.setProperty('role', 'card')
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(10)

        header_col = QVBoxLayout()
        header_col.setContentsMargins(0, 0, 0, 0)
        header_col.setSpacing(3)
        title = QLabel('TraceDesk MCP 服务端（tracedesk_mcp）', card)
        title.setObjectName('sectionTitle')
        header_col.addWidget(title)

        meta = QLabel(
            f'提供 {len(TOOL_CATALOG)} 个取证工具与 2 个资源 · 源镜像只读保护 · 受控操作自动写入 SHA-256 审计链',
            card,
        )
        meta.setProperty('role', 'muted')
        meta.setWordWrap(True)
        header_col.addWidget(meta)
        card_layout.addLayout(header_col)

        self.status_label = QLabel(card)
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        card_layout.addWidget(self.status_label)

        self.lock_banner = QFrame(card)
        self.lock_banner.setObjectName('mcpLockBanner')
        self.lock_banner.setProperty('bannerState', 'warning')
        lock_layout = QHBoxLayout(self.lock_banner)
        lock_layout.setContentsMargins(12, 8, 12, 8)
        lock_layout.setSpacing(10)
        lock_icon = QLabel(self.lock_banner)
        lock_icon.setFixedSize(16, 16)
        lock_icon.setPixmap(ui_icon('warning', theme.WARN_FG, 16).pixmap(16, 16))
        lock_layout.addWidget(lock_icon, 0, Qt.AlignmentFlag.AlignVCenter)
        self.lock_label = QLabel(self.lock_banner)
        self.lock_label.setWordWrap(True)
        lock_layout.addWidget(self.lock_label, 1)
        self.release_case_button = QPushButton('释放当前案件锁', self.lock_banner)
        self.release_case_button.setIcon(ui_icon('lock_open', theme.WARN_FG, 14))
        self.release_case_button.setProperty('role', 'warningAction')
        self.release_case_button.clicked.connect(self._on_release_case)
        lock_layout.addWidget(self.release_case_button)
        card_layout.addWidget(self.lock_banner)
        self._refresh_lock_banner()

        controls = QHBoxLayout()
        controls.setSpacing(CONTROL_GAP)
        controls.addWidget(QLabel('监听地址：127.0.0.1（仅本机回环）', card))
        port_label = QLabel('端口：', card)
        self.port_spin = QSpinBox(card)
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(manager.port if manager.running else DEFAULT_PORT)
        self.port_spin.setMinimumWidth(92)
        self.port_spin.setFont(mono)
        port_label.setBuddy(self.port_spin)
        controls.addWidget(port_label)
        controls.addWidget(self.port_spin)
        controls.addStretch(1)

        self.toggle_button = QPushButton(card)
        self.toggle_button.clicked.connect(self._toggle_http_server)
        controls.addWidget(self.toggle_button)
        card_layout.addLayout(controls)

        layout.addWidget(card)

        # 配置与工具清单标签页
        self.tabs = QTabWidget(body)

        # Tab 1: stdio 配置
        stdio_tab = QWidget()
        stdio_layout = QVBoxLayout(stdio_tab)
        stdio_layout.setContentsMargins(12, 10, 12, 10)
        stdio_layout.setSpacing(CONTROL_GAP)
        stdio_hint = QLabel(
            '推荐用于 Claude Desktop、Cursor、Antigravity 等本地 MCP 客户端：'
            '客户端按需以子进程方式拉起，无需常驻网络端口。'
        )
        stdio_hint.setProperty('role', 'muted')
        stdio_hint.setWordWrap(True)
        stdio_layout.addWidget(stdio_hint)

        self.stdio_edit = QPlainTextEdit()
        self.stdio_edit.setReadOnly(True)
        self.stdio_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.stdio_edit.setProperty('surface', 'code')
        self.stdio_edit.setFont(mono)
        self.stdio_edit.setPlainText(format_config_json(build_stdio_config(cases_root=manager.cases_root)))
        stdio_layout.addWidget(self.stdio_edit, 1)

        stdio_actions = QHBoxLayout()
        stdio_actions.setSpacing(CONTROL_GAP)
        self.copy_stdio_json_btn = QPushButton('复制配置 JSON')
        self.copy_stdio_json_btn.setIcon(ui_icon('copy', theme.ACCENT_SOFT_TEXT, 14))
        self.copy_stdio_json_btn.setProperty('role', 'soft')
        self.copy_stdio_json_btn.clicked.connect(
            lambda: self._copy_text(self.stdio_edit.toPlainText(), '已复制 stdio 配置 JSON')
        )
        self.copy_stdio_cmd_btn = QPushButton('复制启动命令')
        self.copy_stdio_cmd_btn.clicked.connect(
            lambda: self._copy_text(build_cli_command(transport='stdio'), '已复制 stdio 启动命令')
        )
        stdio_actions.addWidget(self.copy_stdio_json_btn)
        stdio_actions.addWidget(self.copy_stdio_cmd_btn)
        stdio_actions.addStretch(1)
        stdio_layout.addLayout(stdio_actions)
        self.tabs.addTab(stdio_tab, 'stdio 接入配置（推荐）')

        # Tab 2: Streamable HTTP 配置
        http_tab = QWidget()
        http_layout = QVBoxLayout(http_tab)
        http_layout.setContentsMargins(12, 10, 12, 10)
        http_layout.setSpacing(CONTROL_GAP)
        http_hint = QLabel(
            '适用于支持 Streamable HTTP 的 MCP 客户端。点击上方“启动本地 HTTP 服务”或通过命令行启动后即可接入，'
            '已启用本机回环限制与 DNS 重绑定防护。'
        )
        http_hint.setProperty('role', 'muted')
        http_hint.setWordWrap(True)
        http_layout.addWidget(http_hint)

        self.http_edit = QPlainTextEdit()
        self.http_edit.setReadOnly(True)
        self.http_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.http_edit.setProperty('surface', 'code')
        self.http_edit.setFont(mono)
        http_layout.addWidget(self.http_edit, 1)

        http_actions = QHBoxLayout()
        http_actions.setSpacing(CONTROL_GAP)
        self.copy_http_json_btn = QPushButton('复制配置 JSON')
        self.copy_http_json_btn.setIcon(ui_icon('copy', theme.ACCENT_SOFT_TEXT, 14))
        self.copy_http_json_btn.setProperty('role', 'soft')
        self.copy_http_json_btn.clicked.connect(
            lambda: self._copy_text(self.http_edit.toPlainText(), '已复制 HTTP 配置 JSON')
        )
        self.copy_http_url_btn = QPushButton('复制服务地址')
        self.copy_http_url_btn.clicked.connect(
            lambda: self._copy_text(self._current_url(), '已复制本地 HTTP 服务地址')
        )
        self.copy_http_cmd_btn = QPushButton('复制命令行启动指令')
        self.copy_http_cmd_btn.clicked.connect(
            lambda: self._copy_text(
                build_cli_command(
                    transport='streamable-http',
                    host=DEFAULT_HOST,
                    port=self.port_spin.value(),
                    path=DEFAULT_HTTP_PATH,
                ),
                '已复制 HTTP 启动命令',
            )
        )
        http_actions.addWidget(self.copy_http_json_btn)
        http_actions.addWidget(self.copy_http_url_btn)
        http_actions.addWidget(self.copy_http_cmd_btn)
        http_actions.addStretch(1)
        http_layout.addLayout(http_actions)
        self.tabs.addTab(http_tab, 'Streamable HTTP 配置')

        # Tab 3: 工具目录
        tools_tab = QWidget()
        tools_layout = QVBoxLayout(tools_tab)
        tools_layout.setContentsMargins(10, 10, 10, 10)
        self.tools_tree = QTreeWidget()
        self.tools_tree.setRootIsDecorated(False)
        self.tools_tree.setAlternatingRowColors(True)
        self.tools_tree.setUniformRowHeights(True)
        self.tools_tree.setItemDelegate(
            ForensicItemDelegate(
                self.tools_tree,
                pill_columns={2},
                mono_columns={0},
                accent_column=0,
                row_height=ROW_HEIGHT_TABLE,
            )
        )
        self.tools_tree.setHeaderLabels(['工具名称', '分类', '模式', '功能说明'])
        for spec in TOOL_CATALOG:
            mode_text = '只读' if spec['read_only'] else '受控写入（记入审计链）'
            item = QTreeWidgetItem([spec['name'], spec['category'], mode_text, spec['summary']])
            item.setToolTip(3, spec['summary'])
            self.tools_tree.addTopLevelItem(item)
        header = self.tools_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tools_layout.addWidget(self.tools_tree)
        self.tabs.addTab(tools_tab, f'可用工具清单（{len(TOOL_CATALOG)}）')

        layout.addWidget(self.tabs, 1)
        outer.addWidget(body, 1)

        footer_bar = QFrame(self)
        footer_bar.setObjectName('dialogFooterBar')
        footer = QHBoxLayout(footer_bar)
        footer.setContentsMargins(DIALOG_MARGIN, 10, DIALOG_MARGIN, 10)
        footer.setSpacing(CONTROL_GAP)
        self.feedback_label = QLabel('', footer_bar)
        self.feedback_label.setProperty('role', 'muted')
        footer.addWidget(self.feedback_label, 1)
        close_btn = QPushButton('关闭', footer_bar)
        close_btn.setAutoDefault(False)
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)
        outer.addWidget(footer_bar)

        self.port_spin.valueChanged.connect(self._refresh_http_config)
        self._refresh_state()

    def _current_url(self) -> str:
        port = self.manager.port if self.manager.running else self.port_spin.value()
        return f'http://{DEFAULT_HOST}:{port}{DEFAULT_HTTP_PATH}'

    def _refresh_http_config(self) -> None:
        port = self.manager.port if self.manager.running else self.port_spin.value()
        self.http_edit.setPlainText(
            format_config_json(build_http_config(host=DEFAULT_HOST, port=port, path=DEFAULT_HTTP_PATH))
        )

    def _refresh_state(self) -> None:
        running = self.manager.running
        self.port_spin.setEnabled(not running)
        if running:
            self.port_spin.setValue(self.manager.port)
            self.status_label.setText(f'本地 HTTP 服务状态：运行中 · {self.manager.url}')
            self.status_label.setProperty('statusState', 'running')
            self.toggle_button.setText('停止本地 HTTP 服务')
            self.toggle_button.setProperty('role', 'soft')
        else:
            self.status_label.setText('本地 HTTP 服务状态：未启动（stdio 模式无需启动端口即可由外部客户端拉起）')
            self.status_label.setProperty('statusState', 'stopped')
            self.toggle_button.setText('启动本地 HTTP 服务')
            self.toggle_button.setProperty('role', 'accent')
        theme.repolish(self.status_label)
        theme.repolish(self.toggle_button)
        self._refresh_http_config()

    def _toggle_http_server(self) -> None:
        try:
            if self.manager.running:
                self.manager.stop()
                self.feedback_label.setText('本地 HTTP MCP 服务已停止')
            else:
                url = self.manager.start(
                    host=DEFAULT_HOST,
                    port=self.port_spin.value(),
                    path=DEFAULT_HTTP_PATH,
                )
                self.feedback_label.setText(f'本地 HTTP MCP 服务已启动：{url}')
        except Exception as error:
            QMessageBox.critical(self, 'MCP 服务操作失败', str(error))
        finally:
            self._refresh_state()

    def _refresh_lock_banner(self) -> None:
        if self.active_case is None:
            self.lock_banner.hide()
            return
        case_number = self.active_case.data.get('number', '')
        self.lock_label.setText(
            f'提示：桌面端当前已打开案件「{case_number}」并持有 case.lock。'
            '外部 MCP 客户端操作同一案件前，可点击右侧按钮一键释放案件锁。'
        )
        self.release_case_button.setVisible(self._release_case is not None)
        self.lock_banner.show()

    def _on_release_case(self) -> None:
        if self.active_case is None or self._release_case is None:
            return
        case_number = self.active_case.data.get('number', '')
        if self._release_case():
            self.active_case = None
            self._refresh_lock_banner()
            self.feedback_label.setText(f'已关闭案件「{case_number}」并释放 case.lock，现在可由外部 MCP 客户端操作')

    def _copy_text(self, text: str, notice: str) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
        self.feedback_label.setText(notice)


def show_mcp_dialog(context):
    def release_active_case() -> bool:
        if context.case() is None:
            return True
        if not context.available(False):
            return False
        context.replace_case(None)
        return True

    dialog = McpDialog(
        context.root,
        get_manager(context),
        active_case=context.case(),
        release_case=release_active_case,
    )
    try:
        dialog.exec()
    finally:
        dialog.deleteLater()


FEATURE = Feature(
    'mcp',
    actions=(Action('mcp', show_mcp_dialog, 'MCP 服务', 'brand', 'pager'),),
    shutdown=shutdown_mcp,
)
