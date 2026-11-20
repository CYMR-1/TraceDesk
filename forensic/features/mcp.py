"""工作台内 MCP 服务端状态管理与客户端接入配置弹窗。"""
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
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

    def __init__(self, parent, manager: LocalHttpMcpManager, active_case=None):
        super().__init__(parent)
        self.manager = manager
        self.active_case = active_case
        self.setWindowTitle('MCP 服务配置 · TraceDesk')
        self.resize(780, 580)

        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        if 'Consolas' in set(QFontDatabase.families()):
            mono.setFamily('Consolas')
        mono.setPointSizeF(10)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # 顶部状态与本地 HTTP 启停卡片
        card = QFrame()
        card.setProperty('role', 'card')
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(8)

        title = QLabel('TraceDesk MCP 服务端（tracedesk_mcp）')
        title.setObjectName('sectionTitle')
        card_layout.addWidget(title)

        meta = QLabel(
            f'提供 {len(TOOL_CATALOG)} 个取证工具与 2 个资源 · 源镜像只读保护 · 受控操作自动写入 SHA-256 审计链'
        )
        meta.setProperty('role', 'muted')
        meta.setWordWrap(True)
        card_layout.addWidget(meta)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        card_layout.addWidget(self.status_label)

        if active_case is not None:
            case_number = active_case.data.get('number', '')
            lock_tip = QLabel(
                f'提示：桌面端当前已打开案件「{case_number}」并持有 case.lock。'
                '外部 MCP 客户端需要操作同一案件时，请先在桌面端关闭或切换案件。'
            )
            lock_tip.setWordWrap(True)
            lock_tip.setStyleSheet(
                'background: #f8f4ea; color: #6e5218; border: 1px solid #eadcc0; '
                'border-radius: 6px; padding: 6px 10px;'
            )
            card_layout.addWidget(lock_tip)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        controls.addWidget(QLabel('监听地址：127.0.0.1（仅本机回环）'))
        port_label = QLabel('端口：')
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(manager.port if manager.running else DEFAULT_PORT)
        self.port_spin.setMinimumWidth(88)
        port_label.setBuddy(self.port_spin)
        controls.addWidget(port_label)
        controls.addWidget(self.port_spin)
        controls.addStretch(1)

        self.toggle_button = QPushButton()
        self.toggle_button.clicked.connect(self._toggle_http_server)
        controls.addWidget(self.toggle_button)
        card_layout.addLayout(controls)

        layout.addWidget(card)

        # 配置与工具清单标签页
        self.tabs = QTabWidget()

        # Tab 1: stdio 配置
        stdio_tab = QWidget()
        stdio_layout = QVBoxLayout(stdio_tab)
        stdio_layout.setContentsMargins(10, 10, 10, 10)
        stdio_layout.setSpacing(8)
        stdio_hint = QLabel(
            '推荐用于 Claude Desktop、Cursor、Antigravity 等本地 MCP 客户端：'
            '客户端按需以子进程方式拉起，无需常驻网络端口。'
        )
        stdio_hint.setProperty('role', 'muted')
        stdio_hint.setWordWrap(True)
        stdio_layout.addWidget(stdio_hint)

        self.stdio_edit = QPlainTextEdit()
        self.stdio_edit.setReadOnly(True)
        self.stdio_edit.setFont(mono)
        self.stdio_edit.setPlainText(format_config_json(build_stdio_config(cases_root=manager.cases_root)))
        stdio_layout.addWidget(self.stdio_edit, 1)

        stdio_actions = QHBoxLayout()
        self.copy_stdio_json_btn = QPushButton('复制配置 JSON')
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
        http_layout.setContentsMargins(10, 10, 10, 10)
        http_layout.setSpacing(8)
        http_hint = QLabel(
            '适用于支持 Streamable HTTP 的 MCP 客户端。点击上方“启动本地 HTTP 服务”或通过命令行启动后即可接入，'
            '已启用本机回环限制与 DNS 重绑定防护。'
        )
        http_hint.setProperty('role', 'muted')
        http_hint.setWordWrap(True)
        http_layout.addWidget(http_hint)

        self.http_edit = QPlainTextEdit()
        self.http_edit.setReadOnly(True)
        self.http_edit.setFont(mono)
        http_layout.addWidget(self.http_edit, 1)

        http_actions = QHBoxLayout()
        self.copy_http_json_btn = QPushButton('复制配置 JSON')
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
        self.tools_tree.setHeaderLabels(['工具名称', '分类', '模式', '功能说明'])
        for spec in TOOL_CATALOG:
            mode_text = '只读' if spec['read_only'] else '受控写入（记入审计链）'
            item = QTreeWidgetItem([spec['name'], spec['category'], mode_text, spec['summary']])
            self.tools_tree.addTopLevelItem(item)
        header = self.tools_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tools_layout.addWidget(self.tools_tree)
        self.tabs.addTab(tools_tab, f'可用工具清单（{len(TOOL_CATALOG)}）')

        layout.addWidget(self.tabs, 1)

        footer = QHBoxLayout()
        self.feedback_label = QLabel('')
        self.feedback_label.setProperty('role', 'muted')
        footer.addWidget(self.feedback_label, 1)
        close_btn = QPushButton('关闭')
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)
        layout.addLayout(footer)

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
            self.status_label.setStyleSheet(
                'background: #eaf6f0; color: #086b55; border: 1px solid #c8e6d7; '
                'border-radius: 6px; padding: 6px 10px; font-weight: 600;'
            )
            self.toggle_button.setText('停止本地 HTTP 服务')
            self.toggle_button.setProperty('role', 'soft')
        else:
            self.status_label.setText('本地 HTTP 服务状态：未启动（stdio 模式无需启动端口即可由外部客户端拉起）')
            self.status_label.setStyleSheet(
                'background: #f5f6f8; color: #4f665d; border: 1px solid #e2e7e5; '
                'border-radius: 6px; padding: 6px 10px;'
            )
            self.toggle_button.setText('启动本地 HTTP 服务')
            self.toggle_button.setProperty('role', 'accent')
        self.toggle_button.style().unpolish(self.toggle_button)
        self.toggle_button.style().polish(self.toggle_button)
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

    def _copy_text(self, text: str, notice: str) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
        self.feedback_label.setText(notice)


def show_mcp_dialog(context):
    dialog = McpDialog(context.root, get_manager(context), active_case=context.case())
    try:
        dialog.exec()
    finally:
        dialog.deleteLater()


FEATURE = Feature(
    'mcp',
    actions=(Action('mcp', show_mcp_dialog, 'MCP 服务', 'brand', 'pager'),),
    shutdown=shutdown_mcp,
)
