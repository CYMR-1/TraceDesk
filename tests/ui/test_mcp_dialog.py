"""PySide6 桌面端 MCP 配置弹窗与本地服务生命周期回归。"""
import json
import socket
import unittest

from PySide6.QtWidgets import QApplication

from forensic.features.mcp import McpDialog, get_manager
from forensic.mcp.server import TOOL_CATALOG
from tests.ui.test_gui import QtTests


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class McpDialogTests(QtTests):
    def test_mcp_button_mounts_in_brand_bar_and_stays_enabled_when_busy(self):
        _, app = self.controller()
        self.assertIn('mcp', app.view.action_buttons)
        app.view.set_busy(True)
        self.assertTrue(app.view.action_buttons['mcp'].isEnabled())
        app.view.set_busy(False)

    def test_mcp_dialog_config_copy_start_stop_and_window_shutdown(self):
        root, app = self.controller()
        manager = get_manager(app.features.context)
        self.addCleanup(manager.stop)
        dialog = McpDialog(root, manager)
        self.addCleanup(dialog.deleteLater)

        # 验证工具目录完整展示
        self.assertEqual(dialog.tools_tree.topLevelItemCount(), len(TOOL_CATALOG))

        # 验证 stdio JSON 配置合法
        stdio_cfg = json.loads(dialog.stdio_edit.toPlainText())
        self.assertIn('mcpServers', stdio_cfg)
        self.assertIn('tracedesk', stdio_cfg['mcpServers'])
        self.assertTrue(stdio_cfg['mcpServers']['tracedesk']['args'][0].endswith('mcp_server.py'))

        # 验证端口变更实时更新 HTTP 配置
        port = _free_local_port()
        dialog.port_spin.setValue(port)
        http_cfg = json.loads(dialog.http_edit.toPlainText())
        self.assertEqual(http_cfg['mcpServers']['tracedesk']['url'], f'http://127.0.0.1:{port}/mcp')

        # 验证复制到剪贴板
        dialog.copy_stdio_json_btn.click()
        self.assertEqual(QApplication.clipboard().text(), dialog.stdio_edit.toPlainText())
        self.assertIn('已复制', dialog.feedback_label.text())

        # 通过按钮启动本地 HTTP MCP 服务
        dialog.toggle_button.click()
        self.assertTrue(manager.running)
        self.assertIn('运行中', dialog.status_label.text())
        self.assertFalse(dialog.port_spin.isEnabled())

        # 关闭主窗口应自动停止托管的本地 HTTP MCP 服务
        app._shutdown()
        self.assertFalse(manager.running)


if __name__ == '__main__':
    unittest.main()
