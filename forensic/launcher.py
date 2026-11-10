"""桌面应用入口与可见的异常报告。"""
from datetime import datetime
from pathlib import Path
import sys
import tempfile
import traceback


class ErrorReporter:
    """将启动或 Qt 回调异常写入日志，并向用户显示日志位置。"""

    def __init__(self, log_path=None):
        self.log_path = Path(log_path) if log_path else Path(__file__).resolve().parent.parent / 'logs' / 'startup.log'
        self.root = None
        self._previous_hook = None
        self._hook = self.report_exception
        self._installed = False

    def install(self, root):
        self.root = root
        if not self._installed:
            self._previous_hook = sys.excepthook
            self._installed = True
        sys.excepthook = self._hook

    def restore(self):
        """退出事件循环时恢复宿主的异常处理器。"""
        if self._installed and sys.excepthook is self._hook:
            sys.excepthook = self._previous_hook
        self._previous_hook = None
        self._installed = False
        self.root = None

    def report_exception(self, exception_type, exception, tb):
        detail = ''.join(traceback.format_exception(exception_type, exception, tb))
        log_path = self._write_log(detail)
        location = f'\n\n错误日志：{log_path}' if log_path else '\n\n无法写入错误日志，请检查目录权限。'
        message = f'程序遇到错误：{exception}{location}'
        try:
            from PySide6.QtWidgets import QApplication, QMessageBox
            if QApplication.instance() is None:
                raise RuntimeError('Qt 应用尚未初始化')
            QMessageBox.critical(self.root, 'TraceDesk · 程序错误', message)
        except Exception:
            # PySide6 缺失或 Qt 初始化失败时，仍能在 Windows 显示原因。
            try:
                import ctypes
                ctypes.windll.user32.MessageBoxW(None, message, 'TraceDesk', 0x10)
            except Exception:
                pass

    def _write_log(self, detail):
        fallback = Path(tempfile.gettempdir()) / 'TraceDesk' / 'startup.log'
        for path in (self.log_path, fallback):
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('a', encoding='utf-8') as output:
                    output.write(f'\n[{datetime.now().astimezone().isoformat(timespec="seconds")}]\n{detail}')
                return path
            except OSError:
                continue
        return None


class ApplicationLauncher:
    """延迟加载界面，统一报告导入与初始化错误。"""

    def __init__(self, reporter=None):
        self.reporter = reporter if reporter is not None else ErrorReporter()

    def run(self):
        try:
            from .gui import main
            main()
            return 0
        except Exception as error:
            self.reporter.report_exception(type(error), error, error.__traceback__)
            return 1
