"""应用图标和 Windows 任务栏身份；资源定位不依赖启动目录。"""
from pathlib import Path
import sys

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication


APP_ID = 'TraceDesk.ForensicWorkbench'
ASSET_DIR = Path(__file__).resolve().parent / 'assets'


def set_windows_app_id():
    """在创建窗口前设置进程身份，使工作台拥有独立的任务栏分组。"""
    if sys.platform != 'win32':
        return False
    import ctypes

    try:
        shell = ctypes.WinDLL('shell32', use_last_error=True)
        set_app_id = shell.SetCurrentProcessExplicitAppUserModelID
        set_app_id.argtypes = [ctypes.c_wchar_p]
        set_app_id.restype = ctypes.c_long
        return set_app_id(APP_ID) >= 0
    except (AttributeError, OSError):
        # 无 Windows Shell 的环境仍可通过 Qt 显示窗口图标。
        return False


def set_window_icon(window):
    """统一主窗口、任务栏及后续对话框使用的应用图标。"""
    icon = QIcon(str(ASSET_DIR / 'tracedesk.ico'))
    if icon.isNull():
        icon = QIcon(str(ASSET_DIR / 'tracedesk.svg'))
    QApplication.instance().setWindowIcon(icon)
    window.setWindowIcon(icon)
