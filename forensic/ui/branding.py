"""应用图标和 Windows 任务栏身份；资源定位不依赖启动目录。"""
import sys

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QIcon, QImage, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication

from ..paths import ASSET_DIR

APP_ID = 'TraceDesk.ForensicWorkbench'


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


def brand_icon() -> QIcon:
    """加载多分辨率应用图标（ICO 优先，SVG 回退）。"""
    icon = QIcon(str(ASSET_DIR / 'tracedesk.ico'))
    if icon.isNull():
        icon = QIcon(str(ASSET_DIR / 'tracedesk.svg'))
    return icon


def brand_pixmap(size: int = 28, dpr: float = 1.0) -> QPixmap:
    """按显示器缩放倍率直接矢量光栅化品牌徽标，保证顶部命令带清晰锐利。"""
    scale = max(1.0, float(dpr or 1.0))
    svg_path = ASSET_DIR / 'tracedesk.svg'
    renderer = QSvgRenderer(str(svg_path))
    if renderer.isValid():
        pixel_size = max(1, round(size * scale))
        image = QImage(pixel_size, pixel_size, QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        renderer.render(painter, QRectF(0.0, 0.0, float(pixel_size), float(pixel_size)))
        painter.end()
        pixmap = QPixmap.fromImage(image)
        pixmap.setDevicePixelRatio(scale)
        return pixmap
    return brand_icon().pixmap(QSize(size, size), scale)


def set_window_icon(window):
    """统一主窗口、任务栏及后续对话框使用的应用图标。"""
    icon = brand_icon()
    app = QApplication.instance()
    if app is not None:
        app.setWindowIcon(icon)
    if window is not None:
        window.setWindowIcon(icon)
