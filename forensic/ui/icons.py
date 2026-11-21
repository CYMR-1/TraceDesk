"""本地矢量绘制的高 DPI 取证文件类型图标与界面操作图标；无外部依赖。"""
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import QApplication

from . import theme

_OUTLINE_CACHE: dict[tuple[int, str], QIcon] = {}
_UI_ICON_CACHE: dict[tuple[int, str, str, int, str | None], QIcon] = {}

_OUTLINE_PALETTE = {
    'folder': ('#B4781E', '#FEF5E2'),
    'disk': ('#2674C4', '#EAF4FF'),
    'file': ('#4A6682', '#F2F6FA'),
    'image': ('#B4466B', '#FDF0F5'),
    'table': ('#1F7A4D', '#ECF9F2'),
    'system': ('#6447B3', '#F4F0FD'),
}


def _app_key() -> int:
    app = QApplication.instance()
    return id(app) if app is not None else 0


def outline_icon(kind: str) -> QIcon:
    """绘制 32×32 逻辑像素（2× HiDPI 64×64）证据树与文件表图标。"""
    cache_key = (_app_key(), kind)
    cached = _OUTLINE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    stroke, fill = _OUTLINE_PALETTE[kind]
    pixmap = QPixmap(64, 64)
    pixmap.setDevicePixelRatio(2.0)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(
        QColor(stroke),
        1.5,
        Qt.PenStyle.SolidLine,
        Qt.PenCapStyle.RoundCap,
        Qt.PenJoinStyle.RoundJoin,
    )
    painter.setPen(pen)
    painter.setBrush(QColor(fill))

    if kind == 'folder':
        path = QPainterPath(QPointF(3.5, 9.5))
        path.lineTo(3.5, 6.8)
        path.quadTo(3.5, 4.8, 5.5, 4.8)
        path.lineTo(12.2, 4.8)
        path.lineTo(15.2, 8.0)
        path.lineTo(26.5, 8.0)
        path.quadTo(28.5, 8.0, 28.5, 10.0)
        path.lineTo(28.5, 24.8)
        path.quadTo(28.5, 26.8, 26.5, 26.8)
        path.lineTo(5.5, 26.8)
        path.quadTo(3.5, 26.8, 3.5, 24.8)
        path.closeSubpath()
        painter.drawPath(path)
        painter.drawLine(QPointF(4.2, 11.4), QPointF(27.8, 11.4))
    elif kind == 'disk':
        painter.drawRoundedRect(QRectF(3.5, 5.5, 25.0, 21.0), 3.6, 3.6)
        painter.drawLine(QPointF(4.2, 19.6), QPointF(27.8, 19.6))
        painter.drawArc(QRectF(9.5, 8.4, 9.0, 8.4), 35 * 16, 155 * 16)
        painter.setBrush(QColor(stroke))
        painter.drawEllipse(QPointF(23.5, 23.0), 1.0, 1.0)
        painter.drawEllipse(QPointF(19.6, 23.0), 1.0, 1.0)
    elif kind == 'image':
        painter.drawRoundedRect(QRectF(4.5, 5.5, 23.0, 21.0), 3.2, 3.2)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QPointF(10.8, 11.2), 2.1, 2.1)
        painter.drawPolyline(
            QPolygonF([
                QPointF(6.8, 23.2),
                QPointF(12.6, 16.6),
                QPointF(16.6, 20.4),
                QPointF(20.6, 15.2),
                QPointF(25.2, 23.2),
            ])
        )
    elif kind == 'table':
        painter.drawRoundedRect(QRectF(4.5, 5.5, 23.0, 21.0), 3.2, 3.2)
        painter.drawLine(QPointF(5.0, 11.2), QPointF(27.0, 11.2))
        painter.drawLine(QPointF(5.0, 16.4), QPointF(27.0, 16.4))
        painter.drawLine(QPointF(5.0, 21.6), QPointF(27.0, 21.6))
        painter.drawLine(QPointF(12.5, 11.2), QPointF(12.5, 26.0))
    elif kind == 'system':
        painter.drawRoundedRect(QRectF(6.2, 3.6, 19.6, 24.8), 3.0, 3.0)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(QPointF(16.0, 16.0), 3.8, 3.8)
        for dx, dy in ((0.0, -5.6), (0.0, 5.6), (-5.6, 0.0), (5.6, 0.0)):
            painter.drawLine(QPointF(16.0 + dx * 0.68, 16.0 + dy * 0.68), QPointF(16.0 + dx, 16.0 + dy))
        painter.setBrush(QColor(stroke))
        painter.drawEllipse(QPointF(16.0, 16.0), 1.1, 1.1)
    else:  # 'file'
        path = QPainterPath(QPointF(6.5, 3.8))
        path.lineTo(19.5, 3.8)
        path.lineTo(25.5, 9.8)
        path.lineTo(25.5, 26.2)
        path.quadTo(25.5, 28.2, 23.5, 28.2)
        path.lineTo(8.5, 28.2)
        path.quadTo(6.5, 28.2, 6.5, 26.2)
        path.closeSubpath()
        painter.drawPath(path)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolyline(QPolygonF([QPointF(19.2, 4.0), QPointF(19.2, 10.0), QPointF(25.2, 10.0)]))
        painter.drawLine(QPointF(10.5, 14.5), QPointF(21.5, 14.5))
        painter.drawLine(QPointF(10.5, 19.0), QPointF(21.5, 19.0))
        painter.drawLine(QPointF(10.5, 23.5), QPointF(17.5, 23.5))

    painter.end()
    icon = QIcon(pixmap)
    _OUTLINE_CACHE[cache_key] = icon
    return icon


def entry_icon_kind(entry) -> str:
    if entry['directory']:
        return 'folder'
    if entry['mode'].lower().startswith('v/'):
        return 'system'
    suffix = entry['path'].rsplit('.', 1)[-1].lower()
    if suffix in ('png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'svg'):
        return 'image'
    if suffix in ('csv', 'tsv', 'xls', 'xlsx', 'ods'):
        return 'table'
    return 'file'


def ui_icon(name: str, color: str = theme.TEXT_SECONDARY, size: int = 16, *, fill: str | None = None) -> QIcon:
    """绘制并缓存 HiDPI 线性操作图标，基于 16×16 矢量坐标系缩放。"""
    cache_key = (_app_key(), name, color, int(size), fill)
    cached = _UI_ICON_CACHE.get(cache_key)
    if cached is not None:
        return cached

    logical = max(12, int(size))
    pixmap = QPixmap(logical * 2, logical * 2)
    pixmap.setDevicePixelRatio(2.0)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    scale = logical / 16.0
    painter.scale(scale, scale)

    stroke_color = QColor(color)
    stroke_width = 1.35 if logical >= 28 else 1.5
    pen = QPen(
        stroke_color,
        stroke_width,
        Qt.PenStyle.SolidLine,
        Qt.PenCapStyle.RoundCap,
        Qt.PenJoinStyle.RoundJoin,
    )
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    def _soft_fill() -> QColor | None:
        if fill is not None:
            return QColor(fill)
        if logical >= 24:
            tinted = QColor(stroke_color)
            tinted.setAlpha(30)
            return tinted
        return None

    if name == 'search':
        painter.drawEllipse(QPointF(7.1, 7.1), 4.2, 4.2)
        painter.drawLine(QPointF(10.2, 10.2), QPointF(13.8, 13.8))
    elif name == 'import_disk':
        painter.drawRoundedRect(QRectF(2.2, 9.6, 11.6, 4.2), 1.4, 1.4)
        painter.drawLine(QPointF(8.0, 2.2), QPointF(8.0, 8.0))
        painter.drawPolyline(QPolygonF([QPointF(5.4, 5.6), QPointF(8.0, 8.2), QPointF(10.6, 5.6)]))
        painter.setBrush(stroke_color)
        painter.drawEllipse(QPointF(11.4, 11.7), 0.7, 0.7)
    elif name in ('verify', 'check_shield'):
        path = QPainterPath(QPointF(8.0, 1.8))
        path.lineTo(13.2, 3.8)
        path.lineTo(13.2, 7.7)
        path.cubicTo(13.2, 10.9, 10.9, 13.0, 8.0, 14.3)
        path.cubicTo(5.1, 13.0, 2.8, 10.9, 2.8, 7.7)
        path.lineTo(2.8, 3.8)
        path.closeSubpath()
        tint = _soft_fill() if name == 'check_shield' else (QColor(fill) if fill else None)
        if tint is not None:
            painter.setBrush(tint)
        painter.drawPath(path)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPolyline(QPolygonF([QPointF(5.5, 8.1), QPointF(7.3, 9.9), QPointF(10.7, 6.2)]))
    elif name == 'export':
        painter.drawPolyline(QPolygonF([QPointF(2.8, 10.4), QPointF(2.8, 13.2), QPointF(13.2, 13.2), QPointF(13.2, 10.4)]))
        painter.drawLine(QPointF(8.0, 9.8), QPointF(8.0, 2.8))
        painter.drawPolyline(QPolygonF([QPointF(5.2, 5.5), QPointF(8.0, 2.7), QPointF(10.8, 5.5)]))
    elif name == 'report':
        painter.drawRoundedRect(QRectF(3.2, 1.8, 9.6, 12.4), 1.6, 1.6)
        painter.drawLine(QPointF(5.5, 5.4), QPointF(10.5, 5.4))
        painter.drawLine(QPointF(5.5, 8.2), QPointF(10.5, 8.2))
        painter.drawLine(QPointF(5.5, 11.0), QPointF(8.7, 11.0))
    elif name == 'bundle':
        painter.drawRoundedRect(QRectF(2.0, 2.6, 12.0, 2.8), 1.0, 1.0)
        painter.drawRoundedRect(QRectF(2.8, 5.4, 10.4, 8.4), 1.4, 1.4)
        painter.drawLine(QPointF(6.4, 8.6), QPointF(9.6, 8.6))
    elif name == 'case_new':
        path = QPainterPath(QPointF(2.2, 5.0))
        path.lineTo(2.2, 3.8)
        path.quadTo(2.2, 2.8, 3.2, 2.8)
        path.lineTo(6.4, 2.8)
        path.lineTo(7.8, 4.4)
        path.lineTo(12.8, 4.4)
        path.quadTo(13.8, 4.4, 13.8, 5.4)
        path.lineTo(13.8, 12.2)
        path.quadTo(13.8, 13.2, 12.8, 13.2)
        path.lineTo(3.2, 13.2)
        path.quadTo(2.2, 13.2, 2.2, 12.2)
        path.closeSubpath()
        painter.drawPath(path)
        painter.drawLine(QPointF(8.0, 6.8), QPointF(8.0, 10.8))
        painter.drawLine(QPointF(6.0, 8.8), QPointF(10.0, 8.8))
    elif name == 'case_open':
        back = QPainterPath(QPointF(2.2, 12.2))
        back.lineTo(2.2, 3.8)
        back.quadTo(2.2, 2.8, 3.2, 2.8)
        back.lineTo(6.4, 2.8)
        back.lineTo(7.8, 4.4)
        back.lineTo(12.4, 4.4)
        back.quadTo(13.2, 4.4, 13.2, 5.2)
        back.lineTo(13.2, 6.8)
        painter.drawPath(back)
        front = QPainterPath(QPointF(2.2, 12.6))
        front.lineTo(4.0, 7.0)
        front.lineTo(14.2, 7.0)
        front.lineTo(12.4, 12.6)
        front.closeSubpath()
        painter.drawPath(front)
    elif name == 'mcp':
        painter.drawLine(QPointF(5.5, 7.2), QPointF(10.5, 4.8))
        painter.drawLine(QPointF(5.5, 8.8), QPointF(10.5, 11.2))
        painter.drawEllipse(QPointF(4.0, 8.0), 1.8, 1.8)
        painter.drawEllipse(QPointF(12.0, 4.0), 1.8, 1.8)
        painter.drawEllipse(QPointF(12.0, 12.0), 1.8, 1.8)
    elif name == 'help':
        painter.drawEllipse(QPointF(8.0, 8.0), 6.0, 6.0)
        q = QPainterPath(QPointF(6.2, 6.3))
        q.cubicTo(6.2, 4.8, 9.8, 4.8, 9.8, 6.5)
        q.cubicTo(9.8, 7.7, 8.0, 7.9, 8.0, 9.2)
        painter.drawPath(q)
        painter.setBrush(stroke_color)
        painter.drawEllipse(QPointF(8.0, 11.5), 0.75, 0.75)
    elif name == 'warning':
        tri = QPainterPath(QPointF(8.0, 2.2))
        tri.lineTo(14.0, 12.8)
        tri.quadTo(14.4, 13.5, 13.5, 13.5)
        tri.lineTo(2.5, 13.5)
        tri.quadTo(1.6, 13.5, 2.0, 12.8)
        tri.closeSubpath()
        tint = _soft_fill()
        if tint is not None:
            painter.setBrush(tint)
        painter.drawPath(tri)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawLine(QPointF(8.0, 6.0), QPointF(8.0, 9.4))
        painter.setBrush(stroke_color)
        painter.drawEllipse(QPointF(8.0, 11.5), 0.75, 0.75)
    elif name == 'folder_up':
        path = QPainterPath(QPointF(12.6, 12.4))
        path.lineTo(12.6, 8.4)
        path.quadTo(12.6, 6.2, 10.4, 6.2)
        path.lineTo(3.8, 6.2)
        painter.drawPath(path)
        painter.drawPolyline(QPolygonF([QPointF(6.4, 3.6), QPointF(3.8, 6.2), QPointF(6.4, 8.8)]))
    elif name == 'index':
        painter.drawEllipse(QRectF(3.0, 2.4, 10.0, 3.6))
        arc1 = QPainterPath(QPointF(3.0, 4.2))
        arc1.lineTo(3.0, 8.2)
        arc1.cubicTo(3.0, 10.2, 13.0, 10.2, 13.0, 8.2)
        arc1.lineTo(13.0, 4.2)
        painter.drawPath(arc1)
        arc2 = QPainterPath(QPointF(3.0, 8.2))
        arc2.lineTo(3.0, 12.0)
        arc2.cubicTo(3.0, 14.0, 13.0, 14.0, 13.0, 12.0)
        arc2.lineTo(13.0, 8.2)
        painter.drawPath(arc2)
    elif name == 'expand':
        painter.drawPolyline(QPolygonF([QPointF(4.4, 6.0), QPointF(8.0, 2.6), QPointF(11.6, 6.0)]))
        painter.drawPolyline(QPolygonF([QPointF(4.4, 10.0), QPointF(8.0, 13.4), QPointF(11.6, 10.0)]))
    elif name == 'collapse':
        painter.drawPolyline(QPolygonF([QPointF(4.4, 3.0), QPointF(8.0, 6.4), QPointF(11.6, 3.0)]))
        painter.drawPolyline(QPolygonF([QPointF(4.4, 13.0), QPointF(8.0, 9.6), QPointF(11.6, 13.0)]))
    elif name == 'document_preview':
        doc = QPainterPath(QPointF(8.2, 13.4))
        doc.lineTo(4.0, 13.4)
        doc.quadTo(2.8, 13.4, 2.8, 12.2)
        doc.lineTo(2.8, 3.2)
        doc.quadTo(2.8, 2.0, 4.0, 2.0)
        doc.lineTo(9.8, 2.0)
        doc.quadTo(11.0, 2.0, 11.0, 3.2)
        doc.lineTo(11.0, 6.6)
        painter.drawPath(doc)
        painter.drawLine(QPointF(5.0, 5.2), QPointF(8.8, 5.2))
        painter.drawLine(QPointF(5.0, 7.8), QPointF(7.4, 7.8))
        painter.drawEllipse(QPointF(10.4, 10.4), 2.6, 2.6)
        painter.drawLine(QPointF(12.3, 12.3), QPointF(14.0, 14.0))
    elif name == 'copy':
        painter.drawRoundedRect(QRectF(5.6, 5.2, 7.6, 8.6), 1.3, 1.3)
        back = QPainterPath(QPointF(10.4, 5.2))
        back.lineTo(10.4, 3.4)
        back.quadTo(10.4, 2.2, 9.2, 2.2)
        back.lineTo(4.0, 2.2)
        back.quadTo(2.8, 2.2, 2.8, 3.4)
        back.lineTo(2.8, 9.6)
        back.quadTo(2.8, 10.8, 4.0, 10.8)
        back.lineTo(5.6, 10.8)
        painter.drawPath(back)
    elif name == 'lock_open':
        painter.drawRoundedRect(QRectF(3.2, 7.4, 9.6, 6.4), 1.5, 1.5)
        shackle = QPainterPath(QPointF(5.4, 7.4))
        shackle.lineTo(5.4, 4.9)
        shackle.cubicTo(5.4, 2.2, 10.2, 2.0, 10.7, 4.5)
        painter.drawPath(shackle)
        painter.setBrush(stroke_color)
        painter.drawEllipse(QPointF(8.0, 10.6), 0.9, 0.9)
    else:
        raise ValueError(f'Unknown UI icon: {name}')

    painter.end()
    icon = QIcon(pixmap)
    _UI_ICON_CACHE[cache_key] = icon
    return icon
