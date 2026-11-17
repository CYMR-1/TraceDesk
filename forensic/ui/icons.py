"""本地绘制的彩色线性图标；不依赖外部字体、网络或图片包。"""
from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap, QPolygonF


def outline_icon(kind):
    colors = {
        'folder': ('#b57c17', '#fff0c5'),
        'disk': ('#7953be', '#eee5fc'),
        'file': ('#168674', '#e4f5ed'),
        'image': ('#ba577a', '#fce9ef'),
        'table': ('#329258', '#e5f5e9'),
        'system': ('#79858c', '#eef1f3'),
    }
    stroke, fill = colors[kind]
    pixmap = QPixmap(40, 40)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.scale(1.25, 1.25)
    painter.setPen(QPen(QColor(stroke), 1.7, Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    painter.setBrush(QColor(fill))
    if kind == 'folder':
        path = QPainterPath(QPointF(3, 9))
        path.lineTo(3, 6)
        path.quadTo(3, 4, 5, 4)
        path.lineTo(13, 4)
        path.lineTo(17, 8)
        path.lineTo(27, 8)
        path.quadTo(29, 8, 29, 11)
        path.lineTo(29, 25)
        path.quadTo(29, 28, 26, 28)
        path.lineTo(6, 28)
        path.quadTo(3, 28, 3, 25)
        path.closeSubpath()
        painter.drawPath(path)
        painter.drawLine(4, 11, 28, 11)
    elif kind == 'disk':
        painter.drawRoundedRect(3, 5, 26, 23, 4, 4)
        painter.drawLine(4, 20, 28, 20)
        painter.drawPoint(23, 24)
        painter.drawPoint(19, 24)
    else:
        painter.drawRoundedRect(6, 3, 21, 26, 3, 3)
        if kind == 'image':
            painter.drawEllipse(11, 9, 4, 4)
            painter.drawPolyline(QPolygonF([QPointF(9, 24), QPointF(15, 17),
                                            QPointF(19, 21), QPointF(24, 15)]))
        elif kind == 'table':
            for y in (11, 17, 23):
                painter.drawLine(10, y, 23, y)
            painter.drawLine(16, 8, 16, 25)
        else:
            painter.drawLine(11, 11, 22, 11)
            painter.drawLine(11, 17, 22, 17)
            painter.drawLine(11, 23, 18, 23)
    painter.end()
    return QIcon(pixmap)


def entry_icon_kind(entry):
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
