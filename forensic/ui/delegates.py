"""取证列表语义胶囊委托与十六进制只读视图委托。"""
from PySide6.QtCore import QPointF, QRect, QRectF, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QFontMetricsF, QIcon, QPainter, QPalette, QPen
from PySide6.QtWidgets import QApplication, QStyle, QStyledItemDelegate, QStyleOptionViewItem

from . import theme
from .metrics import ROW_HEIGHT_HEX, ROW_HEIGHT_TABLE


def _draw_selection_rail(painter: QPainter, rect: QRect) -> None:
    painter.save()
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(theme.ACCENT))
    painter.drawRect(QRectF(float(rect.left()), float(rect.top()), 2.5, float(rect.height())))
    painter.restore()


def _draw_item_background(style: QStyle, opt: QStyleOptionViewItem, painter: QPainter, *, clear_brush: bool = False) -> None:
    bg_opt = QStyleOptionViewItem(opt)
    bg_opt.text = ''
    bg_opt.icon = QIcon()
    bg_opt.features &= ~QStyleOptionViewItem.ViewItemFeature.HasDisplay
    bg_opt.features &= ~QStyleOptionViewItem.ViewItemFeature.HasDecoration
    if clear_brush:
        bg_opt.backgroundBrush = QBrush()
    style.drawControl(QStyle.ControlElement.CE_ItemViewItem, bg_opt, painter, opt.widget)


class ForensicItemDelegate(QStyledItemDelegate):
    """统一的取证表格/文件树渲染委托：语义胶囊徽章、等宽数字列、静默占位与普鲁士蓝选中导轨。"""

    def __init__(
        self,
        parent=None,
        *,
        pill_columns=(),
        mono_columns=(),
        subtle_columns=(),
        accent_column: int | None = 0,
        row_height: int = ROW_HEIGHT_TABLE,
        muted_prefixes: tuple[str, ...] = ('—', '未记录', '不支持'),
        mono_size: float = 9.0,
        pill_size: float = 8.5,
    ):
        super().__init__(parent)
        self._pill_columns = frozenset(pill_columns)
        self._mono_columns = frozenset(mono_columns)
        self._subtle_columns = frozenset(subtle_columns)
        self._accent_column = accent_column
        self._row_height = int(row_height)
        self._muted_prefixes = tuple(muted_prefixes)
        self._mono_font = theme.mono_font(mono_size, cjk_fallback=True)
        self._pill_font = theme.ui_font(pill_size, QFont.Weight.DemiBold)

    def _is_muted(self, text: str) -> bool:
        return bool(text) and any(text.startswith(prefix) for prefix in self._muted_prefixes)

    def sizeHint(self, option, index) -> QSize:
        size = super().sizeHint(option, index)
        col = index.column()
        raw = str(index.data(Qt.ItemDataRole.DisplayRole) or '').strip()
        if col in self._pill_columns and raw and not self._is_muted(raw):
            fm = QFontMetrics(self._pill_font)
            width = max(size.width(), fm.horizontalAdvance(raw) + 28)
            return QSize(width, self._row_height if self._row_height > 0 else size.height())
        if col in self._mono_columns and raw:
            fm = QFontMetrics(self._mono_font)
            width = max(size.width(), fm.horizontalAdvance(raw) + 18)
            return QSize(width, self._row_height if self._row_height > 0 else size.height())
        if self._row_height > 0:
            return QSize(size.width(), self._row_height)
        return size

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.state &= ~QStyle.StateFlag.State_HasFocus

        style = opt.widget.style() if opt.widget is not None else QApplication.style()
        col = index.column()
        is_selected = bool(opt.state & QStyle.StateFlag.State_Selected)
        is_enabled = bool(opt.state & QStyle.StateFlag.State_Enabled)
        raw = opt.text.strip()

        if col in self._pill_columns and raw and not self._is_muted(raw):
            pill = theme.semantic_pill(raw, default=theme.PILL_NEUTRAL)
            _draw_item_background(style, opt, painter, clear_brush=True)
            if pill is not None:
                self._paint_pill(painter, opt, raw, pill)
            if self._accent_column is not None and col == self._accent_column and is_selected:
                _draw_selection_rail(painter, opt.rect)
            return

        if col in self._mono_columns:
            mono = QFont(self._mono_font)
            if opt.font.bold():
                mono.setWeight(QFont.Weight.DemiBold)
            opt.font = mono
            opt.fontMetrics = QFontMetrics(mono)

        if not is_selected and is_enabled:
            if self._is_muted(raw):
                muted_color = QColor(theme.TEXT_MUTED)
                opt.palette.setColor(QPalette.ColorRole.Text, muted_color)
                opt.palette.setColor(QPalette.ColorRole.WindowText, muted_color)
            elif col in self._subtle_columns:
                subtle_color = QColor('#47586B')
                opt.palette.setColor(QPalette.ColorRole.Text, subtle_color)
                opt.palette.setColor(QPalette.ColorRole.WindowText, subtle_color)

        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)

        if self._accent_column is not None and col == self._accent_column and is_selected:
            _draw_selection_rail(painter, opt.rect)

    def _paint_pill(self, painter: QPainter, opt: QStyleOptionViewItem, text: str, pill: theme.PillStyle) -> None:
        rect = opt.rect
        if rect.width() < 14 or rect.height() < 14:
            return
        fm = QFontMetricsF(self._pill_font)
        h_pad = 8.0
        outer_x = 6.0
        pill_h = min(20.0, max(16.0, float(rect.height()) - 6.0))
        max_w = max(12.0, float(rect.width()) - outer_x * 2.0)
        text_w = fm.horizontalAdvance(text)
        pill_w = min(max_w, text_w + h_pad * 2.0)
        inner_w = max(4.0, pill_w - h_pad * 2.0)
        draw_text = fm.elidedText(text, Qt.TextElideMode.ElideRight, inner_w) if text_w > inner_w + 0.5 else text

        align = opt.displayAlignment
        if align & Qt.AlignmentFlag.AlignHCenter:
            px = rect.left() + (rect.width() - pill_w) / 2.0
        elif align & Qt.AlignmentFlag.AlignRight:
            px = rect.right() + 1.0 - outer_x - pill_w
        else:
            px = rect.left() + outer_x
        py = rect.top() + (rect.height() - pill_h) / 2.0
        pill_rect = QRectF(px, py, pill_w, pill_h).adjusted(0.5, 0.5, -0.5, -0.5)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(QPen(QColor(pill.border), 1.0))
        painter.setBrush(QColor(pill.bg))
        painter.drawRoundedRect(pill_rect, 4.0, 4.0)
        painter.setFont(self._pill_font)
        painter.setPen(QColor(pill.fg))
        painter.drawText(pill_rect, Qt.AlignmentFlag.AlignCenter, draw_text)
        painter.restore()


class HexItemDelegate(QStyledItemDelegate):
    """十六进制视图专用委托：凹陷偏移槽、00 空字节弱化、字符区细分界线，完整保留复杂文字整形。"""

    def __init__(self, parent=None, *, row_height: int = ROW_HEIGHT_HEX):
        super().__init__(parent)
        self._row_height = int(row_height)

    def sizeHint(self, option, index) -> QSize:
        size = super().sizeHint(option, index)
        if self._row_height > 0:
            return QSize(size.width(), self._row_height)
        return size

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.state &= ~QStyle.StateFlag.State_HasFocus

        style = opt.widget.style() if opt.widget is not None else QApplication.style()
        col = index.column()
        is_selected = bool(opt.state & QStyle.StateFlag.State_Selected)
        is_hovered = bool(opt.state & QStyle.StateFlag.State_MouseOver)
        rect = opt.rect

        if col == 0:
            painter.save()
            if is_selected:
                bg = QColor(theme.SURFACE_SELECTED)
            elif is_hovered:
                bg = QColor('#EBF1F8')
            else:
                bg = QColor(theme.CHROME_BG)
            painter.fillRect(rect, bg)
            painter.fillRect(QRect(rect.right(), rect.top(), 1, rect.height()), QColor(theme.BORDER_HAIRLINE))
            if is_selected:
                _draw_selection_rail(painter, rect)
            painter.setFont(opt.font)
            painter.setPen(QColor(theme.SURFACE_SELECTED_TEXT if is_selected else theme.HEX_OFFSET_FG))
            painter.drawText(rect.adjusted(8, 0, -6, 0), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, opt.text)
            painter.restore()
            return

        if col == 1:
            _draw_item_background(style, opt, painter)
            text = opt.text
            if not text:
                return
            painter.save()
            painter.setClipRect(rect.adjusted(4, 0, -4, 0))
            painter.setFont(opt.font)
            fm = QFontMetricsF(opt.font)
            baseline = rect.top() + (rect.height() + fm.ascent() - fm.descent()) / 2.0
            x = float(rect.left() + 8)
            space_w = fm.horizontalAdvance(' ')
            normal_pen = QColor(theme.SURFACE_SELECTED_TEXT if is_selected else theme.TEXT_PRIMARY)
            null_pen = QColor(theme.HEX_NULL_SELECTED_FG if is_selected else theme.HEX_NULL_FG)
            limit_x = float(rect.right())
            for token in text.split(' '):
                if not token:
                    continue
                if x > limit_x:
                    break
                painter.setPen(null_pen if token == '00' else normal_pen)
                painter.drawText(QPointF(x, baseline), token)
                x += fm.horizontalAdvance(token) + space_w
            painter.restore()
            return

        if col == 2:
            text = opt.text
            # 含中文、印度系文字或其它非 ASCII 字符（除不可打印占位符 '·' 外）时，完全交由 Qt 原生整形绘制。
            if any(ord(ch) > 127 and ch != '·' for ch in text):
                super().paint(painter, opt, index)
                painter.fillRect(QRect(rect.left(), rect.top(), 1, rect.height()), QColor('#E8EDF3'))
                return

            _draw_item_background(style, opt, painter)
            painter.fillRect(QRect(rect.left(), rect.top(), 1, rect.height()), QColor('#E8EDF3'))
            if not text:
                return
            painter.save()
            painter.setClipRect(rect.adjusted(4, 0, -4, 0))
            painter.setFont(opt.font)
            fm = QFontMetricsF(opt.font)
            baseline = rect.top() + (rect.height() + fm.ascent() - fm.descent()) / 2.0
            x = float(rect.left() + 8)
            normal_pen = QColor(theme.SURFACE_SELECTED_TEXT if is_selected else theme.HEX_CHAR_FG)
            dot_pen = QColor(theme.HEX_NULL_SELECTED_FG if is_selected else theme.HEX_DOT_FG)
            limit_x = float(rect.right())

            idx = 0
            length = len(text)
            while idx < length and x <= limit_x:
                muted = text[idx] == '·'
                end = idx + 1
                while end < length and (text[end] == '·') == muted:
                    end += 1
                chunk = text[idx:end]
                painter.setPen(dot_pen if muted else normal_pen)
                painter.drawText(QPointF(x, baseline), chunk)
                x += fm.horizontalAdvance(chunk)
                idx = end
            painter.restore()
            return

        super().paint(painter, opt, index)
