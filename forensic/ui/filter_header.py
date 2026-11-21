"""支持表头下拉筛选、全选复选框与指定列排序的表头组件。"""
from PySide6.QtCore import QPoint, QPointF, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import QHeaderView, QMenu

from . import theme


class FilterHeaderView(QHeaderView):
    """统一表头：支持可选首列三态全选框（带字样）、下拉筛选列与正倒序排序列。"""

    toggled = Signal(bool)
    filter_changed = Signal(int, object)
    sort_requested = Signal(int)

    SECTION_HEIGHT = 32

    def __init__(self, parent=None, *, checkable_column=None, check_label='全选',
                 filter_columns=(), sort_columns=()):
        super().__init__(Qt.Orientation.Horizontal, parent)
        self.setObjectName('recordHeader')
        self.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.setStretchLastSection(True)
        self.setSectionsClickable(True)
        self.setMouseTracking(True)
        self._checkable_column = checkable_column
        self._check_label = check_label
        self._check_state = Qt.CheckState.Unchecked
        self._filter_columns = set(filter_columns)
        self._sort_columns = set(sort_columns)
        self._options = {column: [] for column in filter_columns}
        self._selected = {column: None for column in filter_columns}
        self._hovered_column = -1
        if sort_columns:
            self.setSortIndicatorShown(True)

    def sizeHint(self):
        size = super().sizeHint()
        return QSize(size.width(), max(self.SECTION_HEIGHT, size.height()))

    def check_state(self):
        return self._check_state

    def set_check_state(self, state):
        if self._check_state != state:
            self._check_state = state
            self.viewport().update()

    def filter_columns(self):
        return tuple(sorted(self._filter_columns))

    def filter_options(self, column):
        return list(self._options.get(column, ()))

    def set_filter_options(self, column, values):
        if column not in self._filter_columns:
            return
        items = list(values)
        self._options[column] = items
        if self._selected[column] is not None and not items:
            self._selected[column] = None
        self.viewport().update()

    def filter_value(self, column):
        return self._selected.get(column)

    def active_filters(self):
        return {column: value for column, value in self._selected.items() if value is not None}

    def set_filter_value(self, column, value, *, emit=True):
        if column not in self._filter_columns:
            return
        if self._selected[column] == value:
            return
        self._selected[column] = value
        self.viewport().update()
        if emit:
            self.filter_changed.emit(column, value)

    def clear_filters(self, *, emit=False):
        changed = [column for column, value in self._selected.items() if value is not None]
        for column in changed:
            self._selected[column] = None
        if changed:
            self.viewport().update()
            if emit:
                for column in changed:
                    self.filter_changed.emit(column, None)

    @staticmethod
    def _checkbox_rect(rect):
        # QTreeView::indicator 为 15px 内容 + 1px 边框（总 17px），左起点与行复选框像素对齐。
        size = 17
        x = rect.left() + 8
        y = rect.top() + (rect.height() - size) // 2
        return QRect(x, y, size, size)

    def _base_label(self, logicalIndex):
        model = self.model()
        if model is None:
            return ''
        value = model.headerData(logicalIndex, self.orientation(), Qt.ItemDataRole.DisplayRole)
        return '' if value is None else str(value)

    def _header_alignment(self, logicalIndex):
        model = self.model()
        if model is not None:
            value = model.headerData(logicalIndex, self.orientation(), Qt.ItemDataRole.TextAlignmentRole)
            if value is not None:
                return Qt.AlignmentFlag(value)
        return self.defaultAlignment()

    def _header_font(self, painter, *, bold=False):
        font = QFont(painter.font())
        font.setPointSizeF(8.5)
        font.setWeight(QFont.Weight.Bold if bold else QFont.Weight.DemiBold)
        return font

    def _paint_chrome(self, painter, rect, logicalIndex, *, bg, active=False):
        painter.fillRect(rect, QColor(bg))
        painter.fillRect(QRect(rect.left(), rect.bottom(), rect.width(), 1), QColor(theme.HEADER_CELL_BORDER))
        if logicalIndex < self.count() - 1:
            painter.fillRect(QRect(rect.right(), rect.top(), 1, max(0, rect.height() - 1)),
                             QColor(theme.HEADER_CELL_DIVIDER))
        if active:
            painter.fillRect(QRect(rect.left(), rect.bottom() - 1, rect.width(), 2), QColor(theme.ACCENT))

    def paintSection(self, painter, rect, logicalIndex):
        if not rect.isValid():
            return

        if logicalIndex == self._checkable_column:
            hovered = self._hovered_column == logicalIndex
            painter.save()
            bg = theme.HEADER_CELL_HOVER_BG if hovered else theme.HEADER_CELL_BG
            self._paint_chrome(painter, rect, logicalIndex, bg=bg)
            box = QRectF(self._checkbox_rect(rect)).adjusted(0.5, 0.5, -0.5, -0.5)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            checked = self._check_state != Qt.CheckState.Unchecked
            fill = QColor(theme.ACCENT) if checked else QColor(theme.SURFACE_BG)
            border = QColor(theme.ACCENT) if (checked or hovered) else QColor(theme.BORDER_STRONG)
            painter.setPen(QPen(border, 1.0))
            painter.setBrush(fill)
            painter.drawRoundedRect(box, 3.0, 3.0)
            if self._check_state == Qt.CheckState.Checked:
                path = QPainterPath()
                path.moveTo(box.left() + box.width() * 0.22, box.top() + box.height() * 0.52)
                path.lineTo(box.left() + box.width() * 0.42, box.top() + box.height() * 0.72)
                path.lineTo(box.left() + box.width() * 0.78, box.top() + box.height() * 0.29)
                pen = QPen(QColor(theme.SURFACE_BG), 1.7, Qt.PenStyle.SolidLine,
                           Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
                painter.setPen(pen)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(path)
            elif self._check_state == Qt.CheckState.PartiallyChecked:
                y = box.center().y()
                pen = QPen(QColor(theme.SURFACE_BG), 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
                painter.setPen(pen)
                painter.drawLine(QPointF(box.left() + 3.2, y), QPointF(box.right() - 3.2, y))
            if self._check_label:
                painter.setFont(self._header_font(painter))
                painter.setPen(QColor(theme.ACCENT) if hovered else QColor(theme.TEXT_SECONDARY))
                text_left = int(box.right()) + 6
                text_rect = QRect(text_left, rect.top(), max(0, rect.right() - text_left - 6), rect.height())
                painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self._check_label)
            painter.restore()
            return

        if logicalIndex in self._filter_columns:
            selected = self._selected.get(logicalIndex)
            hovered = self._hovered_column == logicalIndex
            active = selected is not None
            painter.save()
            bg = theme.HEADER_CELL_ACTIVE_BG if active else (
                theme.HEADER_CELL_HOVER_BG if hovered else theme.HEADER_CELL_BG
            )
            self._paint_chrome(painter, rect, logicalIndex, bg=bg, active=active)
            base = self._base_label(logicalIndex)
            label = f'{base}：{selected}' if active else base
            painter.setFont(self._header_font(painter, bold=active))
            text_color = QColor(theme.ACCENT_SOFT_TEXT) if active else (
                QColor(theme.ACCENT) if hovered else QColor(theme.HEADER_CELL_FG)
            )
            painter.setPen(text_color)
            text_rect = QRect(rect.left() + 8, rect.top(), max(0, rect.width() - 26), rect.height())
            elided = painter.fontMetrics().elidedText(label, Qt.TextElideMode.ElideRight, text_rect.width())
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elided)
            # 右侧绘制下拉筛选指示图标（激活时实心晴空蓝，悬停时晴空蓝，默认静默灰蓝）。
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            cx = float(rect.right() - 11)
            cy = float(rect.center().y()) + 0.5
            if active:
                triangle = QPolygonF([
                    QPointF(cx - 3.6, cy - 1.8),
                    QPointF(cx + 3.6, cy - 1.8),
                    QPointF(cx, cy + 2.4),
                ])
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(theme.ACCENT))
                painter.drawPolygon(triangle)
            else:
                chevron = QPainterPath()
                chevron.moveTo(cx - 3.4, cy - 1.5)
                chevron.lineTo(cx, cy + 2.0)
                chevron.lineTo(cx + 3.4, cy - 1.5)
                chevron_color = QColor(theme.ACCENT) if hovered else QColor(theme.TEXT_MUTED)
                painter.setPen(QPen(chevron_color, 1.5, Qt.PenStyle.SolidLine,
                                    Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(chevron)
            painter.restore()
            return

        if logicalIndex in self._sort_columns:
            hovered = self._hovered_column == logicalIndex
            is_sorted = self.isSortIndicatorShown() and self.sortIndicatorSection() == logicalIndex
            painter.save()
            bg = theme.HEADER_CELL_HOVER_BG if hovered else theme.HEADER_CELL_BG
            self._paint_chrome(painter, rect, logicalIndex, bg=bg)
            painter.setFont(self._header_font(painter))
            text_color = QColor(theme.ACCENT) if (is_sorted or hovered) else QColor(theme.HEADER_CELL_FG)
            painter.setPen(text_color)
            text_rect = QRect(rect.left() + 8, rect.top(), max(0, rect.width() - 26), rect.height())
            elided = painter.fontMetrics().elidedText(
                self._base_label(logicalIndex), Qt.TextElideMode.ElideRight, text_rect.width()
            )
            painter.drawText(text_rect, self._header_alignment(logicalIndex), elided)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            cx = float(rect.right() - 11)
            cy = float(rect.center().y()) + 0.5
            if is_sorted:
                ascending = self.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
                arrow = QPainterPath()
                if ascending:
                    arrow.moveTo(cx - 3.4, cy + 1.6)
                    arrow.lineTo(cx, cy - 2.0)
                    arrow.lineTo(cx + 3.4, cy + 1.6)
                else:
                    arrow.moveTo(cx - 3.4, cy - 1.6)
                    arrow.lineTo(cx, cy + 2.0)
                    arrow.lineTo(cx + 3.4, cy - 1.6)
                painter.setPen(QPen(QColor(theme.ACCENT), 1.6, Qt.PenStyle.SolidLine,
                                    Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(arrow)
            elif hovered:
                up = QPainterPath()
                up.moveTo(cx - 2.6, cy - 1.2)
                up.lineTo(cx, cy - 3.6)
                up.lineTo(cx + 2.6, cy - 1.2)
                down = QPainterPath()
                down.moveTo(cx - 2.6, cy + 1.2)
                down.lineTo(cx, cy + 3.6)
                down.lineTo(cx + 2.6, cy + 1.2)
                painter.setPen(QPen(QColor(theme.TEXT_MUTED), 1.3, Qt.PenStyle.SolidLine,
                                    Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(up)
                painter.drawPath(down)
            painter.restore()
            return

        painter.save()
        self._paint_chrome(painter, rect, logicalIndex, bg=theme.HEADER_CELL_BG)
        painter.setFont(self._header_font(painter))
        painter.setPen(QColor(theme.HEADER_CELL_FG))
        text_rect = QRect(rect.left() + 8, rect.top(), max(0, rect.width() - 16), rect.height())
        elided = painter.fontMetrics().elidedText(
            self._base_label(logicalIndex), Qt.TextElideMode.ElideRight, text_rect.width()
        )
        painter.drawText(text_rect, self._header_alignment(logicalIndex), elided)
        painter.restore()

    def _near_edge(self, pos_x, column):
        left = self.sectionViewportPosition(column)
        right = left + self.sectionSize(column)
        return (pos_x - left) <= 4 or (right - pos_x) <= 4

    def open_filter_menu(self, column):
        if column not in self._filter_columns:
            return
        menu = QMenu(self)
        menu.setMinimumWidth(max(130, self.sectionSize(column)))
        current = self._selected.get(column)
        all_action = menu.addAction('全部')
        all_action.setCheckable(True)
        all_action.setChecked(current is None)
        all_action.triggered.connect(lambda: self.set_filter_value(column, None))
        options = self._options.get(column, [])
        if options:
            menu.addSeparator()
            for option in options:
                action = menu.addAction(option)
                action.setCheckable(True)
                action.setChecked(option == current)
                action.triggered.connect(lambda checked=False, value=option: self.set_filter_value(column, value))
        else:
            menu.addSeparator()
            empty = menu.addAction('（暂无可选项）')
            empty.setEnabled(False)
        pos = self.viewport().mapToGlobal(QPoint(self.sectionViewportPosition(column), self.height()))
        menu.exec(pos)
        menu.deleteLater()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            pos = event.position().toPoint()
            column = self.logicalIndexAt(pos)
            if column == self._checkable_column and not self._near_edge(pos.x(), column):
                self.toggled.emit(self._check_state != Qt.CheckState.Checked)
                event.accept()
                return
            if column in self._filter_columns and not self._near_edge(pos.x(), column):
                self.open_filter_menu(column)
                event.accept()
                return
            if column in self._sort_columns and not self._near_edge(pos.x(), column):
                self.sort_requested.emit(column)
                event.accept()
                return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        pos = event.position().toPoint()
        column = self.logicalIndexAt(pos)
        interactive = (column == self._checkable_column or column in self._filter_columns
                       or column in self._sort_columns)
        hovered = column if (interactive and not self._near_edge(pos.x(), column)) else -1
        if hovered != self._hovered_column:
            self._hovered_column = hovered
            self.viewport().update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        if self._hovered_column != -1:
            self._hovered_column = -1
            self.viewport().update()
        super().leaveEvent(event)
