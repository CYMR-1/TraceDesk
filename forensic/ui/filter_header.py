"""支持表头下拉筛选、全选复选框与指定列排序的表头组件。"""
from PySide6.QtCore import QPoint, QPointF, QRect, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QHeaderView, QMenu


class FilterHeaderView(QHeaderView):
    """统一表头：支持可选首列三态全选框（带字样）、下拉筛选列与正倒序排序列。"""

    toggled = Signal(bool)
    filter_changed = Signal(int, object)
    sort_requested = Signal(int)

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
        size = 17
        # QTreeView::indicator 为 15px 内容 + 1px 边框（总 17px），左起点与行复选框对齐。
        x = rect.left() + 8
        y = rect.top() + (rect.height() - size) // 2
        return QRect(x, y, size, size)

    def _base_label(self, logicalIndex):
        model = self.model()
        if model is None:
            return ''
        value = model.headerData(logicalIndex, self.orientation(), Qt.ItemDataRole.DisplayRole)
        return '' if value is None else str(value)

    def paintSection(self, painter, rect, logicalIndex):
        if logicalIndex == self._checkable_column:
            super().paintSection(painter, rect, logicalIndex)
            box = QRectF(self._checkbox_rect(rect)).adjusted(0.5, 0.5, -0.5, -0.5)
            hovered = self._hovered_column == logicalIndex
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            checked = self._check_state != Qt.CheckState.Unchecked
            fill = QColor('#087f6b') if checked else QColor('#ffffff')
            border = QColor('#087f6b') if (checked or hovered) else QColor('#b8c7bf')
            painter.setPen(QPen(border, 1.0))
            painter.setBrush(fill)
            painter.drawRoundedRect(box, 4.0, 4.0)
            if self._check_state == Qt.CheckState.Checked:
                path = QPainterPath()
                path.moveTo(box.left() + box.width() * 0.22, box.top() + box.height() * 0.52)
                path.lineTo(box.left() + box.width() * 0.42, box.top() + box.height() * 0.72)
                path.lineTo(box.left() + box.width() * 0.78, box.top() + box.height() * 0.30)
                pen = QPen(QColor('#ffffff'), 1.8, Qt.PenStyle.SolidLine,
                           Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
                painter.setPen(pen)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.drawPath(path)
            elif self._check_state == Qt.CheckState.PartiallyChecked:
                y = box.center().y()
                pen = QPen(QColor('#ffffff'), 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
                painter.setPen(pen)
                painter.drawLine(QPointF(box.left() + 3.5, y), QPointF(box.right() - 3.5, y))
            if self._check_label:
                font = QFont(painter.font())
                font.setWeight(QFont.Weight.DemiBold)
                painter.setFont(font)
                painter.setPen(QColor('#087f6b') if hovered else QColor('#5b6d64'))
                text_rect = QRect(int(box.right()) + 6, rect.top(), max(0, rect.right() - int(box.right()) - 8), rect.height())
                painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, self._check_label)
            painter.restore()
            return

        if logicalIndex in self._filter_columns:
            selected = self._selected.get(logicalIndex)
            hovered = self._hovered_column == logicalIndex
            active = selected is not None
            painter.save()
            bg = QColor('#e5f4ed') if active else (QColor('#ebf2ee') if hovered else QColor('#f3f6f5'))
            painter.fillRect(rect, bg)
            painter.setPen(QPen(QColor('#dfe7e2'), 1.0))
            painter.drawLine(rect.bottomLeft(), rect.bottomRight())
            if logicalIndex < self.count() - 1:
                painter.setPen(QPen(QColor('#ffffff'), 2.0))
                painter.drawLine(rect.right(), rect.top(), rect.right(), rect.bottom())
            base = self._base_label(logicalIndex)
            label = f'{base}：{selected}' if active else base
            font = QFont(painter.font())
            font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            text_color = QColor('#087f6b') if (active or hovered) else QColor('#5b6d64')
            painter.setPen(text_color)
            text_rect = QRect(rect.left() + 7, rect.top(), max(0, rect.width() - 25), rect.height())
            elided = painter.fontMetrics().elidedText(label, Qt.TextElideMode.ElideRight, text_rect.width())
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elided)
            # 右侧绘制下拉箭头，提示该列可点击下拉筛选。
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            cx = rect.right() - 11
            cy = rect.center().y()
            chevron = QPainterPath()
            chevron.moveTo(cx - 3.5, cy - 1.5)
            chevron.lineTo(cx, cy + 2.2)
            chevron.lineTo(cx + 3.5, cy - 1.5)
            painter.setPen(QPen(text_color, 1.5, Qt.PenStyle.SolidLine,
                                Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawPath(chevron)
            painter.restore()
            return

        super().paintSection(painter, rect, logicalIndex)

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
