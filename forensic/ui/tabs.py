"""标签与操作控件共享一行，避免原生角落区域裁切控件或绘制多余基线。"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QPushButton, QStackedWidget, QTabBar, QVBoxLayout, QWidget,
)

from . import theme
from .metrics import TAB_BAR_HEIGHT


class _TabBar(QTabBar):
    row_height = 0

    def tabSizeHint(self, index):
        size = super().tabSizeHint(index)
        size.setHeight(max(size.height(), self.row_height))
        return size


class TabbedView(QWidget):
    currentChanged = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._strip = QFrame(self)
        self._strip.setObjectName('tabStrip')
        self._bar = _TabBar(self._strip)
        self._bar.setDocumentMode(True)
        self._bar.setDrawBase(False)
        self._bar.setExpanding(False)
        self._bar.setUsesScrollButtons(True)
        self._pages = QStackedWidget(self)
        self._controls = ()
        self._actions = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._row = QHBoxLayout(self._strip)
        self._row.setContentsMargins(10, 0, 12, 0)
        self._row.setSpacing(0)
        self._row.addWidget(self._bar, 1)

        layout.addWidget(self._strip)
        layout.addWidget(self._pages, 1)
        self._bar.currentChanged.connect(self._pages.setCurrentIndex)
        self._bar.currentChanged.connect(self.currentChanged)

    def addTab(self, page, title):
        self._pages.addWidget(page)
        index = self._bar.addTab(title)
        self._align_height()
        return index

    def set_actions(self, widget, controls):
        self._actions, self._controls = widget, tuple(controls)
        widget.setParent(self._strip)
        self._row.addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)
        self._align_height()

    def _align_height(self):
        # 字体与局部样式须先应用，否则首次装配会缓存主题默认的较大标签高度。
        is_preview = self._bar.objectName() == 'previewTabs'
        strip_name = 'previewModeBar' if is_preview else 'tabStrip'
        if self._strip.objectName() != strip_name:
            self._strip.setObjectName(strip_name)
            theme.repolish(self._strip)
        if is_preview:
            self._row.setContentsMargins(1, 0, 12, 0)
        else:
            self._row.setContentsMargins(3, 0, 12, 0)

        self._bar.ensurePolished()
        for control in self._controls:
            control.ensurePolished()

        heights = [QTabBar.tabSizeHint(self._bar, i).height() for i in range(self._bar.count())]
        base_height = 32 if is_preview else TAB_BAR_HEIGHT
        control_heights = []
        for control in self._controls:
            if not is_preview and isinstance(control, QPushButton):
                control.setFixedHeight(28)
                control_heights.append(28)
            else:
                control_heights.append(control.sizeHint().height())

        height = max([base_height, *heights, *(h + 6 for h in control_heights)])
        self._bar.row_height = height
        self._bar.setFixedHeight(height)
        if self._actions is not None:
            self._actions.setFixedHeight(height)
        # 预留 1px 底部分隔线，避免裁剪标签底部的高亮指示条。
        self._strip.setFixedHeight(height + 1)
        self._bar.updateGeometry()

    def tabBar(self):
        return self._bar

    def strip(self):
        return self._strip

    def currentIndex(self):
        return self._bar.currentIndex()

    def currentWidget(self):
        return self._pages.currentWidget()

    def setCurrentIndex(self, index):
        self._bar.setCurrentIndex(index)
