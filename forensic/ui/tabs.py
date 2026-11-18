"""标签与操作控件共享一行，避免原生角落区域裁切控件或绘制多余基线。"""
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QHBoxLayout, QStackedWidget, QTabBar, QVBoxLayout, QWidget


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
        self._bar = _TabBar(self)
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
        self._row = QHBoxLayout()
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(0)
        self._row.addWidget(self._bar, 1)
        layout.addLayout(self._row)
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
        self._row.addWidget(widget)
        self._align_height()

    def _align_height(self):
        # 字体与局部样式须先应用，否则首次装配会缓存主题默认的较大标签高度。
        self._bar.ensurePolished()
        for control in self._controls:
            control.ensurePolished()
        heights = [QTabBar.tabSizeHint(self._bar, i).height() for i in range(self._bar.count())]
        heights.extend(control.sizeHint().height() for control in self._controls)
        height = max(heights, default=0)
        self._bar.row_height = height
        self._bar.setFixedHeight(height)
        for control in self._controls:
            control.setFixedHeight(height)
        if self._actions:
            self._actions.setFixedHeight(height)
        self._bar.updateGeometry()

    def tabBar(self):
        return self._bar

    def currentIndex(self):
        return self._bar.currentIndex()

    def setCurrentIndex(self, index):
        self._bar.setCurrentIndex(index)
