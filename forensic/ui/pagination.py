"""分页视图共用的页码跳转入口，界面页码从 1 开始。"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QInputDialog, QLabel


class PageLabel(QLabel):
    def __init__(self, jump):
        super().__init__()
        self.jump = jump
        self.current = self.total = 1
        self.setToolTip('双击页码，输入要跳转的页数')

    def set_pages(self, current, total, *, show_text=True):
        self.current, self.total = current, max(1, total)
        if show_text:
            self.setText(f'第 {current} / {self.total} 页')

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.total > 1:
            prompt = f'目标页（1–{self.total}）'
            if self.total <= 2147483647:
                number, accepted = QInputDialog.getInt(self, '跳转页码', prompt, self.current, 1, self.total)
            else:
                value, accepted = QInputDialog.getText(self, '跳转页码', prompt, text=str(self.current))
                value = value.strip()
                number = int(value) if value.isascii() and value.isdigit() and len(value) < 21 else 0
            if accepted and 1 <= number <= self.total:
                self.jump(number - 1)
            event.accept()
            return
        super().mouseDoubleClickEvent(event)
