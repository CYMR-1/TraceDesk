"""分页视图共用的页码跳转入口，界面页码从 1 开始。"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox,
    QVBoxLayout, QWidget,
)

from . import theme
from .metrics import CONTROL_GAP, DIALOG_MARGIN, SECTION_GAP


class PageJumpDialog(QDialog):
    def __init__(self, parent, current, total):
        super().__init__(parent)
        self.setWindowTitle('跳转页码')
        self.setMinimumWidth(320)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        body = QWidget(self)
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(DIALOG_MARGIN, 18, DIALOG_MARGIN, 16)
        body_layout.setSpacing(SECTION_GAP)
        prompt = QLabel(f'目标页（1–{total}）')
        prompt.setProperty('role', 'section')
        body_layout.addWidget(prompt)
        if total <= 2147483647:
            self.field = QSpinBox()
            self.field.setRange(1, total)
            self.field.setValue(current)
        else:
            self.field = QLineEdit(str(current))
            self.field.setMaxLength(len(str(total)))
        self.field.setFont(theme.mono_font(10.0, cjk_fallback=False))
        prompt.setBuddy(self.field)
        body_layout.addWidget(self.field)
        root.addWidget(body)

        footer = QFrame(self)
        footer.setObjectName('dialogFooterBar')
        buttons = QHBoxLayout(footer)
        buttons.setContentsMargins(DIALOG_MARGIN, 10, DIALOG_MARGIN, 10)
        buttons.setSpacing(CONTROL_GAP)
        cancel = QPushButton('Cancel')
        cancel.setAutoDefault(False)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        buttons.addStretch(1)
        confirm = QPushButton('OK')
        confirm.setProperty('role', 'accent')
        confirm.setDefault(True)
        confirm.clicked.connect(self.accept)
        buttons.addWidget(confirm)
        root.addWidget(footer)

        if isinstance(self.field, QLineEdit):
            self.field.textChanged.connect(lambda s: confirm.setEnabled(
                s.isascii() and s.isdigit() and 1 <= int(s) <= total))
        self.adjustSize()
        self.resize(max(320, self.width()), self.sizeHint().height())
        self.field.setFocus()
        self.field.selectAll()

    def number(self):
        return self.field.value() if isinstance(self.field, QSpinBox) else int(self.field.text())


class PageLabel(QLabel):
    def __init__(self, jump):
        super().__init__()
        self.jump = jump
        self.current = self.total = 1
        self.setProperty('role', 'pageBadge')
        self.setToolTip('双击页码，输入要跳转的页数')

    def set_pages(self, current, total, *, show_text=True):
        self.current, self.total = current, max(1, total)
        if self.total > 1:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
        else:
            self.unsetCursor()
        if show_text:
            self.setText(f'第 {current} / {self.total} 页')

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.total > 1:
            dialog = PageJumpDialog(self, self.current, self.total)
            try:
                if dialog.exec() == QDialog.DialogCode.Accepted:
                    self.jump(dialog.number() - 1)
            finally:
                dialog.deleteLater()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)
