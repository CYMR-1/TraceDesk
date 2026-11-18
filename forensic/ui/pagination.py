"""分页视图共用的页码跳转入口，界面页码从 1 开始。"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, QVBoxLayout


class PageJumpDialog(QDialog):
    def __init__(self, parent, current, total):
        super().__init__(parent)
        self.setWindowTitle('跳转页码')
        layout = QVBoxLayout(self)
        prompt = QLabel(f'目标页（1–{total}）')
        layout.addWidget(prompt)
        if total <= 2147483647:
            self.field = QSpinBox()
            self.field.setRange(1, total)
            self.field.setValue(current)
        else:
            self.field = QLineEdit(str(current))
            self.field.setMaxLength(len(str(total)))
        prompt.setBuddy(self.field)
        layout.addWidget(self.field)
        buttons = QHBoxLayout()
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
        layout.addLayout(buttons)
        if isinstance(self.field, QLineEdit):
            self.field.textChanged.connect(lambda s: confirm.setEnabled(
                s.isascii() and s.isdigit() and 1 <= int(s) <= total))
        self.field.setFocus()
        self.field.selectAll()

    def number(self):
        return self.field.value() if isinstance(self.field, QSpinBox) else int(self.field.text())


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
            dialog = PageJumpDialog(self, self.current, self.total)
            try:
                if dialog.exec() == QDialog.DialogCode.Accepted:
                    self.jump(dialog.number() - 1)
            finally:
                dialog.deleteLater()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)
