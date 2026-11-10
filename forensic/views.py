"""原生 Qt 桌面组件；组件处理显示和输入，不承担取证业务。"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from .tsk import ROOT


class ReadOnlyTextPanel(QWidget):
    """可选择、复制并支持双向滚动的只读文字区。"""

    def __init__(self, parent):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.text = QPlainTextEdit(self)
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.text)

    def set_text(self, value):
        self.text.setPlainText(value)


class NewCaseDialog(QDialog):
    """收集新案件信息，创建工作交给注入的回调完成。"""

    def __init__(self, parent, on_create):
        super().__init__(parent)
        self.on_create = on_create
        self.setWindowTitle('新建取证案件')
        self.setModal(True)
        self.setMinimumWidth(460)
        content = QVBoxLayout(self)
        content.setContentsMargins(24, 24, 24, 24)
        content.setSpacing(16)
        title = QLabel('填写案件信息', self)
        title.setObjectName('sectionTitle')
        content.addWidget(title)
        subtitle = QLabel('选择案件库，用于保存导出副本、日志和报告。', self)
        subtitle.setObjectName('muted')
        subtitle.setWordWrap(True)
        content.addWidget(subtitle)
        form = QFormLayout()
        form.setSpacing(12)
        self.fields = []
        for label in ('案件编号', '取证人员', '取证对象'):
            entry = QLineEdit(self)
            entry.setClearButtonEnabled(True)
            form.addRow(label, entry)
            self.fields.append(entry)
        content.addLayout(form)
        buttons = QDialogButtonBox(self)
        cancel = buttons.addButton('取消', QDialogButtonBox.ButtonRole.RejectRole)
        create = QPushButton('选择案件库并创建', self)
        create.setProperty('accent', True)
        create.setDefault(True)
        buttons.addButton(create, QDialogButtonBox.ButtonRole.AcceptRole)
        cancel.clicked.connect(self.reject)
        create.clicked.connect(self.create)
        content.addWidget(buttons)
        self.fields[0].setFocus(Qt.FocusReason.OtherFocusReason)

    def create(self):
        values = [entry.text().strip() for entry in self.fields]
        if not all(values):
            QMessageBox.warning(self, '信息不全', '请填写所有案件信息。')
            return
        folder = QFileDialog.getExistingDirectory(
            self, '选择案件库目录', str(ROOT / 'cases'),
            QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog)
        if not folder:
            return
        try:
            self.on_create(folder, *values)
        except Exception as error:
            QMessageBox.critical(self, '创建失败', str(error))
            return
        self.accept()
