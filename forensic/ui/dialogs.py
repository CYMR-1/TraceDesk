"""公共输入弹窗：取消在底部左侧，确认操作在右侧。"""
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGridLayout, QHBoxLayout,
    QInputDialog, QLineEdit, QWidget,
)


RAW_IMAGE_FILTER = 'RAW 或 EWF 首段 (*.dd *.raw *.img *.ima *.bin *.dsk *.image *.flp *.vfd *.E01 *.e01)'


def cancel_on_left(dialog):
    """将 Qt 自带按钮区改为横跨窗口底部的一行，保留原确认按钮及信号。"""
    box = dialog.findChild(QDialogButtonBox)
    if box is None or len(box.buttons()) < 2 or dialog.findChild(QWidget, 'dialogFooter'):
        return
    cancel = next((button for button in box.buttons()
                   if box.buttonRole(button) == QDialogButtonBox.ButtonRole.RejectRole), None)
    if cancel is None:
        return
    layout = dialog.layout()
    layout.removeWidget(box)
    footer = QWidget(dialog)
    footer.setObjectName('dialogFooter')
    row = QHBoxLayout(footer)
    row.setContentsMargins(0, 0, 0, 0)
    box.removeButton(cancel)
    cancel.setText('取消')
    cancel.setAutoDefault(False)
    cancel.clicked.connect(dialog.reject)
    row.addWidget(cancel)
    row.addStretch(1)
    box.setOrientation(Qt.Orientation.Horizontal)
    row.addWidget(box)
    if isinstance(layout, QGridLayout):
        layout.addWidget(footer, layout.rowCount(), 0, 1, layout.columnCount())
    else:
        layout.addWidget(footer)


class OpenFileDialog(QFileDialog):
    def __init__(self, parent, title, directory='', file_filter='所有文件 (*)'):
        super().__init__(parent, title)
        self.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        self.setFileMode(QFileDialog.FileMode.ExistingFile)
        self.setAcceptMode(QFileDialog.AcceptMode.AcceptOpen)
        self.setDirectory(directory)
        self.setNameFilter(file_filter)
        self.setLabelText(QFileDialog.DialogLabel.Accept, '打开')
        self.setLabelText(QFileDialog.DialogLabel.Reject, '取消')
        cancel_on_left(self)


def choose_file(parent, title, directory='', file_filter='所有文件 (*)'):
    dialog = OpenFileDialog(parent, title, directory, file_filter)
    try:
        return dialog.selectedFiles()[0] if dialog.exec() == QDialog.DialogCode.Accepted else ''
    finally:
        dialog.deleteLater()


class NoteDialog(QInputDialog):
    def __init__(self, parent, title, label):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setLabelText(label)
        self.setInputMode(QInputDialog.InputMode.TextInput)
        self.setOption(QInputDialog.InputDialogOption.UsePlainTextEditForTextInput, True)
        self.setOkButtonText('保存')
        self.setCancelButtonText('取消')
        self.resize(540, 300)
        cancel_on_left(self)


def enter_note(parent, title, label):
    dialog = NoteDialog(parent, title, label)
    try:
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        return dialog.textValue(), accepted
    finally:
        dialog.deleteLater()


def edit_evidence_source(parent, field_labels, provenance):
    """登记证据来源与交付方 SHA-256 的公共弹窗。"""
    dialog = QDialog(parent)
    dialog.setWindowTitle('登记证据来源')
    dialog.setMinimumWidth(580)
    form = QFormLayout(dialog)
    form.setContentsMargins(16, 14, 16, 14)
    form.setSpacing(10)
    fields = {}
    for key, label in field_labels.items():
        fields[key] = QLineEdit((provenance or {}).get(key, ''))
        form.addRow(label, fields[key])
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    form.addRow(buttons)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    dialog.resize(600, 270)
    try:
        if dialog.exec():
            return {key: field.text() for key, field in fields.items()}
        return None
    finally:
        dialog.deleteLater()
