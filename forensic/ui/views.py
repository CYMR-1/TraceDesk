"""原生 Qt 桌面组件；组件处理显示和输入，不承担取证业务。"""
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QPushButton, QSizePolicy, QStyle, QVBoxLayout, QWidget,
)

from ..paths import CASES_DIR
from .metrics import SECTION_GAP


class ReadOnlyTextPanel(QWidget):
    """可选择、复制并支持双向滚动的只读文字区。"""

    def __init__(self, parent):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, SECTION_GAP, 0, 0)
        self.text = QPlainTextEdit(self)
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.text)

    def set_text(self, value):
        self.text.setPlainText(value)


class ExportResultDialog(QDialog):
    """展示实际导出结果，并通过系统默认程序打开副本或所在目录。"""

    def __init__(self, parent, path, title='导出成功', note=''):
        super().__init__(parent)
        self.path = Path(path).absolute()
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 16)
        layout.setSpacing(18)
        content = QHBoxLayout()
        content.setSpacing(14)
        icon = QLabel()
        icon.setPixmap(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation).pixmap(40, 40))
        content.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        self.message = QLabel('\n\n'.join(filter(None, (str(self.path), note))))
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        self.message.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.message.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse
                                             | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        self.message.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        content.addWidget(self.message, 1)
        layout.addLayout(content)
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.open_file_button = QPushButton('打开文件')
        self.open_folder_button = QPushButton('打开文件所在文件夹')
        for button in (self.open_file_button, self.open_folder_button):
            button.setAutoDefault(False)
            buttons.addWidget(button)
        buttons.addStretch(1)
        self.open_file_button.clicked.connect(lambda: self._open_target(folder=False))
        self.open_folder_button.clicked.connect(lambda: self._open_target(folder=True))
        self.ok_button = QPushButton('OK')
        self.ok_button.setObjectName('exportOk')
        self.ok_button.setDefault(True)
        self.ok_button.clicked.connect(self.accept)
        buttons.addWidget(self.ok_button)
        layout.addLayout(buttons)
        self.ok_button.setFocus(Qt.FocusReason.OtherFocusReason)
        self.ensurePolished()
        self.resize(self.minimumWidth(), layout.totalHeightForWidth(self.minimumWidth()))

    def _open_target(self, *, folder):
        target = self.path.parent if folder else self.path
        kind = '文件夹' if folder else '文件'
        if not (target.is_dir() if folder else target.is_file()):
            QMessageBox.warning(self, '无法打开', f'{kind}不存在或已被移动：\n{target}')
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(target))):
            QMessageBox.warning(self, '无法打开', f'系统未能打开此{kind}：\n{target}')


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
            self, '选择案件库目录', str(CASES_DIR),
            QFileDialog.Option.ShowDirsOnly | QFileDialog.Option.DontUseNativeDialog)
        if not folder:
            return
        try:
            self.on_create(folder, *values)
        except Exception as error:
            QMessageBox.critical(self, '创建失败', str(error))
            return
        self.accept()
