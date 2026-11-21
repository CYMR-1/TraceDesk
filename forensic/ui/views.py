"""原生 Qt 桌面组件；组件处理显示和输入，不承担取证业务。"""
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPlainTextEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget,
)

from ..core.case import case_folder_name
from ..paths import CASES_DIR
from . import theme
from .case_directory import choose_case_directory
from .icons import ui_icon
from .metrics import CONTROL_GAP, DIALOG_MARGIN


class ReadOnlyTextPanel(QWidget):
    """可选择、复制并支持双向滚动的只读文字区。"""

    def __init__(self, parent):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.text = QPlainTextEdit(self)
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setProperty('surface', 'raw')
        self.text.setFont(theme.mono_font(9.5))
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
        self.setMinimumWidth(540)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        body = QWidget(self)
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(DIALOG_MARGIN, DIALOG_MARGIN, DIALOG_MARGIN, DIALOG_MARGIN)
        body_layout.setSpacing(16)

        is_partial = title == '部分导出'
        icon_widget = QLabel(body)
        icon_widget.setFixedSize(36, 36)
        vector_icon = (
            ui_icon('warning', color=theme.WARN_FG, size=36, fill=theme.WARN_BG)
            if is_partial
            else ui_icon('check_shield', color=theme.OK_FG, size=36, fill=theme.OK_BG)
        )
        icon_widget.setPixmap(vector_icon.pixmap(36, 36))
        body_layout.addWidget(icon_widget, 0, Qt.AlignmentFlag.AlignTop)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(8)

        heading = QLabel(title, body)
        heading.setFont(theme.ui_font(11.5, QFont.Weight.DemiBold))
        text_col.addWidget(heading)

        self.message = QLabel('\n\n'.join(filter(None, (str(self.path), note))), body)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        self.message.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.message.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self.message.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        text_col.addWidget(self.message)
        body_layout.addLayout(text_col, 1)
        layout.addWidget(body, 1)

        footer = QFrame(self)
        footer.setObjectName('dialogFooterBar')
        buttons = QHBoxLayout(footer)
        buttons.setContentsMargins(DIALOG_MARGIN, 12, DIALOG_MARGIN, 12)
        buttons.setSpacing(CONTROL_GAP)
        self.open_file_button = QPushButton('打开文件', footer)
        self.open_folder_button = QPushButton('打开文件所在文件夹', footer)
        for button in (self.open_file_button, self.open_folder_button):
            button.setAutoDefault(False)
            buttons.addWidget(button)
        buttons.addStretch(1)
        self.open_file_button.clicked.connect(lambda: self._open_target(folder=False))
        self.open_folder_button.clicked.connect(lambda: self._open_target(folder=True))
        self.ok_button = QPushButton('OK', footer)
        self.ok_button.setObjectName('exportOk')
        self.ok_button.setDefault(True)
        self.ok_button.clicked.connect(self.accept)
        buttons.addWidget(self.ok_button)
        layout.addWidget(footer)

        self.ok_button.setFocus(Qt.FocusReason.OtherFocusReason)
        self.ensurePolished()
        target_height = max(layout.totalHeightForWidth(self.minimumWidth()), self.sizeHint().height())
        self.resize(self.minimumWidth(), target_height)

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
        self.setMinimumWidth(480)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        body = QWidget(self)
        content = QVBoxLayout(body)
        content.setContentsMargins(24, 22, 24, 20)
        content.setSpacing(14)

        header = QVBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(4)
        title = QLabel('填写案件信息', body)
        title.setObjectName('sectionTitle')
        header.addWidget(title)
        subtitle = QLabel('下一步可选择位置并修改案件文件夹名称。', body)
        subtitle.setObjectName('muted')
        subtitle.setWordWrap(True)
        header.addWidget(subtitle)
        content.addLayout(header)

        form = QFormLayout()
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.fields = []
        field_specs = (
            ('案件编号', '例如：CASE-2026-001'),
            ('取证人员', '取证人员姓名'),
            ('取证对象', '检材或设备说明'),
        )
        for label_text, placeholder in field_specs:
            entry = QLineEdit(body)
            entry.setPlaceholderText(placeholder)
            entry.setClearButtonEnabled(True)
            form.addRow(label_text, entry)
            self.fields.append(entry)
        content.addLayout(form)
        outer.addWidget(body, 1)

        footer = QFrame(self)
        footer.setObjectName('dialogFooterBar')
        buttons = QHBoxLayout(footer)
        buttons.setContentsMargins(24, 12, 24, 12)
        buttons.setSpacing(CONTROL_GAP)
        cancel = QPushButton('取消', footer)
        cancel.setAutoDefault(False)
        buttons.addWidget(cancel)
        buttons.addStretch(1)
        create = QPushButton('选择案件目录', footer)
        create.setProperty('role', 'accent')
        create.setProperty('accent', True)
        create.setDefault(True)
        buttons.addWidget(create)
        cancel.clicked.connect(self.reject)
        create.clicked.connect(self.create)
        outer.addWidget(footer)

        self.fields[0].setFocus(Qt.FocusReason.OtherFocusReason)

    def create(self):
        values = [entry.text().strip() for entry in self.fields]
        if not all(values):
            QMessageBox.warning(self, '信息不全', '请填写所有案件信息。')
            return
        folder = choose_case_directory(self, CASES_DIR / case_folder_name(*values))
        if folder is None:
            return
        try:
            self.on_create(folder.parent, *values, folder_name=folder.name)
        except Exception as error:
            QMessageBox.critical(self, '创建失败', str(error))
            return
        self.accept()
