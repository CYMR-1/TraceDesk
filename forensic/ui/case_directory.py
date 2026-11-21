"""选择新案件的完整地址。目录树选择父目录，地址栏保留可编辑的案件名。"""
from pathlib import Path
from PySide6.QtCore import QDir
from PySide6.QtWidgets import (
    QDialog, QFileSystemModel, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QTreeView, QVBoxLayout, QWidget,
)

from ..core.case import windows_filename
from . import theme
from .delegates import ForensicItemDelegate
from .metrics import CONTROL_GAP, DIALOG_MARGIN, ROW_HEIGHT_TREE


def choose_case_directory(parent, suggested):
    dialog = QDialog(parent)
    dialog.setWindowTitle('选择案件目录')
    dialog.resize(640, 420)

    outer = QVBoxLayout(dialog)
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(0)

    body = QWidget(dialog)
    layout = QVBoxLayout(body)
    layout.setContentsMargins(DIALOG_MARGIN, 18, DIALOG_MARGIN, 16)
    layout.setSpacing(10)

    hint = QLabel('选择上级目录，或直接修改下方的完整地址。', body)
    hint.setProperty('role', 'muted')
    layout.addWidget(hint)

    model = QFileSystemModel(dialog)
    model.setFilter(QDir.Filter.AllDirs | QDir.Filter.Drives | QDir.Filter.NoDotAndDotDot)
    model.setRootPath('')

    tree = QTreeView(body)
    tree.setModel(model)
    tree.setHeaderHidden(True)
    tree.setUniformRowHeights(True)
    tree.setItemDelegate(ForensicItemDelegate(tree, accent_column=0, row_height=ROW_HEIGHT_TREE))
    for column in range(1, model.columnCount()):
        tree.hideColumn(column)
    index = model.index(str(suggested.parent))
    tree.setCurrentIndex(index)
    tree.scrollTo(index)
    layout.addWidget(tree, 1)

    addr_label = QLabel('案件目录地址', body)
    addr_label.setProperty('role', 'section')
    layout.addWidget(addr_label)

    address = QLineEdit(str(suggested), body)
    address.setFont(theme.mono_font(9.5))
    address.setClearButtonEnabled(True)
    addr_label.setBuddy(address)
    layout.addWidget(address)

    tree.clicked.connect(lambda idx: address.setText(str(
        Path(model.filePath(idx)) / (Path(address.text()).name or suggested.name))))

    outer.addWidget(body, 1)

    footer = QFrame(dialog)
    footer.setObjectName('dialogFooterBar')
    row = QHBoxLayout(footer)
    row.setContentsMargins(DIALOG_MARGIN, 12, DIALOG_MARGIN, 12)
    row.setSpacing(CONTROL_GAP)
    cancel = QPushButton('取消', footer)
    cancel.setAutoDefault(False)
    create = QPushButton('创建案件', footer)
    create.setProperty('role', 'accent')
    create.setDefault(True)
    row.addWidget(cancel)
    row.addStretch(1)
    row.addWidget(create)
    outer.addWidget(footer)

    cancel.clicked.connect(dialog.reject)

    def confirm():
        path = Path(address.text().strip())
        if not path.is_absolute() or not path.name or path.name != windows_filename(path.name):
            QMessageBox.warning(dialog, '地址无效', '请输入含有效案件文件夹名称的完整路径。')
            return
        dialog.accept()

    create.clicked.connect(confirm)
    address.setFocus()
    address.setSelection(len(str(suggested.parent)) + 1, len(suggested.name))
    return Path(address.text().strip()) if dialog.exec() else None
