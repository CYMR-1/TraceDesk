"""选择新案件的完整地址。目录树选择父目录，地址栏保留可编辑的案件名。"""
from pathlib import Path
from PySide6.QtCore import QDir
from PySide6.QtWidgets import (QDialog, QFileSystemModel, QLabel, QLineEdit, QPushButton,
                               QTreeView, QVBoxLayout, QHBoxLayout, QMessageBox)

from ..core.case import windows_filename


def choose_case_directory(parent, suggested):
    dialog = QDialog(parent)
    dialog.setWindowTitle('选择案件目录')
    dialog.resize(620, 400)
    layout = QVBoxLayout(dialog)
    layout.addWidget(QLabel('选择上级目录，或直接修改下方的完整地址。'))
    model = QFileSystemModel(dialog)
    model.setFilter(QDir.Filter.AllDirs | QDir.Filter.Drives | QDir.Filter.NoDotAndDotDot)
    model.setRootPath('')
    tree = QTreeView()
    tree.setModel(model)
    tree.setHeaderHidden(True)
    for column in range(1, model.columnCount()):
        tree.hideColumn(column)
    index = model.index(str(suggested.parent))
    tree.setCurrentIndex(index)
    tree.scrollTo(index)
    layout.addWidget(tree)
    layout.addWidget(QLabel('案件目录地址'))
    address = QLineEdit(str(suggested))
    layout.addWidget(address)
    tree.clicked.connect(lambda index: address.setText(str(
        Path(model.filePath(index)) / (Path(address.text()).name or suggested.name))))
    row = QHBoxLayout()
    row.addStretch()
    cancel, create = QPushButton('取消'), QPushButton('创建案件')
    row.addWidget(cancel)
    row.addWidget(create)
    layout.addLayout(row)
    cancel.clicked.connect(dialog.reject)

    def confirm():
        path = Path(address.text().strip())
        if not path.is_absolute() or not path.name or path.name != windows_filename(path.name):
            QMessageBox.warning(dialog, '地址无效', '请输入含有效案件文件夹名称的完整路径。')
            return
        dialog.accept()

    create.clicked.connect(confirm)
    create.setDefault(True)
    address.setFocus()
    address.setSelection(len(str(suggested.parent)) + 1, len(suggested.name))
    return Path(address.text().strip()) if dialog.exec() else None
