"""输入弹窗的真实布局、确认/取消行为和文件筛选回归。"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from PySide6.QtCore import QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QLineEdit, QMainWindow, QPushButton

from forensic.paths import ROOT
from forensic.ui.appearance import DesktopAppearance
from forensic.ui.case_directory import choose_case_directory
from forensic.ui.dialogs import OpenFileDialog, NoteDialog, RAW_IMAGE_FILTER, choose_file, enter_note
from forensic.ui.views import NewCaseDialog


class DialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def setUp(self):
        self.root = QMainWindow()
        DesktopAppearance(self.root).configure()
        self.addCleanup(self.root.deleteLater)

    def cancel(self, dialog):
        return next(b for b in dialog.findChildren(QPushButton) if b.text() == '取消')

    def check_positions(self, dialog):
        dialog.show()
        self.qt.processEvents()
        cancel = self.cancel(dialog)
        self.assertTrue(cancel.isVisible())
        others = [b for b in dialog.findChildren(QPushButton) if b is not cancel and b.isVisible()]
        self.assertTrue(others)
        left = cancel.mapTo(dialog, cancel.rect().topLeft())
        self.assertLess(left.x(), dialog.width() / 4)
        self.assertTrue(any(b.mapTo(dialog, b.rect().topLeft()).x() > dialog.width() / 2 for b in others))
        self.assertTrue(any(abs(b.mapTo(dialog, b.rect().topLeft()).y() - left.y()) <= 2 for b in others))
        return cancel

    def test_file_picker_cancel_left_and_accept_selected_raw_file(self):
        dialog = OpenFileDialog(self.root, '选择 RAW 镜像', str(ROOT / 'evidence'), RAW_IMAGE_FILTER)
        self.addCleanup(dialog.deleteLater)
        cancel = self.check_positions(dialog)
        self.assertEqual(len(dialog.nameFilters()), 1)
        self.assertNotIn('所有文件', dialog.nameFilters()[0])
        self.assertIn('*.bin', dialog.nameFilters()[0])
        filename = dialog.findChild(QLineEdit, 'fileNameEdit')
        filename.setFocus()
        QTest.keyClicks(filename, 'demo.dd')
        self.qt.processEvents()
        box = dialog.findChild(QDialogButtonBox)
        accept = next(b for b in box.buttons() if box.buttonRole(b) == QDialogButtonBox.ButtonRole.AcceptRole)
        self.assertTrue(accept.isEnabled())
        accept.click()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Accepted)
        self.assertEqual(Path(dialog.selectedFiles()[0]), ROOT / 'evidence/demo.dd')
        dialog.show()
        self.qt.processEvents()
        cancel.click()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)

    def test_note_buttons_keep_input_accept_and_escape(self):
        dialog = NoteDialog(self.root, '记录取证发现', 'photo.png')
        self.addCleanup(dialog.deleteLater)
        self.check_positions(dialog)
        dialog.setTextValue('图片核查记录')
        save = next(b for b in dialog.findChildren(QPushButton) if b.text() == '保存')
        save.click()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Accepted)
        self.assertEqual(dialog.textValue(), '图片核查记录')
        dialog.show()
        self.qt.processEvents()
        QTest.keyClick(dialog, Qt.Key.Key_Escape)
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)

    def test_new_case_and_directory_cancel_without_creating(self):
        create = Mock()
        dialog = NewCaseDialog(self.root, create)
        self.addCleanup(dialog.deleteLater)
        self.check_positions(dialog).click()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        create.assert_not_called()
        failures = []

        def reject_directory():
            active = self.qt.activeModalWidget()
            try:
                self.check_positions(active).click()
            except Exception as error:
                failures.append(error)
                active.reject()

        with tempfile.TemporaryDirectory(dir=ROOT / '.test-work') as temp:
            suggested = Path(temp) / '新案件'
            QTimer.singleShot(0, reject_directory)
            self.assertIsNone(choose_case_directory(self.root, suggested))
            self.assertFalse(suggested.exists())
        if failures:
            raise failures[0]

    def test_cancel_helpers_return_no_file_or_note(self):
        with patch.object(OpenFileDialog, 'exec', return_value=QDialog.DialogCode.Rejected):
            self.assertEqual(choose_file(self.root, '打开'), '')
        with patch.object(NoteDialog, 'exec', return_value=QDialog.DialogCode.Rejected):
            self.assertEqual(enter_note(self.root, '记录', '文件'), ('', False))
