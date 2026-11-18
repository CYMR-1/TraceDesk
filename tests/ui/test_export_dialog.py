"""导出后操作：本地路径、失败反馈和部分导出说明。"""
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialog

from forensic.paths import ROOT
from forensic.ui.views import ExportResultDialog
from tests.ui.test_gui import QtTests


class ExportDialogTests(QtTests):
    def dialog(self):
        root, app = self.controller()
        work = ROOT / '.test-work'
        work.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=work)
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / '导出 #1 & 副本.txt'
        path.write_text('测试内容', encoding='utf-8')
        dialog = ExportResultDialog(root, path)
        self.addCleanup(dialog.deleteLater)
        self.addCleanup(dialog.close)
        dialog.show()
        self.qt_app.processEvents()
        return dialog, path

    def test_open_actions_pass_local_urls_and_keep_dialog_open(self):
        dialog, path = self.dialog()
        with patch('forensic.ui.views.QDesktopServices.openUrl', return_value=True) as open_url:
            for button, target in ((dialog.open_file_button, path),
                                   (dialog.open_folder_button, path.parent)):
                QTest.mouseClick(button, Qt.MouseButton.LeftButton)
                url = open_url.call_args.args[0]
                self.assertTrue(url.isLocalFile())
                self.assertEqual(Path(url.toLocalFile()), target)
                self.assertTrue(dialog.isVisible())
            self.assertEqual(open_url.call_count, 2)
        dialog.ok_button.setFocus()
        QTest.keyClick(dialog, Qt.Key.Key_Return)
        self.assertEqual(dialog.result(), QDialog.DialogCode.Accepted)
        self.assertFalse(dialog.isVisible())

    def test_missing_file_reports_error_but_folder_can_still_open(self):
        dialog, path = self.dialog()
        path.unlink()
        with patch('forensic.ui.views.QDesktopServices.openUrl', return_value=True) as open_url, \
                patch('forensic.ui.views.QMessageBox.warning') as warning:
            dialog.open_file_button.click()
            open_url.assert_not_called()
            self.assertIn(str(path), warning.call_args.args[2])
            self.assertTrue(dialog.isVisible())
            dialog.open_folder_button.click()
            self.assertEqual(Path(open_url.call_args.args[0].toLocalFile()), path.parent)

    def test_system_open_failure_reports_target_and_keeps_dialog_open(self):
        dialog, path = self.dialog()
        with patch('forensic.ui.views.QDesktopServices.openUrl', return_value=False), \
                patch('forensic.ui.views.QMessageBox.warning') as warning:
            dialog.open_file_button.click()
            self.assertIn('系统未能打开', warning.call_args.args[2])
            self.assertIn(str(path), warning.call_args.args[2])
            self.assertTrue(dialog.isVisible())

    def test_export_callback_uses_exported_path_and_preserves_partial_note(self):
        root, app = self.controller()
        path = ROOT / '.test-work' / '导出副本.txt'
        entry = dict(mode='r/r', size=10, deleted=True, directory=False)
        app.selected_entry = Mock(return_value=entry)
        app.case = Mock()
        app.case.export.return_value = path
        app.task = Mock()
        for size, title in ((10, '导出成功'), (4, '部分导出')):
            with self.subTest(size=size):
                record = dict(path=str(path), size=size, recorded_size=10, deleted=True,
                              inode='7', read_note='簇链读取说明')
                app.case.data = dict(exports=[record])
                with patch('forensic.features.export.ExportResultDialog') as result_dialog:
                    app.export()
                    _, work, callback = app.task.call_args.args
                    self.assertEqual(work(), path)
                    callback(path)
                    args = result_dialog.call_args.args
                    self.assertEqual(args[:3], (root, path, title))
                    self.assertIn(f'{size} / 10 字节', args[3])
                    self.assertIn('簇链读取说明', args[3])
                    result_dialog.return_value.exec.assert_called_once()
