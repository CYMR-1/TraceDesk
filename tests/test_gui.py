"""Qt 控制器、窗口生命周期及文件树刷新回归。"""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QDialog, QMainWindow

from forensic.gui import App
from forensic.tasks import TaskResult
from forensic.views import NewCaseDialog


class QtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication([])
        cls.qt_app.setQuitOnLastWindowClosed(False)

    def controller(self):
        root = QMainWindow()
        app = App(root)
        self.addCleanup(lambda: QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete))
        self.addCleanup(root.deleteLater)
        self.addCleanup(app._shutdown)
        return root, app


class ControllerTests(QtTests):
    def test_callback_failure_keeps_polling_and_restores_controls(self):
        root, app = self.controller()
        app.case = Mock()
        callback = Mock(side_effect=ValueError('结果无法显示'))
        app.runner = SimpleNamespace(busy=False, poll=Mock(
            return_value=TaskResult(value='结果', callback=callback)))
        app.view.set_busy(True)
        with patch('forensic.gui.QMessageBox.critical') as error_dialog:
            app.poll()
        callback.assert_called_once_with('结果')
        self.assertTrue(all(button.isEnabled() for button in app.view.buttons))
        self.assertIn('结果无法显示', error_dialog.call_args.args[2])
        self.assertTrue(app._timer.isActive())

    def test_close_during_task_keeps_case_and_window_open(self):
        root, app = self.controller()
        app.case = Mock()
        app.runner.busy = True
        root.show()
        self.qt_app.processEvents()
        with patch('forensic.gui.QMessageBox.information') as dialog:
            self.assertFalse(app.close())
        dialog.assert_called_once()
        app.case.close.assert_not_called()
        self.assertTrue(root.isVisible())
        self.assertFalse(app._closed)
        self.assertTrue(app._timer.isActive())
        app.runner.busy = False

    def test_idle_close_stops_timers_and_releases_case_once(self):
        root, app = self.controller()
        app.case = Mock()
        app.browser.cancel_display = Mock(wraps=app.browser.cancel_display)
        app.preview.clear = Mock(wraps=app.preview.clear)
        self.assertTrue(app.close())
        app._shutdown()
        self.assertTrue(app._closed)
        self.assertFalse(app._timer.isActive())
        app.browser.cancel_display.assert_called_once()
        app.preview.clear.assert_called_once()
        app.case.close.assert_called_once()

    def test_native_close_event_uses_same_task_guard(self):
        root, app = self.controller()
        app.case = Mock()
        app.runner.busy = True
        event = QCloseEvent()
        with patch('forensic.gui.QMessageBox.information'):
            self.assertTrue(app.eventFilter(root, event))
        self.assertFalse(event.isAccepted())
        app.case.close.assert_not_called()
        app.runner.busy = False


class FileBrowserTests(QtTests):
    @staticmethod
    def entry(**values):
        return dict(dict(path='记录.txt', inode='1', mode='r/r', size=10, deleted=False,
                         directory=False, offset=0, mtime=0, atime=0, ctime=0), **values)

    def test_inventory_refresh_replaces_pending_tree_rows(self):
        root, app = self.controller()
        app.display([self.entry(path=f'旧记录{index}.txt', inode=str(index + 1))
                     for index in range(600)])
        app.display([self.entry(path='新清单.txt')])
        self.qt_app.processEvents()
        self.assertEqual([row['path'] for row in app.entries.values()], ['新清单.txt'])
        self.assertEqual(app.tree.topLevelItemCount(), 1)
        self.assertEqual(app.tree.topLevelItem(0).text(0), '新清单.txt')

    def test_numeric_columns_keep_centered_headers_and_values(self):
        root, app = self.controller()
        app.display([self.entry(size=123456789, inode='123456789')])
        for column in (2, 3):
            alignment = app.tree.headerItem().textAlignment(column)
            self.assertTrue(alignment & Qt.AlignmentFlag.AlignHCenter)
            alignment = app.tree.topLevelItem(0).textAlignment(column)
            self.assertTrue(alignment & Qt.AlignmentFlag.AlignHCenter)
            self.assertGreaterEqual(app.tree.columnWidth(column), 120)

    def test_selected_partition_survives_audit_refresh(self):
        root, app = self.controller()
        data = dict(number='TEST', examiner='测试', target='镜像', offset=0,
                    evidence=dict(sha256='0' * 64, path='demo.dd', size=100,
                                  fixed_at='2026-11-11T00:00:00+08:00', layout='布局',
                                  partitions=[dict(offset=0, description='卷一'),
                                              dict(offset=2048, description='卷二')]),
                    inventory=[], fsstat='')
        app.case = SimpleNamespace(data=data, check_audit=lambda: [],
                                   timeline_events=lambda: [], close=lambda: None)
        app.refresh(reset=True)
        app.partition.setCurrentIndex(1)
        app.refresh()
        self.assertEqual(app.partition.currentIndex(), 1)


class NewCaseDialogTests(QtTests):
    def dialog(self):
        root, app = self.controller()
        callback = Mock()
        dialog = NewCaseDialog(root, callback)
        self.addCleanup(dialog.deleteLater)
        return dialog, callback

    def test_missing_fields_do_not_open_folder_picker(self):
        dialog, callback = self.dialog()
        with patch('forensic.views.QMessageBox.warning') as warning, \
                patch('forensic.views.QFileDialog.getExistingDirectory') as picker:
            dialog.create()
        warning.assert_called_once()
        picker.assert_not_called()
        callback.assert_not_called()

    def test_creation_failure_keeps_inputs_for_retry(self):
        dialog, callback = self.dialog()
        for entry, text in zip(dialog.fields, (' CASE-1 ', '测试人员', '证据镜像')):
            entry.setText(text)
        callback.side_effect = OSError('案件库不可写')
        with patch('forensic.views.QFileDialog.getExistingDirectory', return_value='cases'), \
                patch('forensic.views.QMessageBox.critical') as error:
            dialog.create()
        callback.assert_called_once_with('cases', 'CASE-1', '测试人员', '证据镜像')
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        self.assertIn('案件库不可写', error.call_args.args[2])
        callback.side_effect = None
        with patch('forensic.views.QFileDialog.getExistingDirectory', return_value='cases'):
            dialog.create()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Accepted)


if __name__ == '__main__':
    unittest.main()
