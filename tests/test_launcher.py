"""验证应用入口能报告错误，不启动真实消息框。"""
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import Mock, patch

from forensic.launcher import ApplicationLauncher, ErrorReporter


class LauncherTests(unittest.TestCase):
    def test_startup_failure_is_reported(self):
        reporter = Mock()
        with patch('forensic.gui.main', side_effect=RuntimeError('初始化失败')):
            self.assertEqual(ApplicationLauncher(reporter).run(), 1)
        arguments = reporter.report_exception.call_args.args
        self.assertIs(arguments[0], RuntimeError)
        self.assertEqual(str(arguments[1]), '初始化失败')
        self.assertIsNotNone(arguments[2])

    def test_successful_startup(self):
        reporter = Mock()
        with patch('forensic.gui.main') as main:
            self.assertEqual(ApplicationLauncher(reporter).run(), 0)
        main.assert_called_once_with()
        reporter.report_exception.assert_not_called()

    def test_qt_callback_writes_traceback_and_shows_log_path(self):
        test_root = Path(__file__).resolve().parent.parent / '.test-work'
        test_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as folder:
            path = Path(folder) / 'logs' / 'startup.log'
            reporter = ErrorReporter(path)
            root = Mock()
            previous_hook = sys.excepthook
            reporter.install(root)
            self.addCleanup(reporter.restore)
            try:
                raise ValueError('回调测试')
            except ValueError as error:
                with patch('PySide6.QtWidgets.QApplication.instance', return_value=object()), \
                        patch('PySide6.QtWidgets.QMessageBox.critical') as dialog:
                    sys.excepthook(type(error), error, error.__traceback__)
            text = path.read_text(encoding='utf-8')
            self.assertIn('Traceback', text)
            self.assertIn('ValueError: 回调测试', text)
            self.assertIn(str(path), dialog.call_args.args[2])
            self.assertIs(dialog.call_args.args[0], root)
            reporter.restore()
            self.assertIs(sys.excepthook, previous_hook)
            self.assertIsNone(reporter.root)

    def test_restore_preserves_a_new_host_exception_hook(self):
        previous_hook = sys.excepthook
        self.addCleanup(setattr, sys, 'excepthook', previous_hook)
        reporter = ErrorReporter()
        reporter.install(Mock())
        replacement = Mock()
        sys.excepthook = replacement
        reporter.restore()
        self.assertIs(sys.excepthook, replacement)


if __name__ == '__main__':
    unittest.main()
