"""验证应用入口能报告错误，不启动真实消息框。"""
from pathlib import Path
import tempfile
from types import SimpleNamespace
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

    def test_tk_callback_writes_traceback_and_shows_log_path(self):
        test_root = Path(__file__).resolve().parent.parent / '.test-work'
        test_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as folder:
            path = Path(folder) / 'logs' / 'startup.log'
            reporter = ErrorReporter(path)
            root = SimpleNamespace()
            reporter.install(root)
            try:
                raise ValueError('回调测试')
            except ValueError as error:
                with patch('tkinter.messagebox.showerror') as dialog:
                    root.report_callback_exception(type(error), error, error.__traceback__)
            text = path.read_text(encoding='utf-8')
            self.assertIn('Traceback', text)
            self.assertIn('ValueError: 回调测试', text)
            self.assertIn(str(path), dialog.call_args.args[1])
            self.assertIs(dialog.call_args.kwargs['parent'], root)


if __name__ == '__main__':
    unittest.main()
