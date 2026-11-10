"""控制器状态与文件树刷新回归。"""
import gc
import tkinter as tk
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from forensic.gui import App
from forensic.tasks import TaskResult


class ControllerTests(unittest.TestCase):
    def controller(self, busy=False):
        app = App.__new__(App)
        app.root, app.view, app.browser = Mock(), Mock(), Mock()
        app.preview, app.case, app.status = Mock(), Mock(), Mock()
        app.runner = SimpleNamespace(busy=busy, poll=Mock(return_value=None))
        app._closed, app._poll_id = False, 'pending-poll'
        app.refresh = Mock()
        return app

    def test_callback_failure_keeps_polling_and_restores_controls(self):
        app = self.controller()
        callback = Mock(side_effect=ValueError('结果无法显示'))
        app.runner.poll.return_value = TaskResult(value='结果', callback=callback)
        with patch('forensic.gui.messagebox.showerror') as error_dialog:
            app.poll()
        callback.assert_called_once_with('结果')
        app.view.set_busy.assert_called_once_with(False)
        self.assertIn('结果无法显示', error_dialog.call_args.args[1])
        app.root.after.assert_called_once_with(100, app.poll)
        self.assertIs(app._poll_id, app.root.after.return_value)

    def test_close_during_task_keeps_case_and_window_open(self):
        app = self.controller(busy=True)
        with patch('forensic.gui.messagebox.showinfo') as dialog:
            app.close()
        dialog.assert_called_once()
        app.case.close.assert_not_called()
        app.root.destroy.assert_not_called()
        app.preview.clear.assert_not_called()

    def test_idle_close_stops_display_and_releases_case(self):
        app = self.controller()
        app.close()
        app.browser.cancel_display.assert_called_once()
        app.preview.clear.assert_called_once()
        app.case.close.assert_called_once()
        app.root.destroy.assert_called_once()

    def test_destroy_cancels_poll_and_future_tree_batches(self):
        app = self.controller()
        app._on_destroy(SimpleNamespace(widget=app.root))
        self.assertTrue(app._closed)
        self.assertIsNone(app._poll_id)
        app.root.after_cancel.assert_called_once_with('pending-poll')
        app.browser.cancel_display.assert_called_once()


class FileBrowserTests(unittest.TestCase):
    def test_inventory_refresh_replaces_pending_tree_rows(self):
        root = tk.Tk()
        root.attributes('-alpha', 0)
        self.addCleanup(gc.collect)
        self.addCleanup(root.destroy)
        errors = []
        root.report_callback_exception = lambda kind, error, tb: errors.append(error)
        app = App(root)
        entry = dict(path='旧记录.txt', inode='1', mode='r/r', size=10, deleted=False,
                     directory=False, offset=0, mtime=0, atime=0, ctime=0)
        app.display([dict(entry, path=f'旧记录{index}.txt', inode=str(index + 1)) for index in range(600)])
        app.display([dict(entry, path='新清单.txt')])
        root.update()
        self.assertEqual([row['path'] for row in app.entries.values()], ['新清单.txt'])
        self.assertEqual(len(app.tree.get_children()), 1)
        self.assertEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
