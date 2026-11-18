"""Qt 控制器、窗口生命周期及文件树刷新回归。"""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QDialog, QMainWindow

from forensic.ui.controller import App
from forensic.core.tasks import TaskResult
from forensic.ui.views import NewCaseDialog


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
    def test_chained_scan_keeps_busy_controls_and_defers_refresh(self):
        root, app = self.controller()
        app.case = Mock()
        app.refresh = Mock()
        # 加载完成回调立即开始自动扫描，此时不能边读审计文件边刷新。
        def start_scan(_):
            app.runner.busy = True
            app.view.set_busy(True)
            app.status.setText('自动读取所有分区与文件树…')
        app.runner = SimpleNamespace(busy=False, poll=Mock(
            return_value=TaskResult(callback=start_scan)))
        app.poll()
        app.refresh.assert_not_called()
        self.assertFalse(app.browser.load_button.isEnabled())
        self.assertIn('自动读取所有分区', app.status.text())
        app.runner.busy = False

    def test_callback_failure_keeps_polling_and_restores_controls(self):
        root, app = self.controller()
        app.case = Mock()
        callback = Mock(side_effect=ValueError('结果无法显示'))
        app.runner = SimpleNamespace(busy=False, poll=Mock(
            return_value=TaskResult(value='结果', callback=callback)))
        app.view.set_busy(True)
        with patch('forensic.ui.controller.QMessageBox.critical') as error_dialog:
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
        with patch('forensic.ui.controller.QMessageBox.information') as dialog:
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
        with patch('forensic.ui.controller.QMessageBox.information'):
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
        node = app.browser.partition_nodes[2048]
        app.browser.navigation.setCurrentItem(node)
        app.refresh()
        self.assertIs(app.browser.navigation.currentItem(), node)
        self.assertEqual(app.browser._scope_offset, 2048)

    def test_directory_filter_keeps_complete_tree_and_navigation_restores_file(self):
        root, app = self.controller()
        entries = [self.entry(path='DOCS', directory=True, mode='d/d'),
                   self.entry(path='DOCS/a.txt', inode='2'), self.entry(path='root.bin', inode='3')]
        app.display(entries)
        browser = app.browser
        app.preview.open_file = Mock()
        app.case = SimpleNamespace(image=lambda: 'demo.dd', close=lambda: None)
        nodes = dict(browser._nav_items)
        browser.navigation.setCurrentItem(browser._nodes[(0, 'DOCS')])
        self.assertEqual([e['path'] for k, e in browser.entries.items() if not browser._items[k].isHidden()],
                         ['DOCS/a.txt'])
        browser.apply_filter([])
        self.assertEqual(browser._visible_count, 0)
        self.assertEqual(browser._nav_items, nodes)
        self.assertTrue(all(not n.isHidden() for n in nodes.values()))
        key = next(k for k, e in browser.entries.items() if e['path'] == 'root.bin')
        browser.navigation.setCurrentItem(nodes[key])
        self.assertEqual(app.selected_entry()['path'], 'root.bin')
        self.assertEqual(browser._scope, '')
        self.assertIsNone(browser._allowed)
        self.assertTrue(browser.export_button.isEnabled())
        app.preview.open_file.assert_called_once()

    def test_duplicate_deleted_entries_keep_distinct_selection_and_preview(self):
        root, app = self.controller()
        entries = [self.entry(path='DOCS/same.txt', inode=str(i), deleted=True) for i in (5, 9)]
        app.display(entries)
        app.case = SimpleNamespace(image=lambda: 'demo.dd', close=lambda: None)
        app.preview.open_file = Mock()
        browser = app.browser
        for key, entry in browser.entries.items():
            browser.navigation.setCurrentItem(browser._nav_items[key])
            self.assertEqual(app.selected_entry()['inode'], entry['inode'])
            self.assertIn(f'inode {entry["inode"]}', browser.detail.text())
            self.assertEqual(app.preview.open_file.call_args.args[1]['inode'], entry['inode'])
        browser.apply_filter([])
        self.assertFalse(browser.export_button.isEnabled())
        self.assertNotIn('inode', browser.detail.text())
        self.assertIsNone(app.selected_entry())

    def test_same_paths_and_inodes_in_different_partitions_stay_separate(self):
        root, app = self.controller()
        entries = [self.entry(path=path, offset=offset, directory=path == 'DOCS',
                              mode='d/d' if path == 'DOCS' else 'r/r')
                   for offset in (2048, 20480) for path in ('DOCS', 'DOCS/same.txt')]
        app.display(entries)
        app.case = SimpleNamespace(image=lambda: 'demo.dd', close=lambda: None)
        app.preview.open_file = Mock()
        browser = app.browser
        self.assertEqual(len(browser.partition_nodes), 2)
        for offset in (2048, 20480):
            browser.navigation.setCurrentItem(browser.partition_nodes[offset])
            self.assertEqual(browser._visible_count, 2)
            browser.navigation.setCurrentItem(browser._nodes[(offset, 'DOCS')])
            visible = [item for item in browser._items.values() if not item.isHidden()]
            self.assertEqual(len(visible), 1)
            browser.tree.setCurrentItem(visible[0])
            self.assertEqual(app.selected_entry()['offset'], offset)
            self.assertEqual(app.preview.open_file.call_args.args[1]['offset'], offset)
            self.assertEqual(browser.navigation.currentItem().parent(), browser._nodes[(offset, 'DOCS')])
        browser.navigation.setCurrentItem(browser.image_node)
        self.assertEqual(browser._visible_count, 4)
        # 从跨分区结果双击目录，也只能进入该分区的目录。
        item = next(item for key, item in browser._items.items()
                    if browser.entries[key]['directory'] and browser.entries[key]['offset'] == 20480)
        browser._open_directory(item, 0)
        self.assertEqual(browser._scope_offset, 20480)
        self.assertEqual(browser._visible_count, 1)

    def test_unreadable_partition_remains_visible_with_reason(self):
        root, app = self.controller()
        browser = app.browser
        browser.set_context(dict(path='disk.dd', partitions=[dict(offset=2048, description='未知文件系统')]),
                            [dict(offset=2048, status='error', count=0, error='无法识别文件系统')])
        app.display([])
        node = browser.partition_nodes[2048]
        self.assertIn('无法读取', node.text(0))
        browser.navigation.setCurrentItem(node)
        self.assertIn('无法识别文件系统', browser.detail.text())
        self.assertFalse(browser.export_button.isEnabled())

    def test_filters_during_batch_insertion_do_not_drop_tree_records(self):
        root, app = self.controller()
        entries = [self.entry(path=f'DOCS/f{i}.txt', inode=str(i + 1), deleted=i % 2 == 0)
                   for i in range(450)]
        app.display(entries)
        browser = app.browser
        browser.apply_filter(entries[-10:])
        browser.status_filter.setCurrentIndex(2)
        while browser._batch_timer.isActive():
            self.qt_app.processEvents()
        self.assertEqual(len(browser._nav_items), 450)
        self.assertEqual(browser._visible_count, 5)
        self.assertEqual(browser.tree.topLevelItemCount(), 450)

    def test_result_selection_reveals_tree_and_system_regions_cannot_export(self):
        root, app = self.controller()
        app.display([self.entry(path='A/B/region', mode='v/v', extents=[[0, 10]])])
        app.case = SimpleNamespace(image=lambda: 'demo.dd', close=lambda: None)
        app.preview.open_file = Mock()
        browser = app.browser
        browser.navigation.collapseAll()
        app.tree.setCurrentItem(app.tree.topLevelItem(0))
        node = browser.navigation.currentItem()
        self.assertEqual(node.text(0), 'region')
        while node.parent() is not None:
            node = node.parent()
            self.assertTrue(node.isExpanded())
        self.assertFalse(browser.export_button.isEnabled())
        app.preview.open_file.assert_called_once()


class NewCaseDialogTests(QtTests):
    def dialog(self):
        root, app = self.controller()
        callback = Mock()
        dialog = NewCaseDialog(root, callback)
        self.addCleanup(dialog.deleteLater)
        return dialog, callback

    def test_missing_fields_do_not_open_folder_picker(self):
        dialog, callback = self.dialog()
        with patch('forensic.ui.views.QMessageBox.warning') as warning, \
                patch('forensic.ui.views.choose_case_directory') as picker:
            dialog.create()
        warning.assert_called_once()
        picker.assert_not_called()
        callback.assert_not_called()

    def test_creation_failure_keeps_inputs_for_retry(self):
        dialog, callback = self.dialog()
        for entry, text in zip(dialog.fields, (' CASE-1 ', '测试人员', '证据镜像')):
            entry.setText(text)
        callback.side_effect = OSError('案件库不可写')
        with patch('forensic.ui.views.choose_case_directory', return_value=Path('cases/自定义目录')), \
                patch('forensic.ui.views.QMessageBox.critical') as error:
            dialog.create()
        callback.assert_called_once_with(Path('cases'), 'CASE-1', '测试人员', '证据镜像', folder_name='自定义目录')
        self.assertEqual(dialog.result(), QDialog.DialogCode.Rejected)
        self.assertIn('案件库不可写', error.call_args.args[2])
        callback.side_effect = None
        with patch('forensic.ui.views.choose_case_directory', return_value=Path('cases/自定义目录')):
            dialog.create()
        self.assertEqual(dialog.result(), QDialog.DialogCode.Accepted)


if __name__ == '__main__':
    unittest.main()
