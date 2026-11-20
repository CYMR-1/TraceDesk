"""Qt 控制器、窗口生命周期及文件树刷新回归。"""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QMainWindow, QPushButton

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
    def test_record_panels_open_on_double_click_then_follow_single_click(self):
        root, app = self.controller()
        records = [dict(seq=index, action='FILE_NOTE', timestamp=1700000000, actor='测试',
                        subject=name, result='成功', previous='previous-digest', hash='current-digest',
                        details=dict(note=name, offset=0, inode=str(index), deleted=False, image_sha256='abc'))
                   for index, name in enumerate(('first.txt', 'second.txt'), 1)]
        timeline = [dict(time=r['timestamp'], path=r['subject'], event='修改', offset=0, inode='1', status='现存')
                    for r in records]
        root.show()
        for key, data in [('audit', records), ('findings', [[r] for r in records]), ('timeview', timeline)]:
            with self.subTest(panel=key):
                panel = app.view.panels[key]
                app.tabs.setCurrentIndex(list(app.view.panels).index(key) + 1)
                panel.set_text(('测试', data))
                self.qt_app.processEvents()
                table = panel.table
                first, second = [table.visualItemRect(table.topLevelItem(i)).center() for i in range(2)]
                titles = ['second.txt', 'first.txt'] if key == 'audit' else ['first.txt', 'second.txt']
                QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=first)
                self.assertTrue(panel.text.isHidden())
                QTest.mouseDClick(table.viewport(), Qt.MouseButton.LeftButton, pos=first)
                self.assertTrue(panel.text.isVisible())
                self.assertIn(titles[0], panel.text.toPlainText())
                sizes = panel.split.sizes()
                QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=second)
                self.assertTrue(panel.text.isVisible())
                self.assertEqual(panel.split.sizes(), sizes)
                self.assertIn(titles[1], panel.text.toPlainText())
                self.assertNotIn(titles[0], panel.text.toPlainText())
                if key == 'audit':
                    self.assertIn('previous-digest', panel.text.toPlainText())
                    self.assertIn('current-digest', panel.text.toPlainText())

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

    def test_tree_locates_unvisited_file_on_later_page(self):
        window, app = self.controller()
        rows = [self.entry(path=f'深层/目录/{i:04d}.txt') for i in range(1150)]
        app.display(rows)
        browser = app.browser
        branch = browser._nodes[(0, '深层')]
        branch.setExpanded(True)
        folder = browser._nodes[(0, '深层/目录')]
        folder.setExpanded(True)
        self.assertEqual(folder.childCount(), len(rows))
        with patch.dict(browser.commands, select=lambda: None):
            browser.navigation.setCurrentItem(folder.child(1111))
        self.assertEqual(browser._page, 11)
        self.assertEqual(app.selected_entry()['path'], rows[1111]['path'])

    def test_timeline_number_detail_and_page_jump(self):
        window, app = self.controller()
        panel = app.view.panels['timeview']
        records = [dict(time=1700000000, event='修改', status='现存', offset=0,
                        inode=str(i), path=f'{i}.txt') for i in range(215)]
        panel.set_text(('时间线', records))
        def choose_page():
            dialog = QApplication.activeModalWidget()
            dialog.field.setValue(3)
            buttons = {b.text(): b for b in dialog.findChildren(QPushButton)}
            buttons['OK'].click()

        QTimer.singleShot(0, choose_page)
        QTest.mouseDClick(panel.page_label, Qt.MouseButton.LeftButton)
        item = panel.table.topLevelItem(14)
        self.assertEqual(item.text(0), '215')
        panel.table.setCurrentItem(item)
        self.assertEqual(panel.status.text(), 'MAC/B 时间线·UTC+8·当前 215/215')
        self.assertTrue(panel.text.isHidden())
        panel.table.itemDoubleClicked.emit(item, 1)
        self.assertFalse(panel.text.isHidden())
        self.assertIn('214.txt', panel.text.toPlainText())
        panel.search.setText('214.txt')
        panel._search()
        self.assertEqual(panel.table.topLevelItem(0).text(0), '215')

    def test_large_directory_can_select_last_record_without_creating_every_node(self):
        window, app = self.controller()
        rows = [self.entry(path=f'big/{i:05d}.txt') for i in range(3000)]
        app.display(rows)
        browser = app.browser
        node = browser._locate_entry(rows[-1])
        parent = browser._nodes[(0, 'big')]
        self.assertLess(parent.childCount(), 20)
        self.assertLess(len(browser._tree_by_id), 257)
        with patch.dict(browser.commands, select=lambda: None):
            browser.navigation.setCurrentItem(node)
        self.assertEqual(app.selected_entry()['path'], rows[-1]['path'])

    def test_large_inventory_can_find_entries_beyond_first_page(self):
        root, app = self.controller()
        entries = [self.entry(path=f'目录/{index:04d}.txt') for index in range(1051)]
        app.display(entries)
        self.assertEqual(app.tree.topLevelItemCount(), 100)
        app.browser.next_page.click()
        self.assertEqual(app.tree.topLevelItem(0).text(0), '0100.txt')
        app.browser.apply_filter(entries[-1:])
        self.assertEqual(app.tree.topLevelItemCount(), 1)
        self.assertEqual(app.tree.topLevelItem(0).text(0), '1050.txt')
        app.browser.reset_filter()
        self.assertTrue(app.browser.next_page.isEnabled())

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

    def test_review_panel_shows_checkbox_and_sequence_and_saves_checked_hits(self):
        root, app = self.controller()
        panel = app.view.panels['review']
        headers = [panel.table.headerItem().text(i) for i in range(panel.table.columnCount())]
        self.assertEqual(headers[:4], ['', '序号', '文件内字节偏移', '分区偏移'])
        self.assertEqual(panel.header._check_label, '全选')
        self.assertEqual(panel.header.filter_columns(), (3,))
        self.assertEqual(panel.header.check_state(), Qt.CheckState.Unchecked)
        self.assertEqual(panel.search_button.text(), '搜索')
        self.assertFalse(hasattr(panel, 'cancel_button'))

        logged = []
        case = SimpleNamespace(
            data={'evidence': {'sha256': 'a' * 64}},
            log=lambda *args, **kwargs: logged.append((args, kwargs)),
            image=lambda: 'demo.dd',
            close=lambda: None,
        )
        panel.context = SimpleNamespace(
            case=lambda: case,
            available=lambda: True,
            task=lambda label, work, cb=None: (work(), cb(None) if cb else None),
        )
        panel.case = case

        entries = [
            dict(path='DOCS/A.TXT', offset=2048, inode='10', deleted=False),
            dict(path='DOCS/B.TXT', offset=2048, inode='11', deleted=False),
            dict(path='DOCS/C.TXT', offset=2048, inode='12', deleted=True, reallocated=False),
        ]
        hits = [(entries[0], 5, '00 01', '02 03'), (entries[1], 12, 'aa bb', 'cc dd'), (entries[2], 30, '', 'ff')]
        record = dict(
            query='note', encoding='UTF-8', needle='6e6f7465',
            image_sha256='a' * 64, verification='测试校验',
            status='完成', visited=3, eligible=3, errors=[],
            hits=[dict(source_note=''), dict(source_note=''), dict(source_note='已删除，原内容可能已覆盖')],
        )
        panel.finished((record, hits, 'search_test.json'))

        self.assertEqual(panel.table.topLevelItemCount(), 3)
        for row in range(3):
            item = panel.table.topLevelItem(row)
            self.assertEqual(item.text(0), '')
            self.assertEqual(item.text(1), str(row + 1))
            self.assertEqual(item.text(2), str(hits[row][1]))
            self.assertEqual(item.checkState(0), Qt.CheckState.Unchecked)
            self.assertTrue(item.flags() & Qt.ItemFlag.ItemIsUserCheckable)

        # 表头全选框切换全选与取消全选，并同步三态与按钮文案。
        panel.header.toggled.emit(True)
        self.assertEqual(panel.header.check_state(), Qt.CheckState.Checked)
        self.assertEqual(len(panel.checked_items()), 3)
        self.assertIn('3', panel.save_button.text())
        panel.header.toggled.emit(False)
        self.assertEqual(panel.header.check_state(), Qt.CheckState.Unchecked)
        self.assertEqual(len(panel.checked_items()), 0)
        self.assertEqual(panel.save_button.text(), '将所选命中保存为取证发现')

        # 部分勾选时表头全选框进入半选态，并支持批量保存为取证发现。
        panel.table.topLevelItem(0).setCheckState(0, Qt.CheckState.Checked)
        panel.table.topLevelItem(2).setCheckState(0, Qt.CheckState.Checked)
        self.assertEqual(panel.header.check_state(), Qt.CheckState.PartiallyChecked)
        self.assertIn('2', panel.save_button.text())
        panel.bookmark()
        self.assertEqual([(a[1], k['file_byte']) for a, k in logged], [('DOCS/A.TXT', 5), ('DOCS/C.TXT', 30)])

        # 未勾选时回退保存当前选中行。
        logged.clear()
        panel.table.topLevelItem(0).setCheckState(0, Qt.CheckState.Unchecked)
        panel.table.topLevelItem(2).setCheckState(0, Qt.CheckState.Unchecked)
        self.assertEqual(panel.header.check_state(), Qt.CheckState.Unchecked)
        panel.table.setCurrentItem(panel.table.topLevelItem(1))
        panel.bookmark()
        self.assertEqual([(a[1], k['file_byte']) for a, k in logged], [('DOCS/B.TXT', 12)])

        # 双击选择框列不应触发字节预览对话框。
        with patch('forensic.features.review.QDialog') as dialog_cls:
            panel.preview(panel.table.topLevelItem(0), 0)
            dialog_cls.assert_not_called()

        # 分区偏移表头下拉筛选与排除所选项。
        entries_multi = [
            dict(path='BOOT/A.MUI', offset=2048, inode='10', deleted=False),
            dict(path='WIN/B.DLL', offset=104448, inode='11', deleted=False),
            dict(path='WIN/C.EXE', offset=104448, inode='12', deleted=False),
        ]
        hits_multi = [(entries_multi[0], 10, '', ''), (entries_multi[1], 20, '', ''), (entries_multi[2], 30, '', '')]
        rec_multi = dict(record, hits=[dict(source_note='')] * 3)
        panel._reset_results()
        panel.finished((rec_multi, hits_multi, 'search_multi.json'))
        self.assertEqual(panel.header.filter_options(3), ['2048', '104448'])
        panel.header.set_filter_value(3, '104448')
        self.assertTrue(panel.table.topLevelItem(0).isHidden())
        self.assertFalse(panel.table.topLevelItem(1).isHidden())
        self.assertFalse(panel.table.topLevelItem(2).isHidden())
        # 全选仅作用于当前筛选出的可见项，排除所选项仅移除已勾选的可见项。
        panel.header.toggled.emit(True)
        self.assertEqual(len(panel.checked_items()), 2)
        panel.exclude_selected()
        self.assertEqual(panel.table.topLevelItemCount(), 1)
        panel.header.set_filter_value(3, None)
        self.assertEqual(panel.table.topLevelItem(0).text(5), 'BOOT/A.MUI')
        self.assertEqual(panel.table.topLevelItem(0).text(1), '1')
        self.assertEqual(panel.header.filter_options(3), ['2048'])

        # 登记证据来源对话框默认尺寸应足以完整展示 64 位 SHA-256。
        sizes = []
        def capture_exec(dlg):
            sizes.append((dlg.width(), dlg.height()))
            return 0
        with patch.object(QDialog, 'exec', capture_exec):
            panel.source()
        self.assertEqual(sizes, [(600, 270)])

    def test_review_panel_streams_hits_and_allows_actions_during_search(self):
        import threading
        import time

        root, app = self.controller()
        panel = app.view.panels['review']
        logged = []
        case = SimpleNamespace(
            data={'evidence': {'sha256': 'b' * 64}},
            log=lambda *args, **kwargs: logged.append((args, kwargs)),
            image=lambda: 'demo.dd',
            source_note=lambda: '只读保护中',
            close=lambda: None,
        )
        panel.context = SimpleNamespace(
            case=lambda: case,
            available=lambda: True,
            selected_entry=lambda: None,
            refresh=lambda: None,
            task=lambda label, work, cb=None: (work(), cb(None) if cb else None),
        )
        panel.case = case
        panel.query.setText('note')

        first_sent = threading.Event()
        release = threading.Event()
        e1 = dict(path='DOCS/LIVE1.TXT', offset=2048, inode='20', deleted=False)
        e2 = dict(path='DOCS/LIVE2.TXT', offset=2048, inode='21', deleted=False)
        h1 = (e1, 4, '00 01', '02 03')
        h2 = (e2, 9, '10 11', '12 13')

        def fake_search(c, query, encoding, control, progress, *, limit=None, selected=None, on_hit=None):
            progress('搜索文件内容', 1, 2)
            on_hit([h1])
            first_sent.set()
            release.wait(5)
            on_hit([h2])
            record = dict(
                query=query, encoding=encoding, needle='6e6f7465',
                image_sha256='b' * 64, verification='只读保护中',
                status='完成', visited=2, eligible=2, errors=[],
                hits=[dict(source_note=''), dict(source_note='')],
            )
            return record, [h1, h2], 'search_live.json'

        with patch('forensic.features.review.search', side_effect=fake_search):
            panel.toggle_search()
            self.assertTrue(first_sent.wait(5))
            panel._poll_search()
            # 搜索进行中按钮变为“取消搜索”，且可勾选、保存、预览与排除。
            self.assertTrue(panel.searching)
            self.assertEqual(panel.search_button.text(), '取消搜索')
            self.assertTrue(panel.search_button.isEnabled())
            self.assertEqual(panel.table.topLevelItemCount(), 1)
            self.assertEqual(panel.table.topLevelItem(0).text(5), 'DOCS/LIVE1.TXT')

            panel.table.topLevelItem(0).setCheckState(0, Qt.CheckState.Checked)
            self.assertEqual(panel.header.check_state(), Qt.CheckState.Checked)
            panel.bookmark()
            self.assertEqual([(a[1], k['file_byte']) for a, k in logged], [('DOCS/LIVE1.TXT', 4)])

            with patch('forensic.features.review.QDialog.exec', return_value=0) as exec_mock, \
                    patch('forensic.features.review.FilePreview.open_file') as open_mock:
                panel.preview(panel.table.topLevelItem(0), 2)
                exec_mock.assert_called_once()
                open_mock.assert_called_once()
                self.assertEqual(open_mock.call_args.args[1]['path'], 'DOCS/LIVE1.TXT')

            release.set()
            deadline = time.monotonic() + 5
            while panel.searching and time.monotonic() < deadline:
                panel._poll_search()
                time.sleep(0.01)

        # 搜索完成后按钮恢复“搜索”，追加剩余命中且保留先前勾选状态。
        self.assertFalse(panel.searching)
        self.assertEqual(panel.search_button.text(), '搜索')
        self.assertTrue(panel.search_button.isEnabled())
        self.assertEqual(panel.table.topLevelItemCount(), 2)
        self.assertEqual(panel.table.topLevelItem(0).checkState(0), Qt.CheckState.Checked)
        self.assertEqual(panel.table.topLevelItem(1).checkState(0), Qt.CheckState.Unchecked)
        self.assertEqual(panel.header.check_state(), Qt.CheckState.PartiallyChecked)

    def test_timeline_and_audit_toggle_sort_order_on_number_and_time(self):
        root, app = self.controller()
        # 1. MACB 时间线（含大清单跨页倒序/正序切换）
        timeline = app.view.panels['timeview']
        rows = [dict(time=f'2026-11-20T00:{i // 60:02d}:{i % 60:02d}+08:00', event='M 内容修改',
                     status='现存', offset=2048, inode=str(i), path=f'file_{i}.txt')
                for i in range(1, 151)]
        timeline.set_text(('时间线', rows, lambda label, work, cb: cb(work())))
        self.assertEqual(timeline.table.topLevelItem(0).text(0), '1')
        self.assertEqual(timeline.table.header().sortIndicatorOrder(), Qt.SortOrder.AscendingOrder)

        # 点击“序号”切换为倒序，跨页首行应为第 150 条，翻页后应为第 50 条。
        timeline._toggle_sort(0)
        self.assertEqual(timeline.table.header().sortIndicatorSection(), 0)
        self.assertEqual(timeline.table.header().sortIndicatorOrder(), Qt.SortOrder.DescendingOrder)
        self.assertEqual(timeline.table.topLevelItem(0).text(0), '150')
        timeline._move(1)
        self.assertEqual(timeline.table.topLevelItem(0).text(0), '50')

        # 点击“时间（UTC+8）”切回正序并回到首页。
        timeline._toggle_sort(1)
        self.assertEqual(timeline.table.header().sortIndicatorSection(), 1)
        self.assertEqual(timeline.table.header().sortIndicatorOrder(), Qt.SortOrder.AscendingOrder)
        self.assertEqual(timeline.table.topLevelItem(0).text(0), '1')

        # 点击非序号/时间列不改变排序。
        timeline._toggle_sort(2)
        self.assertEqual(timeline.table.topLevelItem(0).text(0), '1')

        # 2. 审计日志（默认倒序，点击序号或时间切换正序/倒序，刷新后保持排序方向）
        audit = app.view.panels['audit']
        records = [dict(seq=i, timestamp=f'2026-11-20T1{i}:00:00+08:00', actor='测试', action='FILE_NOTE',
                        result='成功', subject=f'f{i}.txt', details={}, previous='0' * 64, hash=str(i) * 64)
                   for i in range(1, 4)]
        audit.set_text(('日志校验通过', records))
        self.assertEqual([audit.table.topLevelItem(i).text(0) for i in range(3)], ['3', '2', '1'])

        audit._toggle_sort(0)
        self.assertEqual(audit.table.header().sortIndicatorOrder(), Qt.SortOrder.AscendingOrder)
        self.assertEqual([audit.table.topLevelItem(i).text(0) for i in range(3)], ['1', '2', '3'])

        # 刷新后保持用户选择的正序。
        audit.set_text(('日志校验通过', records))
        self.assertEqual([audit.table.topLevelItem(i).text(0) for i in range(3)], ['1', '2', '3'])

        audit._toggle_sort(1)
        self.assertEqual(audit.table.header().sortIndicatorSection(), 1)
        self.assertEqual(audit.table.header().sortIndicatorOrder(), Qt.SortOrder.DescendingOrder)
        self.assertEqual([audit.table.topLevelItem(i).text(0) for i in range(3)], ['3', '2', '1'])

    def test_header_dropdown_filters_across_analysis_panels_and_findings_export(self):
        root, app = self.controller()

        # 1. 取证发现：状态、分区偏移下拉筛选 + 一键导出仅导出当前展示结果。
        findings = app.view.panels['findings']
        self.assertEqual(findings.header.filter_columns(), (1, 2))
        exported_groups = []
        g1 = [dict(seq=1, timestamp='2026-11-20T10:00:00+08:00', actor='测试', action='FILE_NOTE', result='成功',
                   subject='a.txt', details=dict(offset=2048, inode='10', deleted=False, image_sha256='a' * 64))]
        g2 = [dict(seq=2, timestamp='2026-11-20T11:00:00+08:00', actor='测试', action='FILE_NOTE', result='成功',
                   subject='b.txt', details=dict(offset=104448, inode='11', deleted=True, image_sha256='a' * 64))]
        findings.set_text(('取证发现', [g1, g2], exported_groups.append))
        self.assertTrue(findings.export_button.isEnabled())
        self.assertEqual(findings.header.filter_options(1), ['已删除', '现存'])
        self.assertEqual(findings.header.filter_options(2), ['2048', '104448'])
        findings.header.set_filter_value(1, '已删除')
        self.assertEqual(findings.table.topLevelItemCount(), 1)
        self.assertEqual(findings.table.topLevelItem(0).text(0), 'b.txt')
        findings.export_button.click()
        self.assertEqual(exported_groups, [[g2]])

        # 2. MACB 时间线：事件、状态、分区偏移下拉筛选。
        timeline = app.view.panels['timeview']
        self.assertEqual(timeline.header.filter_columns(), (2, 3, 4))
        rows = [
            dict(time='2026-11-20T10:00:00+08:00', event='M 内容修改', status='现存', offset=2048, inode='1', path='a.txt'),
            dict(time='2026-11-20T11:00:00+08:00', event='B 创建', status='已删除', offset=104448, inode='2', path='b.txt'),
        ]
        timeline.set_text(('时间线', rows))
        self.assertEqual(timeline.header.filter_options(4), ['2048', '104448'])
        timeline.header.set_filter_value(2, 'B 创建')
        self.assertEqual(timeline.table.topLevelItemCount(), 1)
        self.assertEqual(timeline.table.topLevelItem(0).text(6), 'b.txt')

        # 3. 审计日志：操作人员、操作、结果下拉筛选。
        audit = app.view.panels['audit']
        self.assertEqual(audit.header.filter_columns(), (2, 3, 4))
        records = [
            dict(seq=1, timestamp='2026-11-20T10:00:00+08:00', actor='张三', action='CASE_CREATE',
                 result='成功', subject='c1', details={}, previous='0' * 64, hash='1' * 64),
            dict(seq=2, timestamp='2026-11-20T11:00:00+08:00', actor='李四', action='FILE_EXPORT',
                 result='失败', subject='a.txt', details={}, previous='1' * 64, hash='2' * 64),
        ]
        audit.set_text(('日志校验通过', records))
        audit.header.set_filter_value(2, '李四')
        self.assertEqual(audit.table.topLevelItemCount(), 1)
        self.assertEqual(audit.table.topLevelItem(0).text(3), '导出文件')
        audit.header.set_filter_value(4, '成功')
        self.assertEqual(audit.table.topLevelItemCount(), 0)
        audit.header.clear_filters(emit=True)
        self.assertEqual(audit.table.topLevelItemCount(), 2)


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
