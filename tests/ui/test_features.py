"""验证通过登记增删入口、刷新回调和文件操作。"""
from unittest.mock import Mock

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QMainWindow

from forensic.features.api import Action, Feature, Panel
from forensic.features.catalog import load_features
from forensic.ui.controller import App
from tests.ui.test_gui import QtTests


class FeatureAssemblyTests(QtTests):
    def build(self, additions=()):
        window = QMainWindow()
        app = App(window, features=load_features(('cases', 'evidence', 'files')) + additions)
        self.addCleanup(lambda: QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete))
        self.addCleanup(window.deleteLater)
        self.addCleanup(app._shutdown)
        return app

    def test_omitted_features_have_no_controls_or_refresh_hooks(self):
        app = self.build()
        self.assertEqual(set(app.view.panels), {'info'})
        self.assertNotIn('report', app.view.action_buttons)
        self.assertIsNone(app.browser.export_button)
        with self.assertRaisesRegex(ValueError, 'export'):
            app.export()
        case = Mock()
        case.data = dict(number='1', examiner='测试', target='镜像', evidence=None, inventory=[])
        case.needs_partition_scan.return_value = False
        app._replace_case(case)
        case.check_audit.assert_not_called()
        case.timeline_events.assert_not_called()

    def test_added_feature_mounts_page_and_dispatches_button_without_controller_changes(self):
        run = Mock()
        additions = (Feature('example', actions=(Action('sample', run, '示例', 'header'),),
                             panels=(Panel('example_page', '示例页', lambda ctx: '示例内容'),)),)
        app = self.build(additions)
        self.assertEqual(app.view.panels['example_page'].text.toPlainText(), '示例内容')
        app.view.action_buttons['sample'].click()
        run.assert_called_once_with(app.features.context)
