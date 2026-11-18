"""通过真实后台任务验证加载镜像和打开旧案件都会自动补齐分区树。"""
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow

from forensic.core.case import Case
from forensic.paths import TEST_WORK_DIR
from forensic.ui.controller import App
from tests.fixtures import create_multi_partition_image


class PartitionLoadingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def setUp(self):
        TEST_WORK_DIR.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(dir=TEST_WORK_DIR)
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.image = self.folder / 'multi.dd'
        create_multi_partition_image(self.image)
        self.window = QMainWindow()
        self.window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen)
        self.app = App(self.window)
        self.addCleanup(self.window.deleteLater)
        self.addCleanup(self.app._shutdown)

    def finish(self):
        deadline = time.monotonic() + 30
        with patch('forensic.ui.controller.QMessageBox.critical') as errors:
            while (self.app.busy or self.app.browser._batch_timer.isActive()) and time.monotonic() < deadline:
                self.qt.processEvents()
                self.app.poll()
                time.sleep(.01)
        self.assertFalse(self.app.busy, '自动读取未完成')
        errors.assert_not_called()
        self.assertEqual(set(self.app.browser.partition_nodes), {2048, 20480})
        self.assertEqual({e['offset'] for e in self.app.entries.values()}, {2048, 20480})

    def test_loading_image_automatically_populates_every_partition(self):
        self.app.create_case(self.folder / 'cases', 'AUTO', '测试', '自动加载')
        with patch('PySide6.QtWidgets.QFileDialog.getOpenFileName', return_value=(str(self.image), '')):
            self.app.load()
        self.finish()
        self.assertFalse(self.app.case.needs_partition_scan())
        self.assertTrue(self.app.browser.load_button.isEnabled())

    def test_opening_single_partition_case_automatically_completes_inventory(self):
        case = Case.create(self.folder / 'cases', 'OLD', '测试', '旧单分区案件')
        try:
            case.load(self.image)
            case.scan(2048)
            self.assertTrue(case.needs_partition_scan())
        finally:
            case.close()
        with patch('PySide6.QtWidgets.QFileDialog.getOpenFileName',
                   return_value=(str(case.folder / 'case.json'), '')):
            self.app.open_case()
        self.finish()
