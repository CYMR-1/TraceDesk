"""图文操作说明弹窗、内置引导图资源与大图放大查看回归。"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PySide6.QtGui import QImage
from PySide6.QtWidgets import QApplication, QMainWindow

from forensic.features.help import (
    GUIDE_IMAGE_DIR, GUIDE_PAGES, GuideDialog, GuideLightboxDialog, _guide_html,
)
from forensic.ui.appearance import DesktopAppearance


class HelpGuideDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = QMainWindow()
        DesktopAppearance(self.window).configure()
        self.addCleanup(self.window.deleteLater)
        self.addCleanup(self.window.close)

    def test_every_guide_page_has_valid_annotated_png_asset(self):
        self.assertGreaterEqual(len(GUIDE_PAGES), 9)
        for page in GUIDE_PAGES:
            image_path = GUIDE_IMAGE_DIR / page.image
            self.assertTrue(image_path.is_file(), f'缺少操作说明引导图：{image_path}')
            image = QImage(str(image_path))
            self.assertFalse(image.isNull(), f'引导图无法解码：{image_path}')
            self.assertGreaterEqual(image.width(), 600)
            self.assertGreaterEqual(image.height(), 400)

    def test_navigation_updates_figure_steps_and_lightbox(self):
        dialog = GuideDialog(self.window)
        self.addCleanup(dialog.deleteLater)
        self.addCleanup(dialog.close)
        dialog.show()
        self.qt.processEvents()

        self.assertEqual(dialog.topics.count(), len(GUIDE_PAGES))
        self.assertEqual(dialog.topics.currentRow(), 0)
        self.assertFalse(dialog.back_button.isEnabled())
        self.assertTrue(dialog.forward_button.isEnabled())
        self.assertTrue(dialog.figure.isVisible())
        self.assertFalse(dialog.figure.source_pixmap.isNull())
        self.assertIn('第 1 /', dialog.position_label.text())

        # 通过“下一步”翻页，再通过左侧目录跳到最后一页（MCP 接入）
        dialog.forward_button.click()
        self.qt.processEvents()
        self.assertEqual(dialog.topics.currentRow(), 1)
        self.assertTrue(dialog.back_button.isEnabled())
        self.assertIn(GUIDE_PAGES[1].title, dialog.page_title.text())

        last = len(GUIDE_PAGES) - 1
        dialog.topics.setCurrentRow(last)
        self.qt.processEvents()
        self.assertFalse(dialog.forward_button.isEnabled())
        self.assertIn(GUIDE_PAGES[last].title, dialog.page_title.text())
        self.assertIn('MCP', dialog.body.toPlainText())

        # 核验大图预览弹窗可打开并切换 100% / 适应窗口模式
        lightbox = GuideLightboxDialog(dialog, GUIDE_PAGES[last].title, GUIDE_PAGES[last].caption,
                                       dialog.figure.source_pixmap)
        self.addCleanup(lightbox.deleteLater)
        self.addCleanup(lightbox.close)
        lightbox.show()
        self.qt.processEvents()
        self.assertFalse(lightbox.canvas.pixmap().isNull())
        lightbox.zoom_button.click()
        self.qt.processEvents()
        self.assertEqual(lightbox.zoom_button.text(), '适应窗口')
        lightbox.zoom_button.click()
        self.qt.processEvents()
        self.assertEqual(lightbox.zoom_button.text(), '原始尺寸 (100%)')

        # 点击引导图可触发 open_lightbox 路径
        with patch.object(GuideLightboxDialog, 'exec', return_value=0) as mocked_exec:
            dialog.figure.zoom_button.click()
            self.assertEqual(mocked_exec.call_count, 1)

    def test_missing_image_dir_degrades_gracefully_and_renders_callouts(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            dialog = GuideDialog(self.window, image_dir=Path(empty_dir))
            self.addCleanup(dialog.deleteLater)
            self.addCleanup(dialog.close)
            dialog.show()
            self.qt.processEvents()
            self.assertFalse(dialog.figure.isVisible())
            self.assertTrue(dialog.figure.source_pixmap.isNull())
            # 缺失图片时触发放大不报错
            dialog.open_lightbox()

        html = _guide_html('1. 点击 ① **新建案件** 并运行 `main.py`\n\n> 提示：测试提示块')
        self.assertIn('class="step-ref"', html)
        self.assertIn('class="callout"', html)
        self.assertIn('<code>', html)


if __name__ == '__main__':
    unittest.main()
