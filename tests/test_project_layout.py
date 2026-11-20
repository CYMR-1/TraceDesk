"""搬动模块后的资源定位、脱离源码树运行和分发内容回归。"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from forensic.paths import ROOT, TEST_WORK_DIR
from scripts import package


class ProjectLayoutTests(unittest.TestCase):
    def test_resources_and_gui_resolve_from_another_working_directory(self):
        TEST_WORK_DIR.mkdir(exist_ok=True)
        # 新进程避免已导入的旧模块、当前工作目录或 Qt 状态掩盖路径错误。
        code = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from forensic.paths import ROOT, ASSET_DIR, LOGS_DIR
from forensic.launcher import ErrorReporter
from forensic.engines.tsk import TSK
from forensic.ui.controller import App
from PySide6.QtWidgets import QApplication, QMainWindow
assert ROOT == Path(sys.argv[1])
assert ErrorReporter().log_path == LOGS_DIR / 'startup.log'
assert (ASSET_DIR / 'tracedesk.ico').is_file()
assert Path(TSK().command('fls', [])[0]).is_file()
qt = QApplication([])
window = QMainWindow()
app = App(window)
assert not window.windowIcon().isNull()
assert app.browser.navigation.topLevelItemCount() == 1
app._shutdown()
window.close()
'''
        with tempfile.TemporaryDirectory(dir=TEST_WORK_DIR) as folder:
            result = subprocess.run([sys.executable, '-c', code, str(ROOT)], cwd=folder,
                                    env={**os.environ, 'QT_QPA_PLATFORM': 'offscreen'},
                                    capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace'))

    def test_package_includes_subpackages_and_licenses_but_excludes_local_data(self):
        TEST_WORK_DIR.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=TEST_WORK_DIR) as folder:
            root = Path(folder)
            included = ['main.py', 'mcp_server.py', 'requirements.txt', 'README.md', '启动取证工作台.bat', '.gitignore',
                        'forensic/core/__init__.py', 'forensic/core/case.py', 'forensic/engines/tsk.py',
                        'forensic/ui/controller.py', 'forensic/assets/tracedesk.ico',
                        'tests/ui/__init__.py', 'docs/README.md', 'docs/目录结构.md', 'docs/设计与验收说明.md',
                        'tools/sleuthkit-4.15.0-win32/bin/fls.exe',
                        'tools/sleuthkit-4.15.0-win32/bin/runtime.dll',
                        'tools/sleuthkit-4.15.0-win32/licenses/LICENSE.txt',
                        *['evidence/' + name for name in package.DEMO_FILES]]
            excluded = ['evidence/private.dd', 'evidence/private.manifest.json', 'evidence/desktop.ini',
                        'cases/private/case.json', 'logs/startup.log', '.venv/test.txt', '.git/config',
                        '.test-work/output.txt', 'forensic/__pycache__/old.pyc', 'docs/latest-demo.txt',
                        'docs/validation/test-results.txt', 'docs/ui/README.md', 'docs/私有文档.md',
                        'AGENTS.md', 'docs/AGENTS.md']
            for name in included + excluded:
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('fixture', encoding='utf-8')
            with patch.object(package, 'ROOT', root), patch('builtins.print'):
                output = package.build()
            with ZipFile(output) as archive:
                names = set(archive.namelist())
            self.assertEqual(names, {'ForensicTool/' + name for name in included} | {'ForensicTool/cases/.gitkeep'})
