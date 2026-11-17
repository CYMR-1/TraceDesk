"""项目资源与默认运行目录；始终相对源码定位，不依赖当前工作目录。"""
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
ROOT = PACKAGE_DIR.parent
ASSET_DIR = PACKAGE_DIR / 'assets'
EVIDENCE_DIR = ROOT / 'evidence'
CASES_DIR = ROOT / 'cases'
LOGS_DIR = ROOT / 'logs'
TOOLS_DIR = ROOT / 'tools'
TEST_WORK_DIR = ROOT / '.test-work'
