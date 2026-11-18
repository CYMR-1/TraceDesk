"""Qt 桌面外观：白灰底色、多彩功能强调和原生高 DPI。"""
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

from ..paths import ASSET_DIR


class DesktopAppearance:
    """尺寸使用 Qt 逻辑像素，由 Qt 6 自动适配显示器缩放。"""

    BACKGROUND = '#f5f6f8'
    SURFACE = '#ffffff'
    FOREGROUND = '#24332f'
    MUTED = '#687570'
    BORDER = '#e2e7e5'
    ACCENT = '#087f6b'
    DELETED = '#b64262'

    def __init__(self, root):
        self.root = root
        self.fonts = {}

    @staticmethod
    def px(value):
        return round(value)

    def configure(self):
        app = QApplication.instance()
        app.setStyle('Fusion')
        available = set(QFontDatabase.families())
        family = next((name for name in ('Microsoft YaHei UI', 'Microsoft YaHei',
                                         'Noto Sans CJK SC', 'Arial') if name in available),
                      app.font().family())
        font = QFont(family)
        font.setPointSizeF(10)
        app.setFont(font)
        self.root.setFont(font)
        fixed = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        if 'Consolas' in available:
            fixed.setFamily('Consolas')
        fixed.setPointSizeF(10.5)
        self.fonts = {'text': font, 'fixed': fixed}

        palette = QPalette()
        colors = {
            QPalette.ColorRole.Window: self.BACKGROUND,
            QPalette.ColorRole.WindowText: self.FOREGROUND,
            QPalette.ColorRole.Base: '#ffffff',
            QPalette.ColorRole.AlternateBase: '#f8faf9',
            QPalette.ColorRole.Text: self.FOREGROUND,
            QPalette.ColorRole.Button: '#ffffff',
            QPalette.ColorRole.ButtonText: self.FOREGROUND,
            QPalette.ColorRole.Highlight: '#dff3eb',
            QPalette.ColorRole.HighlightedText: '#145b4a',
            QPalette.ColorRole.ToolTipBase: '#ffffff',
            QPalette.ColorRole.ToolTipText: self.FOREGROUND,
            QPalette.ColorRole.Link: self.ACCENT,
            QPalette.ColorRole.LinkVisited: '#7352b8',
            QPalette.ColorRole.PlaceholderText: '#89948f',
            QPalette.ColorRole.Light: '#ffffff',
            QPalette.ColorRole.Midlight: '#f5f6f8',
            QPalette.ColorRole.Mid: self.BORDER,
            QPalette.ColorRole.Dark: '#acb8b2',
            QPalette.ColorRole.Shadow: '#89948f',
        }
        for role, color in colors.items():
            palette.setColor(role, QColor(color))
        for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text,
                     QPalette.ColorRole.ButtonText):
            palette.setColor(QPalette.ColorGroup.Disabled, role, QColor('#98a29d'))
        app.setPalette(palette)
        app.setStyleSheet('''
            QMainWindow, QWidget#workbench { background: #f5f6f8; }
            QDialog { background: #ffffff; }
            QLabel { background: transparent; }
            QLabel[role="section"] { color: #30483e; font-weight: 600; }
            QFrame#navigationPanel, QFrame#resultsPanel, QFrame#previewPanel {
                background: #ffffff; border: 1px solid #e2e7e5; border-radius: 6px;
            }
            QTreeWidget#evidenceTree { background: #ffffff; border: none; }
            QTreeWidget#evidenceTree::item { padding: 5px 3px; }
            QLabel[role="muted"], QLabel#muted { color: #687570; }
            QLabel[role="title"] { color: #1e3b33; }
            QLabel#caseSummary {
                background: #edf4f1; color: #48635a; border: 1px solid #dce9e2;
                border-radius: 8px; padding: 8px 12px;
            }
            QLabel#breadcrumb { color: #4f665d; padding: 2px 0; }
            QLabel#sectionTitle { color: #24332f; font-size: 16px; font-weight: 600; }
            QFrame[role="card"] {
                background: #ffffff; border: 1px solid #e2e7e5; border-radius: 10px;
            }
            QPushButton {
                background: #ffffff; color: #34483f; border: 1px solid #d8e0db;
                border-radius: 7px; padding: 6px 12px; min-height: 20px;
            }
            QPushButton:hover { background: #edf6f1; border-color: #9dcbbb; }
            QPushButton:pressed { background: #dff0e8; }
            QPushButton:focus { border-color: #087f6b; }
            QPushButton:disabled { color: #98a29d; background: #f7f9f8; border-color: #e8ece9; }
            QPushButton[role="accent"], QPushButton[accent="true"] {
                background: #087f6b; color: #ffffff; border-color: #087f6b; font-weight: 600;
            }
            QPushButton[role="accent"]:hover, QPushButton[accent="true"]:hover { background: #096b5b; }
            QPushButton[role="accent"]:pressed, QPushButton[accent="true"]:pressed { background: #075b4d; }
            QPushButton[role="accent"]:focus, QPushButton[accent="true"]:focus { border-color: #043e34; }
            QPushButton[role="accent"]:disabled, QPushButton[accent="true"]:disabled {
                background: #e5eeea; color: #8b9f95; border-color: #e5eeea;
            }
            QPushButton[role="violet"] {
                background: #f0eafa; color: #6947a6; border-color: #e2d7f1; font-weight: 600;
            }
            QPushButton[role="violet"]:hover { background: #e6daf6; border-color: #b6a0da; }
            QPushButton[role="soft"] { background: #eaf6f0; color: #13765e; border-color: #d2eadd; }
            QPushButton[role="soft"]:hover { background: #dcefe5; border-color: #9dcbbb; }
            QPushButton[role="violet"]:disabled, QPushButton[role="soft"]:disabled {
                background: #f7f9f8; color: #98a29d; border-color: #e8ece9;
            }
            QPushButton#exportOk {
                background: #1671d9; color: #ffffff; border-color: #1671d9;
                font-weight: 600; min-width: 54px;
            }
            QPushButton#exportOk:hover { background: #1261bf; border-color: #1261bf; }
            QPushButton#exportOk:pressed { background: #0e50a1; border-color: #0e50a1; }
            QPushButton#exportOk:focus { border-color: #09396f; }
            QLineEdit, QComboBox {
                background: #ffffff; color: #24332f; border: 1px solid #d8e0db;
                border-radius: 7px; padding: 6px 9px; min-height: 20px;
                selection-background-color: #dff3eb; selection-color: #145b4a;
            }
            QLineEdit:hover, QComboBox:hover { border-color: #a8c5b7; }
            QLineEdit:focus, QComboBox:focus { border-color: #087f6b; }
            QLineEdit:disabled, QComboBox:disabled { color: #98a29d; border-color: #e8ece9; }
            QComboBox::drop-down { border: none; width: 24px; }
            QComboBox { padding-right: 24px; }
            QComboBox::down-arrow { image: url("@CHEVRON@"); width: 12px; height: 12px; }
            QComboBox QAbstractItemView {
                background: #ffffff; color: #24332f; border: 1px solid #d8e0db;
                selection-background-color: #dff3eb; selection-color: #145b4a;
            }
            QTabBar::tab {
                background: transparent; color: #687570; padding: 7px 13px;
                border: 1px solid transparent; border-radius: 7px; margin-right: 4px;
            }
            QTabBar::tab:selected { color: #086b55; background: #e5f4ec; border-color: #c8e6d7; }
            QTabBar::tab:hover:!selected { background: #edf0f2; }
            QTabBar#moduleTabs::tab:selected {
                background: #e0f1e9; color: #086b55; border-color: #bfdfcf; font-weight: 600;
            }
            QTreeView, QTableView, QPlainTextEdit {
                background: #ffffff; alternate-background-color: #f8faf9; color: #24332f;
                border: 1px solid #e7ece9; border-radius: 5px;
                selection-background-color: #dff3eb; selection-color: #145b4a; outline: none;
            }
            QPlainTextEdit { padding: 7px; }
            QTreeView::item, QTableView::item { padding: 5px 6px; }
            QTreeView::item:hover, QTableView::item:hover { background: #f0f7f3; }
            QTreeView::item:selected, QTableView::item:selected {
                background: #dff3eb; color: #145b4a;
            }
            QHeaderView::section {
                background: #f3f6f5; color: #5b6d64; padding: 9px 6px;
                border: none; border-bottom: 1px solid #dfe7e2;
                font-weight: 600;
            }
            QSplitter::handle { background: #f5f6f8; }
            QSplitter::handle:hover { background: #c4dfd2; }
            QProgressBar { border: none; border-radius: 3px; background: #e6eae8; max-height: 7px; }
            QProgressBar::chunk { background: #1aa680; border-radius: 3px; }
            QScrollBar:vertical { background: transparent; width: 11px; margin: 0; }
            QScrollBar:horizontal { background: transparent; height: 11px; margin: 0; }
            QScrollBar::handle:vertical { background: #c6d1cb; min-height: 26px; border: 2px solid white; border-radius: 5px; }
            QScrollBar::handle:horizontal { background: #c6d1cb; min-width: 26px; border: 2px solid white; border-radius: 5px; }
            QScrollBar::handle:hover { background: #94ac9f; }
            QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
            QScrollBar::add-page, QScrollBar::sub-page { background: none; }
            QToolTip { background: #ffffff; color: #24332f; border: 1px solid #b6c9be; padding: 6px; }
        '''.replace('@CHEVRON@', (ASSET_DIR / 'chevron-down.svg').as_posix()))
        return self

    @staticmethod
    def work_area(root):
        screen = root.screen() or QApplication.primaryScreen()
        if screen is None:
            return 0, 0, 1280, 800
        area = screen.availableGeometry()
        return area.x(), area.y(), area.width(), area.height()

    def fit_window(self, width=1360, height=900, min_width=900, min_height=640):
        left, top, screen_width, screen_height = self.work_area(self.root)
        available_width = max(1, screen_width - 32)
        available_height = max(1, screen_height - 56)
        width, height = min(width, available_width), min(height, available_height)
        self.root.setMinimumSize(min(min_width, available_width), min(min_height, available_height))
        self.root.resize(width, height)
        self.root.move(left + (screen_width - width) // 2, top + 16)
