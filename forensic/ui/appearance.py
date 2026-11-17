"""Qt 桌面外观：原生高 DPI、中文字体和白色与浅灰主题。"""
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication


class DesktopAppearance:
    """尺寸使用 Qt 逻辑像素，由 Qt 6 自动适配显示器缩放。"""

    BACKGROUND = '#ffffff'
    SURFACE = '#ffffff'
    FOREGROUND = '#303030'
    MUTED = '#737373'
    BORDER = '#e3e3e3'
    ACCENT = '#555555'
    DELETED = '#555555'

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
            QPalette.ColorRole.AlternateBase: '#fafafa',
            QPalette.ColorRole.Text: self.FOREGROUND,
            QPalette.ColorRole.Button: '#ffffff',
            QPalette.ColorRole.ButtonText: self.FOREGROUND,
            QPalette.ColorRole.Highlight: '#e8e8e8',
            QPalette.ColorRole.HighlightedText: '#303030',
            QPalette.ColorRole.ToolTipBase: '#ffffff',
            QPalette.ColorRole.ToolTipText: self.FOREGROUND,
            QPalette.ColorRole.Link: self.ACCENT,
            QPalette.ColorRole.LinkVisited: '#555555',
            QPalette.ColorRole.PlaceholderText: '#808080',
            QPalette.ColorRole.Light: '#ffffff',
            QPalette.ColorRole.Midlight: '#f5f5f5',
            QPalette.ColorRole.Mid: self.BORDER,
            QPalette.ColorRole.Dark: '#aaaaaa',
            QPalette.ColorRole.Shadow: '#999999',
        }
        for role, color in colors.items():
            palette.setColor(role, QColor(color))
        for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text,
                     QPalette.ColorRole.ButtonText):
            palette.setColor(QPalette.ColorGroup.Disabled, role, QColor('#999999'))
        app.setPalette(palette)
        app.setStyleSheet('''
            QMainWindow, QDialog, QWidget#workbench { background: #ffffff; }
            QLabel { background: transparent; }
            QLabel[role="section"] { font-weight: 600; }
            QFrame#navigationPanel { background: #fafafa; border: 1px solid #e3e3e3; border-radius: 4px; }
            QTreeWidget#evidenceTree { background: #fafafa; border: none; }
            QPlainTextEdit#fileMetadata { padding: 8px; }
            QLabel[role="muted"], QLabel#muted { color: #737373; }
            QLabel[role="title"] { color: #303030; }
            QLabel#sectionTitle { color: #303030; font-size: 16px; font-weight: 600; }
            QFrame[role="card"] {
                background: #ffffff; border: 1px solid #e3e3e3; border-radius: 6px;
            }
            QPushButton {
                background: #ffffff; color: #303030; border: 1px solid #d7d7d7;
                border-radius: 5px; padding: 5px 10px; min-height: 20px;
            }
            QPushButton:hover { background: #f0f0f0; border-color: #aaaaaa; }
            QPushButton:pressed { background: #e5e5e5; }
            QPushButton:focus { border-color: #555555; }
            QPushButton:disabled { color: #999999; background: #ffffff; border-color: #e3e3e3; }
            QPushButton[role="accent"], QPushButton[accent="true"] {
                background: #ededed; color: #303030; border-color: #d6d6d6; font-weight: 600;
            }
            QPushButton[role="accent"]:hover, QPushButton[accent="true"]:hover { background: #e4e4e4; }
            QPushButton[role="accent"]:pressed, QPushButton[accent="true"]:pressed { background: #d9d9d9; }
            QPushButton[role="accent"]:disabled, QPushButton[accent="true"]:disabled {
                background: #f5f5f5; color: #999999; border-color: #f5f5f5;
            }
            QLineEdit, QComboBox {
                background: #ffffff; color: #303030; border: 1px solid #d7d7d7;
                border-radius: 4px; padding: 6px 8px; min-height: 20px;
                selection-background-color: #e8e8e8; selection-color: #303030;
            }
            QLineEdit:focus, QComboBox:focus { border-color: #555555; }
            QLineEdit:disabled, QComboBox:disabled { color: #999999; border-color: #e3e3e3; }
            QComboBox::drop-down { border: none; width: 24px; }
            QComboBox QAbstractItemView {
                background: #ffffff; color: #303030; border: 1px solid #d7d7d7;
                selection-background-color: #e8e8e8; selection-color: #303030;
            }
            QTabWidget::pane { border: 1px solid #e3e3e3; background: #ffffff; }
            QTabBar::tab {
                background: #f7f7f7; color: #737373; padding: 7px 14px;
                border: 1px solid #e3e3e3; border-bottom: 2px solid #e3e3e3;
                margin-right: 3px;
            }
            QTabBar::tab:selected { color: #303030; background: #ffffff; border-bottom-color: #555555; }
            QTabBar::tab:hover:!selected { background: #f0f0f0; }
            QTreeView, QTableView, QPlainTextEdit {
                background: #ffffff; alternate-background-color: #fafafa; color: #303030;
                border: 1px solid #e3e3e3; selection-background-color: #e8e8e8;
                selection-color: #303030; outline: none;
            }
            QTreeView::item, QTableView::item { padding: 4px 4px; }
            QTreeView::item:selected, QTableView::item:selected {
                background: #e8e8e8; color: #303030;
            }
            QHeaderView::section {
                background: #f7f7f7; color: #666666; padding: 7px 6px;
                border: none; border-right: 1px solid #e3e3e3; border-bottom: 1px solid #e3e3e3;
                font-weight: 600;
            }
            QSplitter::handle { background: #e3e3e3; }
            QSplitter::handle:hover { background: #bbbbbb; }
            QProgressBar { border: none; border-radius: 3px; background: #eeeeee; max-height: 7px; }
            QProgressBar::chunk { background: #555555; border-radius: 3px; }
            QScrollBar:vertical { background: #ffffff; width: 13px; margin: 0; }
            QScrollBar:horizontal { background: #ffffff; height: 13px; margin: 0; }
            QScrollBar::handle:vertical { background: #cccccc; min-height: 26px; border-radius: 5px; }
            QScrollBar::handle:horizontal { background: #cccccc; min-width: 26px; border-radius: 5px; }
            QScrollBar::handle:hover { background: #aaaaaa; }
            QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
            QScrollBar::add-page, QScrollBar::sub-page { background: none; }
            QToolTip { background: #ffffff; color: #303030; border: 1px solid #aaaaaa; padding: 5px; }
        ''')
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
