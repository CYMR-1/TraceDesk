"""Qt 桌面外观：原生高 DPI、中文字体和暖米白砂岩主题。"""
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication


class DesktopAppearance:
    """尺寸使用 Qt 逻辑像素，由 Qt 6 自动适配显示器缩放。"""

    BACKGROUND = '#f2eee7'
    SURFACE = '#fcf9f3'
    FOREGROUND = '#332f27'
    MUTED = '#746b5c'
    BORDER = '#d8cdbb'
    ACCENT = '#95672f'
    DELETED = '#a34d2e'

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
        font.setPointSizeF(10.5)
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
            QPalette.ColorRole.Base: '#fcf9f3',
            QPalette.ColorRole.AlternateBase: '#f4efe5',
            QPalette.ColorRole.Text: self.FOREGROUND,
            QPalette.ColorRole.Button: '#e9e1d3',
            QPalette.ColorRole.ButtonText: self.FOREGROUND,
            QPalette.ColorRole.Highlight: '#ead9b7',
            QPalette.ColorRole.HighlightedText: '#4a351a',
            QPalette.ColorRole.ToolTipBase: '#fff3da',
            QPalette.ColorRole.ToolTipText: self.FOREGROUND,
            QPalette.ColorRole.Link: self.ACCENT,
            QPalette.ColorRole.LinkVisited: '#795c3d',
            QPalette.ColorRole.PlaceholderText: '#827767',
            QPalette.ColorRole.Light: '#fffcf7',
            QPalette.ColorRole.Midlight: '#efe6d7',
            QPalette.ColorRole.Mid: self.BORDER,
            QPalette.ColorRole.Dark: '#bbae98',
            QPalette.ColorRole.Shadow: '#998b75',
        }
        for role, color in colors.items():
            palette.setColor(role, QColor(color))
        for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text,
                     QPalette.ColorRole.ButtonText):
            palette.setColor(QPalette.ColorGroup.Disabled, role, QColor('#807566'))
        app.setPalette(palette)
        app.setStyleSheet('''
            QMainWindow, QDialog, QWidget#workbench { background: #f2eee7; }
            QLabel { background: transparent; }
            QLabel[role="muted"], QLabel#muted { color: #746b5c; }
            QLabel[role="title"] { color: #332f27; }
            QLabel#sectionTitle { color: #332f27; font-size: 16px; font-weight: 600; }
            QFrame[role="card"] {
                background: #fcf9f3; border: 1px solid #d8cdbb; border-radius: 6px;
            }
            QPushButton {
                background: #e9e1d3; color: #332f27; border: 1px solid #ccbea8;
                border-radius: 5px; padding: 7px 13px; min-height: 20px;
            }
            QPushButton:hover { background: #e1d4bf; border-color: #ae854b; }
            QPushButton:pressed { background: #d6c3a2; }
            QPushButton:focus { border-color: #95672f; }
            QPushButton:disabled { color: #807566; background: #fcf9f3; border-color: #d8cdbb; }
            QPushButton[role="accent"], QPushButton[accent="true"] {
                background: #95672f; color: #fff8e9; border-color: #95672f; font-weight: 600;
            }
            QPushButton[role="accent"]:hover, QPushButton[accent="true"]:hover { background: #a3763c; }
            QPushButton[role="accent"]:pressed, QPushButton[accent="true"]:pressed { background: #7b5428; }
            QPushButton[role="accent"]:disabled, QPushButton[accent="true"]:disabled {
                background: #e0d2bb; color: #786a56; border-color: #e0d2bb;
            }
            QLineEdit, QComboBox {
                background: #fffdf8; color: #332f27; border: 1px solid #ccbea8;
                border-radius: 4px; padding: 6px 8px; min-height: 20px;
                selection-background-color: #ead9b7; selection-color: #4a351a;
            }
            QLineEdit:focus, QComboBox:focus { border-color: #95672f; }
            QLineEdit:disabled, QComboBox:disabled { color: #807566; border-color: #d8cdbb; }
            QComboBox::drop-down { border: none; width: 24px; }
            QComboBox QAbstractItemView {
                background: #fcf9f3; color: #332f27; border: 1px solid #ccbea8;
                selection-background-color: #ead9b7; selection-color: #4a351a;
            }
            QTabWidget::pane { border: 1px solid #d8cdbb; background: #fcf9f3; }
            QTabBar::tab {
                background: #e8e0d2; color: #746b5c; padding: 10px 18px;
                border: 1px solid #d8cdbb; border-bottom: 2px solid #d8cdbb;
                margin-right: 3px;
            }
            QTabBar::tab:selected { color: #855a25; background: #fcf9f3; border-bottom-color: #95672f; }
            QTabBar::tab:hover:!selected { background: #e1d4bf; }
            QTreeView, QTableView, QPlainTextEdit {
                background: #fcf9f3; alternate-background-color: #f4efe5; color: #332f27;
                border: 1px solid #d8cdbb; selection-background-color: #ead9b7;
                selection-color: #4a351a; outline: none;
            }
            QTreeView::item, QTableView::item { padding: 6px 4px; }
            QTreeView::item:selected, QTableView::item:selected {
                background: #ead9b7; color: #4a351a;
            }
            QHeaderView::section {
                background: #e8dfcf; color: #61513a; padding: 9px 6px;
                border: none; border-right: 1px solid #d8cdbb; border-bottom: 1px solid #d8cdbb;
                font-weight: 600;
            }
            QSplitter::handle { background: #d8cdbb; }
            QSplitter::handle:hover { background: #b28d55; }
            QProgressBar { border: none; border-radius: 3px; background: #e4dac9; max-height: 7px; }
            QProgressBar::chunk { background: #95672f; border-radius: 3px; }
            QScrollBar:vertical { background: #fcf9f3; width: 13px; margin: 0; }
            QScrollBar:horizontal { background: #fcf9f3; height: 13px; margin: 0; }
            QScrollBar::handle:vertical { background: #c5b69d; min-height: 26px; border-radius: 5px; }
            QScrollBar::handle:horizontal { background: #c5b69d; min-width: 26px; border-radius: 5px; }
            QScrollBar::handle:hover { background: #a58b62; }
            QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
            QScrollBar::add-page, QScrollBar::sub-page { background: none; }
            QToolTip { background: #fff3da; color: #332f27; border: 1px solid #ae854b; padding: 5px; }
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
