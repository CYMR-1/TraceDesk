"""Qt 桌面外观：Archival Slate & Prussian Ink 配色、调色板、模块化 QSS 与原生高 DPI。"""
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

from ..paths import ASSET_DIR
from . import theme


def _asset_url(filename: str) -> str:
    return (ASSET_DIR / filename).as_posix()


def build_stylesheet() -> str:
    """组装全局模块化 QSS；所有颜色均来自 theme.py，所有控件图标均使用本地 SVG。"""
    t = theme
    sections = (
        # 1. Base windows, dialogs, typography labels
        f'''
        QMainWindow, QWidget#workbench {{
            background: {t.CANVAS_BG};
        }}
        QDialog {{
            background: {t.SURFACE_BG};
        }}
        QLabel {{
            background: transparent;
            color: {t.TEXT_PRIMARY};
        }}
        QLabel[role="section"] {{
            color: #1E2B3A;
            font-size: 13px;
            font-weight: 600;
        }}
        QLabel[role="muted"], QLabel#muted {{
            color: {t.TEXT_MUTED};
        }}
        QLabel[role="title"] {{
            color: {t.TEXT_PRIMARY};
        }}
        QLabel#sectionTitle {{
            color: {t.TEXT_PRIMARY};
            font-size: 17px;
            font-weight: 600;
        }}
        QLabel#timelineStatus {{
            font-size: 12px;
            font-weight: 600;
            color: {t.TEXT_SECONDARY};
        }}
        QLabel#fileResultCount {{
            font-size: 11.5px;
            color: {t.TEXT_MUTED};
        }}
        QLabel#filePageNumber, QLabel[role="pageBadge"] {{
            font-size: 11.5px;
            color: {t.TEXT_SECONDARY};
            background: {t.SURFACE_BG};
            border: 1px solid {t.BORDER_SUBTLE};
            border-radius: 4px;
            padding: 2px 8px;
        }}
        QLabel#filePageNumber:hover, QLabel[role="pageBadge"]:hover {{
            background: {t.ACCENT_SOFT_BG};
            border-color: {t.ACCENT_SOFT_BORDER};
            color: {t.ACCENT_SOFT_TEXT};
        }}
        QLabel#breadcrumb {{
            color: #4A596A;
            font-size: 11.5px;
            padding: 1px 0;
        }}
        ''',
        # 2. Case custody bar & standalone summary fallback
        f'''
        QLabel#caseSummary {{
            background: {t.CHROME_BG};
            color: #2B3948;
            border: none;
            border-bottom: 1px solid {t.BORDER_DEFAULT};
            border-left: 3px solid {t.BORDER_STRONG};
            padding: 7px 14px;
            font-size: 12px;
        }}
        QFrame#caseCustodyBar {{
            background: {t.CHROME_BG};
            border: none;
            border-bottom: 1px solid {t.BORDER_DEFAULT};
            border-left: 3px solid {t.BORDER_STRONG};
            min-height: 36px;
        }}
        QFrame#caseCustodyBar[custodyState="idle"] {{
            border-left-color: {t.BORDER_STRONG};
        }}
        QFrame#caseCustodyBar[custodyState="active"] {{
            border-left-color: {t.ACCENT};
        }}
        QFrame#caseCustodyBar[custodyState="verified"] {{
            border-left-color: {t.OK_FG};
        }}
        QFrame#caseCustodyBar[custodyState="warning"] {{
            border-left-color: {t.WARN_FG};
        }}
        QFrame#caseCustodyBar[custodyState="error"] {{
            border-left-color: {t.DANGER_FG};
        }}
        QFrame#caseCustodyBar QLabel#caseSummary {{
            background: transparent;
            border: none;
            border-radius: 0;
            padding: 7px 14px;
            color: #2B3948;
            font-size: 12px;
        }}
        QFrame#caseCustodyBar[custodyState="idle"] QLabel#caseSummary {{
            color: {t.TEXT_MUTED};
        }}
        ''',
        # 3. Flush panes, headers, toolbars, footers, empty state
        f'''
        QFrame#navigationPanel {{
            background: {t.CHROME_BG};
            border: none;
            border-radius: 0;
        }}
        QFrame#resultsPanel, QFrame#previewPanel {{
            background: {t.SURFACE_BG};
            border: none;
            border-radius: 0;
        }}
        QFrame#paneHeader {{
            background: {t.CHROME_BG};
            border: none;
            border-bottom: 1px solid {t.BORDER_PANE};
        }}
        QFrame#navigationPanel QFrame#paneHeader {{
            background: {t.CHROME_SUBTLE};
        }}
        QFrame#paneFooter {{
            background: {t.CHROME_BG};
            border: none;
            border-top: 1px solid {t.BORDER_PANE};
        }}
        QFrame#navigationPanel QFrame#paneFooter {{
            background: {t.CHROME_SUBTLE};
        }}
        QFrame#filterToolbar {{
            background: {t.SURFACE_SUBTLE};
            border: none;
            border-bottom: 1px solid {t.BORDER_SUBTLE};
        }}
        QFrame#breadcrumbBar {{
            background: {t.SURFACE_BG};
            border: none;
            border-bottom: 1px solid {t.BORDER_SOFT_RULE};
        }}
        QFrame#tableFooter, QFrame#previewFooter {{
            background: {t.SURFACE_SUBTLE};
            border: none;
            border-top: 1px solid {t.BORDER_SUBTLE};
        }}
        QFrame#panelTopBar {{
            background: {t.CHROME_BG};
            border: none;
            border-bottom: 1px solid {t.BORDER_DEFAULT};
        }}
        QFrame#panelSubBar {{
            background: {t.SURFACE_TINT};
            border: none;
            border-bottom: 1px solid {t.BORDER_SUBTLE};
        }}
        QFrame#panelSectionBar {{
            background: {t.CHROME_BG};
            border: none;
            border-top: 1px solid {t.BORDER_PANE};
            border-bottom: 1px solid {t.BORDER_PANE};
        }}
        QFrame#previewModeBar {{
            background: {t.SURFACE_TINT};
            border: none;
            border-bottom: 1px solid {t.BORDER_SUBTLE};
        }}
        QFrame#previewEmptyState {{
            background: {t.SURFACE_BG};
            border: none;
        }}
        QLabel#previewEmptyTitle {{
            color: #4A596A;
            font-size: 13px;
            font-weight: 500;
        }}
        QLabel#previewEmptyHint {{
            color: #7A8899;
            font-size: 11.5px;
        }}
        QFrame#workbenchFooter {{
            background: {t.CHROME_BG};
            border: none;
            border-top: 1px solid {t.BORDER_DEFAULT};
            min-height: 28px;
            max-height: 28px;
        }}
        QFrame#workbenchFooter QLabel {{
            font-size: 11.5px;
            color: {t.TEXT_MUTED};
        }}
        QFrame#footerDivider {{
            background: {t.BORDER_DEFAULT};
            border: none;
            min-width: 1px;
            max-width: 1px;
            min-height: 12px;
            max-height: 12px;
        }}
        QFrame#toolbarDivider {{
            background: {t.BORDER_DEFAULT};
            border: none;
            min-width: 1px;
            max-width: 1px;
            min-height: 18px;
            max-height: 18px;
        }}
        QFrame#dialogHeaderBar {{
            background: {t.CHROME_BG};
            border: none;
            border-bottom: 1px solid {t.BORDER_DEFAULT};
        }}
        QFrame#dialogFooterBar {{
            background: {t.CHROME_BG};
            border: none;
            border-top: 1px solid {t.BORDER_SUBTLE};
        }}
        QLabel#imagePreview {{
            background: {t.IMAGE_BACKDROP};
            border: 1px solid {t.BORDER_PANE};
            border-radius: 4px;
            color: {t.TEXT_MUTED};
        }}
        ''',
        # 4. Dialog cards, callout banners & semantic status pills
        f'''
        QFrame[role="card"] {{
            background: {t.SURFACE_SUBTLE};
            border: 1px solid #D5DCE4;
            border-radius: 8px;
        }}
        QFrame[bannerState="warning"] {{
            background: {t.WARN_BG};
            border: 1px solid {t.WARN_BORDER};
            border-radius: 6px;
        }}
        QFrame[bannerState="warning"] QLabel {{
            color: {t.WARN_FG};
            background: transparent;
        }}
        QFrame[bannerState="warning"] QPlainTextEdit {{
            background: #FFFDF8;
            color: {t.WARN_FG};
            border: 1px solid {t.WARN_BORDER};
            border-radius: 4px;
            padding: 5px 8px;
            font-size: 12px;
        }}
        QFrame[bannerState="ok"] {{
            background: {t.OK_BG};
            border: 1px solid {t.OK_BORDER};
            border-radius: 6px;
        }}
        QFrame[bannerState="ok"] QLabel {{
            color: {t.OK_FG};
            background: transparent;
        }}
        QFrame[bannerState="error"] {{
            background: {t.DANGER_BG};
            border: 1px solid {t.DANGER_BORDER};
            border-radius: 6px;
        }}
        QFrame[bannerState="error"] QLabel {{
            color: {t.DANGER_FG};
            background: transparent;
        }}
        QLabel[statusState="running"] {{
            background: {t.OK_BG};
            color: {t.OK_FG};
            border: 1px solid {t.OK_BORDER};
            border-radius: 5px;
            padding: 6px 10px;
            font-weight: 600;
        }}
        QLabel[statusState="stopped"] {{
            background: {t.NEUTRAL_BG};
            color: {t.NEUTRAL_FG};
            border: 1px solid {t.NEUTRAL_BORDER};
            border-radius: 5px;
            padding: 6px 10px;
        }}
        QLabel[statusState="warning"] {{
            background: {t.WARN_BG};
            color: {t.WARN_FG};
            border: 1px solid {t.WARN_BORDER};
            border-radius: 5px;
            padding: 6px 10px;
            font-weight: 600;
        }}
        QLabel[statusState="error"] {{
            background: {t.DANGER_BG};
            color: {t.DANGER_FG};
            border: 1px solid {t.DANGER_BORDER};
            border-radius: 5px;
            padding: 6px 10px;
            font-weight: 600;
        }}
        ''',
        # 5. Buttons — daylight palette roles
        f'''
        QPushButton {{
            background: {t.SURFACE_BG};
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 5px;
            padding: 5px 12px;
            min-height: 18px;
            font-weight: 500;
        }}
        QPushButton:hover {{
            background: {t.SURFACE_HOVER};
            border-color: {t.BORDER_STRONG};
        }}
        QPushButton:pressed {{
            background: {t.SURFACE_SELECTED};
            border-color: {t.ACCENT};
        }}
        QPushButton:focus {{
            border-color: {t.BORDER_FOCUS};
        }}
        QPushButton:disabled {{
            background: {t.SURFACE_DISABLED};
            color: {t.TEXT_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QPushButton[role="accent"], QPushButton[accent="true"] {{
            background: {t.ACCENT};
            color: #FFFFFF;
            border: 1px solid {t.ACCENT};
            font-weight: 600;
        }}
        QPushButton[role="accent"]:hover, QPushButton[accent="true"]:hover {{
            background: {t.ACCENT_HOVER};
            border-color: {t.ACCENT_HOVER};
        }}
        QPushButton[role="accent"]:pressed, QPushButton[accent="true"]:pressed {{
            background: {t.ACCENT_PRESSED};
            border-color: {t.ACCENT_PRESSED};
        }}
        QPushButton[role="accent"]:focus, QPushButton[accent="true"]:focus {{
            border-color: #0B2545;
        }}
        QPushButton[role="accent"]:disabled, QPushButton[accent="true"]:disabled {{
            background: #D7E1EC;
            color: #8A9BB0;
            border-color: #D7E1EC;
        }}
        QPushButton[role="soft"], QPushButton[role="violet"] {{
            background: {t.ACCENT_SOFT_BG};
            color: {t.ACCENT_SOFT_TEXT};
            border: 1px solid {t.ACCENT_SOFT_BORDER};
            font-weight: 500;
        }}
        QPushButton[role="soft"]:hover, QPushButton[role="violet"]:hover {{
            background: #DCEAF8;
            border-color: #9BBEE3;
        }}
        QPushButton[role="soft"]:pressed, QPushButton[role="violet"]:pressed {{
            background: #CEE2F5;
            border-color: {t.ACCENT};
        }}
        QPushButton[role="soft"]:disabled, QPushButton[role="violet"]:disabled {{
            background: {t.SURFACE_DISABLED};
            color: {t.TEXT_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QPushButton[role="ghost"] {{
            background: transparent;
            color: {t.TEXT_SECONDARY};
            border: 1px solid transparent;
        }}
        QPushButton[role="ghost"]:hover {{
            background: {t.SURFACE_HOVER};
            color: {t.TEXT_PRIMARY};
            border-color: {t.BORDER_SUBTLE};
        }}
        QPushButton[role="ghost"]:pressed {{
            background: {t.SURFACE_SELECTED};
            color: {t.SURFACE_SELECTED_TEXT};
        }}
        QPushButton[role="ghost"]:disabled {{
            background: transparent;
            color: {t.TEXT_DISABLED};
            border-color: transparent;
        }}
        QPushButton[role="compact"] {{
            background: {t.SURFACE_BG};
            color: {t.TEXT_SECONDARY};
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 4px;
            padding: 2px 8px;
            min-height: 16px;
            font-size: 11.5px;
            font-weight: 500;
        }}
        QPushButton[role="compact"]:hover {{
            background: {t.SURFACE_HOVER};
            color: {t.ACCENT};
            border-color: {t.ACCENT_SOFT_BORDER};
        }}
        QPushButton[role="compact"]:pressed {{
            background: {t.SURFACE_SELECTED};
        }}
        QPushButton[role="compact"]:disabled {{
            background: {t.SURFACE_DISABLED};
            color: {t.TEXT_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QPushButton[role="pager"] {{
            background: {t.SURFACE_BG};
            color: {t.TEXT_SECONDARY};
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 4px;
            padding: 2px 9px;
            min-height: 16px;
            font-size: 11.5px;
            font-weight: 500;
        }}
        QPushButton[role="pager"]:hover {{
            background: {t.SURFACE_HOVER};
            color: {t.ACCENT};
            border-color: {t.ACCENT_SOFT_BORDER};
        }}
        QPushButton[role="pager"]:pressed {{
            background: {t.SURFACE_SELECTED};
        }}
        QPushButton[role="pager"]:disabled {{
            background: {t.SURFACE_DISABLED};
            color: {t.TEXT_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QPushButton[role="warning"] {{
            background: {t.WARN_BG};
            color: {t.WARN_FG};
            border: 1px solid {t.WARN_BORDER};
            font-weight: 600;
        }}
        QPushButton[role="warning"]:hover {{
            background: #FBECC9;
            border-color: #D8AD60;
        }}
        QPushButton[role="warning"]:pressed {{
            background: #F6DFAD;
            border-color: #BE8B35;
        }}
        QPushButton[role="warning"]:disabled {{
            background: {t.SURFACE_DISABLED};
            color: {t.TEXT_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QPushButton[role="warningAction"] {{
            background: #FFFDF7;
            color: {t.WARN_FG};
            border: 1px solid #DCBA7D;
            border-radius: 5px;
            padding: 4px 10px;
            min-height: 18px;
            font-weight: 600;
        }}
        QPushButton[role="warningAction"]:hover {{
            background: #FAECDA;
            border-color: #C49746;
        }}
        QPushButton[role="warningAction"]:pressed {{
            background: #F3DCB4;
        }}
        QPushButton[role="warningAction"]:disabled {{
            background: {t.SURFACE_DISABLED};
            color: {t.TEXT_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QPushButton#exportOk {{
            background: {t.ACCENT};
            color: #FFFFFF;
            border: 1px solid {t.ACCENT};
            font-weight: 600;
            min-width: 64px;
        }}
        QPushButton#exportOk:hover {{
            background: {t.ACCENT_HOVER};
            border-color: {t.ACCENT_HOVER};
        }}
        QPushButton#exportOk:pressed {{
            background: {t.ACCENT_PRESSED};
            border-color: {t.ACCENT_PRESSED};
        }}
        QPushButton#exportOk:focus {{
            border-color: #0B2545;
        }}
        ''',
        # 6. Signature Dark Command Ribbon (#workbenchHeader) — scoped strictly & after generic buttons
        f'''
        QFrame#workbenchHeader {{
            background: {t.HEADER_BG};
            border: none;
            border-bottom: 1px solid {t.HEADER_BORDER};
            min-height: 48px;
            max-height: 48px;
        }}
        QFrame#workbenchHeader QLabel {{
            color: {t.HEADER_TEXT};
            background: transparent;
        }}
        QFrame#workbenchHeader QLabel[role="title"] {{
            color: {t.HEADER_TEXT};
        }}
        QFrame#workbenchHeader QLabel[role="muted"] {{
            color: {t.HEADER_MUTED};
            font-size: 12px;
        }}
        QFrame#headerDivider {{
            background: {t.HEADER_DIVIDER};
            border: none;
            min-width: 1px;
            max-width: 1px;
            min-height: 16px;
            max-height: 16px;
        }}
        QFrame#workbenchHeader QPushButton,
        QFrame#workbenchHeader QPushButton[role="violet"],
        QFrame#workbenchHeader QPushButton[role="soft"] {{
            background: {t.HEADER_BTN_BG};
            color: {t.HEADER_TEXT};
            border: 1px solid {t.HEADER_BTN_BORDER};
            border-radius: 5px;
            padding: 4px 11px;
            min-height: 18px;
            font-weight: 500;
        }}
        QFrame#workbenchHeader QPushButton:hover,
        QFrame#workbenchHeader QPushButton[role="violet"]:hover,
        QFrame#workbenchHeader QPushButton[role="soft"]:hover {{
            background: {t.HEADER_BTN_HOVER};
            border-color: #466080;
        }}
        QFrame#workbenchHeader QPushButton:pressed,
        QFrame#workbenchHeader QPushButton[role="violet"]:pressed,
        QFrame#workbenchHeader QPushButton[role="soft"]:pressed {{
            background: {t.HEADER_BTN_PRESSED};
            border-color: #324761;
        }}
        QFrame#workbenchHeader QPushButton:focus {{
            border-color: #6BA9E8;
        }}
        QFrame#workbenchHeader QPushButton:disabled,
        QFrame#workbenchHeader QPushButton[role="violet"]:disabled,
        QFrame#workbenchHeader QPushButton[role="soft"]:disabled {{
            background: #1A2736;
            color: #5E738A;
            border-color: #26364A;
        }}
        QFrame#workbenchHeader QPushButton[role="pager"],
        QFrame#workbenchHeader QPushButton[role="ghost"] {{
            background: transparent;
            color: {t.HEADER_MUTED};
            border: 1px solid transparent;
            border-radius: 5px;
            padding: 4px 9px;
            min-height: 18px;
            font-size: 12px;
            font-weight: 500;
        }}
        QFrame#workbenchHeader QPushButton[role="pager"]:hover,
        QFrame#workbenchHeader QPushButton[role="ghost"]:hover {{
            background: {t.HEADER_GHOST_HOVER};
            color: {t.HEADER_TEXT};
            border-color: #2E425A;
        }}
        QFrame#workbenchHeader QPushButton[role="pager"]:pressed,
        QFrame#workbenchHeader QPushButton[role="ghost"]:pressed {{
            background: {t.HEADER_BTN_PRESSED};
            color: {t.HEADER_TEXT};
        }}
        QFrame#workbenchHeader QPushButton[actionKey="export_bundle"] {{
            background: {t.HEADER_PRIMARY_BG};
            color: #FFFFFF;
            border: 1px solid #3574BA;
            border-radius: 5px;
            padding: 4px 12px;
            min-height: 18px;
            font-weight: 600;
        }}
        QFrame#workbenchHeader QPushButton[actionKey="export_bundle"]:hover {{
            background: {t.HEADER_PRIMARY_HOVER};
            border-color: #4A89CF;
        }}
        QFrame#workbenchHeader QPushButton[actionKey="export_bundle"]:pressed {{
            background: {t.HEADER_PRIMARY_PRESSED};
            border-color: #1D518C;
        }}
        QFrame#workbenchHeader QPushButton[actionKey="export_bundle"]:disabled {{
            background: #1E3550;
            color: #6E88A6;
            border-color: #284466;
        }}
        ''',
        # 7. Inputs: QLineEdit, QComboBox, QSpinBox, EncodingChoice
        f'''
        QLineEdit, QComboBox, QSpinBox {{
            background: {t.SURFACE_BG};
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 5px;
            padding: 4px 9px;
            min-height: 20px;
            selection-background-color: {t.SURFACE_SELECTED};
            selection-color: {t.SURFACE_SELECTED_TEXT};
        }}
        QLineEdit:hover, QComboBox:hover, QSpinBox:hover {{
            border-color: {t.BORDER_STRONG};
        }}
        QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
            border-color: {t.BORDER_FOCUS};
        }}
        QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled {{
            background: {t.SURFACE_DISABLED};
            color: {t.TEXT_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QComboBox {{
            padding-right: 24px;
        }}
        QComboBox::drop-down {{
            border: none;
            width: 24px;
            background: transparent;
        }}
        QComboBox::down-arrow {{
            image: url("{_asset_url('chevron-down.svg')}");
            width: 12px;
            height: 12px;
        }}
        QComboBox QAbstractItemView {{
            background: {t.SURFACE_BG};
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 4px;
            padding: 2px;
            selection-background-color: {t.SURFACE_SELECTED};
            selection-color: {t.SURFACE_SELECTED_TEXT};
            outline: none;
        }}
        QSpinBox {{
            padding-right: 22px;
        }}
        QSpinBox::up-button {{
            subcontrol-origin: border;
            subcontrol-position: top right;
            width: 20px;
            margin-top: 1px;
            margin-right: 1px;
            border: none;
            border-left: 1px solid {t.BORDER_SUBTLE};
            border-bottom: 1px solid {t.BORDER_SUBTLE};
            border-top-right-radius: 4px;
            background: {t.SURFACE_SUBTLE};
        }}
        QSpinBox::down-button {{
            subcontrol-origin: border;
            subcontrol-position: bottom right;
            width: 20px;
            margin-bottom: 1px;
            margin-right: 1px;
            border: none;
            border-left: 1px solid {t.BORDER_SUBTLE};
            border-bottom-right-radius: 4px;
            background: {t.SURFACE_SUBTLE};
        }}
        QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
            background: {t.SURFACE_HOVER};
            border-left-color: {t.BORDER_DEFAULT};
        }}
        QSpinBox::up-button:pressed, QSpinBox::down-button:pressed {{
            background: {t.SURFACE_SELECTED};
            border-left-color: {t.ACCENT};
        }}
        QSpinBox::up-button:disabled, QSpinBox::down-button:disabled {{
            background: {t.SURFACE_DISABLED};
            border-left-color: {t.BORDER_SUBTLE};
        }}
        QSpinBox::up-arrow {{
            image: url("{_asset_url('chevron-up.svg')}");
            width: 9px;
            height: 9px;
        }}
        QSpinBox::down-arrow {{
            image: url("{_asset_url('chevron-down.svg')}");
            width: 9px;
            height: 9px;
        }}
        QWidget#previewEncoding {{
            background: transparent;
        }}
        QWidget#previewEncoding QLabel {{
            font-size: 11.5px;
            color: {t.TEXT_MUTED};
        }}
        QComboBox#previewEncodingChoice {{
            font-size: 12px;
            padding: 2px 24px 2px 8px;
            min-height: 18px;
            border-radius: 4px;
            combobox-popup: 0;
        }}
        QComboBox#previewEncodingChoice QListView::item {{
            min-height: 22px;
            padding: 1px 8px;
        }}
        ''',
        # 8. Tabs — generic QTabWidget, module tab strip, preview mode tabs
        f'''
        QTabWidget::pane {{
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 5px;
            background: {t.SURFACE_BG};
            top: -1px;
        }}
        QTabBar::tab {{
            background: {t.CHROME_BG};
            color: {t.TEXT_SECONDARY};
            padding: 6px 14px;
            border: 1px solid {t.BORDER_SUBTLE};
            border-bottom: none;
            border-top-left-radius: 5px;
            border-top-right-radius: 5px;
            margin-right: 3px;
            font-weight: 500;
        }}
        QTabBar::tab:hover:!selected {{
            background: {t.SURFACE_HOVER};
            color: {t.TEXT_PRIMARY};
        }}
        QTabBar::tab:selected {{
            background: {t.SURFACE_BG};
            color: {t.ACCENT};
            border-color: {t.BORDER_DEFAULT};
            font-weight: 600;
        }}
        QFrame#tabStrip {{
            background: {t.CANVAS_BG};
            border: none;
            border-bottom: 1px solid {t.BORDER_DEFAULT};
        }}
        QTabBar#moduleTabs {{
            background: transparent;
            border: none;
        }}
        QTabBar#moduleTabs::tab {{
            background: transparent;
            color: #4A596A;
            padding: 0 14px;
            min-height: 35px;
            border: none;
            border-bottom: 2.5px solid transparent;
            border-radius: 0;
            margin-right: 2px;
            font-weight: 500;
        }}
        QTabBar#moduleTabs::tab:hover:!selected {{
            background: #DDE4EC;
            color: {t.TEXT_PRIMARY};
        }}
        QTabBar#moduleTabs::tab:selected {{
            background: transparent;
            color: {t.HEADER_BG};
            border: none;
            border-bottom: 2.5px solid {t.ACCENT};
            font-weight: 600;
        }}
        QTabBar#previewTabs {{
            background: transparent;
            border: none;
            font-size: 12px;
        }}
        QTabBar#previewTabs::tab {{
            background: transparent;
            color: {t.TEXT_MUTED};
            padding: 4px 11px;
            border: none;
            border-bottom: 2px solid transparent;
            border-radius: 0;
            margin-right: 2px;
            font-weight: 500;
        }}
        QTabBar#previewTabs::tab:hover:!selected {{
            background: #ECF1F7;
            color: {t.TEXT_PRIMARY};
        }}
        QTabBar#previewTabs::tab:selected {{
            background: transparent;
            color: {t.ACCENT};
            border: none;
            border-bottom: 2px solid {t.ACCENT};
            font-weight: 600;
        }}
        ''',
        # 9. Trees, tables, editors, branches, indicators, headers
        f'''
        QTreeView, QTableView, QPlainTextEdit, QTextBrowser {{
            background: {t.SURFACE_BG};
            alternate-background-color: {t.SURFACE_SUBTLE};
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 4px;
            selection-background-color: {t.SURFACE_SELECTED};
            selection-color: {t.SURFACE_SELECTED_TEXT};
            outline: none;
        }}
        QPlainTextEdit {{
            padding: 8px 10px;
        }}
        QTreeWidget#evidenceTree {{
            background: {t.CHROME_BG};
            alternate-background-color: {t.CHROME_BG};
            border: none;
            border-radius: 0;
        }}
        QTreeWidget#fileResults, QTreeWidget#hexPreview {{
            border: none;
            border-radius: 0;
        }}
        QFrame#previewPanel QPlainTextEdit {{
            border: none;
            border-radius: 0;
            padding: 10px 14px;
        }}
        QTreeWidget[flush="true"], QTreeView[flush="true"],
        QPlainTextEdit[flush="true"], QTextBrowser[flush="true"] {{
            border: none;
            border-radius: 0;
        }}
        QPlainTextEdit[surface="code"] {{
            background: {t.SURFACE_SUBTLE};
            border: 1px solid {t.BORDER_SUBTLE};
            border-radius: 6px;
            padding: 8px 10px;
        }}
        QPlainTextEdit[surface="raw"] {{
            background: {t.SURFACE_TINT};
            border: none;
            border-radius: 0;
            padding: 8px 12px;
        }}
        QTreeView::item, QTableView::item {{
            padding: 2px 6px;
            border: none;
        }}
        QTreeWidget#evidenceTree::item {{
            padding: 2px 4px;
        }}
        QTreeWidget#hexPreview::item {{
            padding: 0px 4px;
        }}
        QTreeView::item:hover, QTableView::item:hover {{
            background: {t.SURFACE_HOVER};
        }}
        QTreeView::item:selected, QTableView::item:selected {{
            background: {t.SURFACE_SELECTED};
            color: {t.SURFACE_SELECTED_TEXT};
        }}
        QTreeView::item:selected:!active, QTableView::item:selected:!active {{
            background: {t.SURFACE_SELECTED_INACTIVE};
            color: {t.SURFACE_SELECTED_TEXT};
        }}
        QTreeView::branch {{
            background: transparent;
            border-image: none;
            image: none;
        }}
        QTreeView::branch:has-children:!has-siblings:closed,
        QTreeView::branch:closed:has-children:has-siblings {{
            image: url("{_asset_url('branch-closed.svg')}");
        }}
        QTreeView::branch:open:has-children:!has-siblings,
        QTreeView::branch:open:has-children:has-siblings {{
            image: url("{_asset_url('branch-open.svg')}");
        }}
        QTreeView::branch:hover {{
            background: {t.SURFACE_HOVER};
        }}
        QTreeView::branch:selected {{
            background: {t.SURFACE_SELECTED};
        }}
        QTreeView::branch:selected:!active {{
            background: {t.SURFACE_SELECTED_INACTIVE};
        }}
        QTreeView::indicator {{
            width: 15px;
            height: 15px;
            border-radius: 3px;
            border: 1px solid {t.BORDER_STRONG};
            background: {t.SURFACE_BG};
        }}
        QTreeView::indicator:hover {{
            border-color: {t.ACCENT};
        }}
        QTreeView::indicator:checked {{
            background: {t.ACCENT};
            border-color: {t.ACCENT};
            image: url("{_asset_url('check-mark.svg')}");
        }}
        QTreeView::indicator:disabled {{
            background: {t.SURFACE_DISABLED};
            border-color: {t.BORDER_SUBTLE};
        }}
        QHeaderView {{
            background: {t.HEADER_CELL_BG};
            border: none;
        }}
        QHeaderView::section {{
            background: {t.HEADER_CELL_BG};
            color: {t.HEADER_CELL_FG};
            padding: 6px 8px;
            min-height: 20px;
            border: none;
            border-bottom: 1px solid {t.HEADER_CELL_BORDER};
            border-right: 1px solid {t.HEADER_CELL_DIVIDER};
            font-size: 11.5px;
            font-weight: 600;
        }}
        QHeaderView::section:last {{
            border-right: none;
        }}
        QHeaderView::section:hover {{
            background: {t.HEADER_CELL_HOVER_BG};
            color: {t.ACCENT};
        }}
        QHeaderView::up-arrow {{
            image: url("{_asset_url('sort-asc.svg')}");
            width: 10px;
            height: 10px;
            subcontrol-position: right center;
            padding-right: 4px;
        }}
        QHeaderView::down-arrow {{
            image: url("{_asset_url('sort-desc.svg')}");
            width: 10px;
            height: 10px;
            subcontrol-position: right center;
            padding-right: 4px;
        }}
        ''',
        # 10. Splitters, progress bar, scrollbars, tooltips, context menus
        f'''
        QSplitter::handle {{
            background: {t.BORDER_HAIRLINE};
        }}
        QSplitter::handle:hover {{
            background: {t.ACCENT};
        }}
        QProgressBar {{
            border: none;
            border-radius: 2px;
            background: #D5DCE4;
            max-height: 5px;
        }}
        QProgressBar::chunk {{
            background: {t.ACCENT};
            border-radius: 2px;
        }}
        QScrollBar:vertical {{
            background: transparent;
            width: 10px;
            margin: 0;
        }}
        QScrollBar:horizontal {{
            background: transparent;
            height: 10px;
            margin: 0;
        }}
        QScrollBar::handle:vertical {{
            background: #C4CEDB;
            min-height: 28px;
            border: 2px solid transparent;
            border-radius: 5px;
            background-clip: padding;
        }}
        QScrollBar::handle:horizontal {{
            background: #C4CEDB;
            min-width: 28px;
            border: 2px solid transparent;
            border-radius: 5px;
            background-clip: padding;
        }}
        QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
            background: #99A8BA;
        }}
        QScrollBar::handle:vertical:pressed, QScrollBar::handle:horizontal:pressed {{
            background: {t.ACCENT};
        }}
        QScrollBar::add-line, QScrollBar::sub-line {{
            width: 0;
            height: 0;
        }}
        QScrollBar::add-page, QScrollBar::sub-page {{
            background: none;
        }}
        QToolTip {{
            background: {t.HEADER_BG};
            color: {t.HEADER_TEXT};
            border: 1px solid {t.HEADER_BTN_BORDER};
            border-radius: 4px;
            padding: 5px 8px;
            font-size: 12px;
        }}
        QMenu {{
            background: {t.SURFACE_BG};
            color: {t.TEXT_PRIMARY};
            border: 1px solid {t.BORDER_DEFAULT};
            border-radius: 6px;
            padding: 4px;
        }}
        QMenu::item {{
            padding: 6px 24px 6px 12px;
            border-radius: 4px;
        }}
        QMenu::item:selected {{
            background: {t.SURFACE_SELECTED};
            color: {t.SURFACE_SELECTED_TEXT};
        }}
        QMenu::item:disabled {{
            color: {t.TEXT_DISABLED};
        }}
        QMenu::separator {{
            height: 1px;
            background: {t.BORDER_SUBTLE};
            margin: 4px 6px;
        }}
        ''',
    )
    return '\n'.join(sections)


class DesktopAppearance:
    """尺寸使用 Qt 逻辑像素，由 Qt 6 自动适配显示器缩放。"""

    BACKGROUND = theme.CANVAS_BG
    SURFACE = theme.SURFACE_BG
    FOREGROUND = theme.TEXT_PRIMARY
    MUTED = theme.TEXT_MUTED
    BORDER = theme.BORDER_DEFAULT
    ACCENT = theme.ACCENT
    DELETED = theme.DELETED

    def __init__(self, root):
        self.root = root
        self.fonts = {}

    @staticmethod
    def px(value):
        return round(value)

    def configure(self):
        app = QApplication.instance()
        app.setStyle('Fusion')
        font = theme.ui_font(9.5)
        app.setFont(font)
        if self.root is not None:
            self.root.setFont(font)
        fixed = theme.mono_font(10.0, cjk_fallback=True)
        self.fonts = {
            'text': font,
            'fixed': fixed,
            'brand': theme.brand_font(),
            'mono_table': theme.mono_font(9.0, cjk_fallback=True),
        }

        palette = QPalette()
        colors = {
            QPalette.ColorRole.Window: theme.CANVAS_BG,
            QPalette.ColorRole.WindowText: theme.TEXT_PRIMARY,
            QPalette.ColorRole.Base: theme.SURFACE_BG,
            QPalette.ColorRole.AlternateBase: theme.SURFACE_SUBTLE,
            QPalette.ColorRole.Text: theme.TEXT_PRIMARY,
            QPalette.ColorRole.Button: theme.SURFACE_BG,
            QPalette.ColorRole.ButtonText: theme.TEXT_PRIMARY,
            QPalette.ColorRole.Highlight: theme.SURFACE_SELECTED,
            QPalette.ColorRole.HighlightedText: theme.SURFACE_SELECTED_TEXT,
            QPalette.ColorRole.ToolTipBase: theme.HEADER_BG,
            QPalette.ColorRole.ToolTipText: theme.HEADER_TEXT,
            QPalette.ColorRole.Link: theme.ACCENT,
            QPalette.ColorRole.LinkVisited: theme.SYSTEM_FG,
            QPalette.ColorRole.PlaceholderText: theme.TEXT_MUTED,
            QPalette.ColorRole.Light: theme.SURFACE_BG,
            QPalette.ColorRole.Midlight: theme.CHROME_BG,
            QPalette.ColorRole.Mid: theme.BORDER_DEFAULT,
            QPalette.ColorRole.Dark: theme.BORDER_STRONG,
            QPalette.ColorRole.Shadow: theme.TEXT_MUTED,
        }
        for role, color in colors.items():
            palette.setColor(role, QColor(color))
        palette.setColor(QPalette.ColorGroup.Inactive, QPalette.ColorRole.Highlight, QColor(theme.SURFACE_SELECTED_INACTIVE))
        palette.setColor(QPalette.ColorGroup.Inactive, QPalette.ColorRole.HighlightedText, QColor(theme.SURFACE_SELECTED_TEXT))
        for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
            palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(theme.TEXT_DISABLED))
        app.setPalette(palette)
        app.setStyleSheet(build_stylesheet())
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
