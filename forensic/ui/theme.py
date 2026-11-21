"""Archival Slate & Prussian Ink 设计令牌、安全字体构造与 HTML 档案样式。"""
from typing import NamedTuple

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

# ---------------------------------------------------------------------------
# 1. Core Palette Tokens — Command Ribbon (Dark Slate-Navy Top Bar)
# ---------------------------------------------------------------------------
HEADER_BG = '#15202E'
HEADER_BORDER = '#0E1722'
HEADER_DIVIDER = '#2A3B50'
HEADER_TEXT = '#F3F6FA'
HEADER_MUTED = '#91A4B8'
HEADER_BTN_BG = '#1F2F42'
HEADER_BTN_BORDER = '#324761'
HEADER_BTN_HOVER = '#293D55'
HEADER_BTN_PRESSED = '#1A2738'
HEADER_GHOST_HOVER = '#223347'
HEADER_PRIMARY_BG = '#2563A8'
HEADER_PRIMARY_HOVER = '#2E72BE'
HEADER_PRIMARY_PRESSED = '#1D518C'

# ---------------------------------------------------------------------------
# 2. Core Palette Tokens — Daylight Optical Surfaces
# ---------------------------------------------------------------------------
CANVAS_BG = '#E8EDF3'
CHROME_BG = '#F3F5F8'
CHROME_SUBTLE = '#EBEEF3'
SURFACE_BG = '#FFFFFF'
SURFACE_SUBTLE = '#F8FAFC'
SURFACE_TINT = '#FAFBFD'
SURFACE_HOVER = '#EDF3FA'
SURFACE_SELECTED = '#DFECF9'
SURFACE_SELECTED_INACTIVE = '#E6EEF8'
SURFACE_SELECTED_TEXT = '#10345E'
SURFACE_DISABLED = '#F3F5F8'
IMAGE_BACKDROP = '#EEF2F6'

# ---------------------------------------------------------------------------
# 3. Core Palette Tokens — Borders & Structural Hairlines
# ---------------------------------------------------------------------------
BORDER_SUBTLE = '#E3E8EF'
BORDER_HAIRLINE = '#E2E7EE'
BORDER_PANE = '#DCE2EA'
BORDER_DEFAULT = '#CFD7E2'
BORDER_STRONG = '#A7B4C4'
BORDER_FOCUS = '#1B4D89'
BORDER_SOFT_RULE = '#EDF0F5'

# ---------------------------------------------------------------------------
# 4. Core Palette Tokens — Text Hierarchy & Technical Readouts
# ---------------------------------------------------------------------------
TEXT_PRIMARY = '#161E29'
TEXT_SECONDARY = '#3D4C5E'
TEXT_MUTED = '#637385'
TEXT_DISABLED = '#99A5B3'
HEX_OFFSET_FG = '#365578'
HEX_NULL_FG = '#A2AEBC'
HEX_NULL_SELECTED_FG = '#6B87A8'
HEX_CHAR_FG = '#2E3B4A'
HEX_DOT_FG = '#ABB6C4'

# ---------------------------------------------------------------------------
# 5. Core Palette Tokens — Primary Accent (Prussian Ink)
# ---------------------------------------------------------------------------
ACCENT = '#1B4D89'
ACCENT_HOVER = '#153F72'
ACCENT_PRESSED = '#10325B'
ACCENT_SOFT_BG = '#EBF2FA'
ACCENT_SOFT_BORDER = '#C0D6EE'
ACCENT_SOFT_TEXT = '#154175'
ACCENT_FILTER_BG = '#E5EFFA'
HEADER_HOVER_BG = '#E9EFF6'

# Header cell tokens (shared with FilterHeaderView)
HEADER_CELL_BG = CHROME_BG
HEADER_CELL_HOVER_BG = HEADER_HOVER_BG
HEADER_CELL_ACTIVE_BG = ACCENT_FILTER_BG
HEADER_CELL_FG = '#4A596A'
HEADER_CELL_BORDER = BORDER_DEFAULT
HEADER_CELL_DIVIDER = BORDER_HAIRLINE

# ---------------------------------------------------------------------------
# 6. Forensic Semantic Status Tokens
# ---------------------------------------------------------------------------
OK_FG = '#165E37'
OK_BG = '#ECF7F1'
OK_BORDER = '#BCE2CD'

DANGER_FG = '#B42318'
DANGER_BG = '#FDF1F0'
DANGER_BORDER = '#F4C5C1'
DELETED = DANGER_FG

WARN_FG = '#8E4F0A'
WARN_BG = '#FEF6E8'
WARN_BORDER = '#ECD19F'

SYSTEM_FG = '#52369B'
SYSTEM_BG = '#F3EFFB'
SYSTEM_BORDER = '#D6C9EE'

NEUTRAL_FG = '#425263'
NEUTRAL_BG = '#EEF1F5'
NEUTRAL_BORDER = '#D4DCE5'


class PillStyle(NamedTuple):
    fg: str
    bg: str
    border: str


PILL_OK = PillStyle(OK_FG, OK_BG, OK_BORDER)
PILL_DANGER = PillStyle(DANGER_FG, DANGER_BG, DANGER_BORDER)
PILL_WARN = PillStyle(WARN_FG, WARN_BG, WARN_BORDER)
PILL_SYSTEM = PillStyle(SYSTEM_FG, SYSTEM_BG, SYSTEM_BORDER)
PILL_NEUTRAL = PillStyle(NEUTRAL_FG, NEUTRAL_BG, NEUTRAL_BORDER)
PILL_ACCENT = PillStyle(ACCENT_SOFT_TEXT, ACCENT_SOFT_BG, ACCENT_SOFT_BORDER)

SEMANTIC_PILLS: dict[str, PillStyle] = {
    # Verified / Allocated
    '现存': PILL_OK,
    '正常': PILL_OK,
    '人工': PILL_OK,
    '成功': PILL_OK,
    '通过': PILL_OK,
    '一致': PILL_OK,
    '校验通过': PILL_OK,
    '运行中': PILL_OK,
    '只读': PILL_OK,
    '已固定': PILL_OK,
    # Deleted / Critical
    '已删除': PILL_DANGER,
    '缺失': PILL_DANGER,
    '失败': PILL_DANGER,
    '不一致': PILL_DANGER,
    '校验失败': PILL_DANGER,
    '错误': PILL_DANGER,
    # Warning / Reallocated
    '已删除·重分配': PILL_WARN,
    '部分导出': PILL_WARN,
    '已取消': PILL_WARN,
    '待固定': PILL_WARN,
    '未固定': PILL_WARN,
    '受控写入（记入审计链）': PILL_WARN,
    '受控写入': PILL_WARN,
    # System / MCP Provenance
    'MCP': PILL_SYSTEM,
    '系统区域': PILL_SYSTEM,
    '虚拟目录': PILL_SYSTEM,
    # Neutral / Info
    '未启动': PILL_NEUTRAL,
    '已停止': PILL_NEUTRAL,
    '跳过': PILL_NEUTRAL,
    # MACB Timeline Event Tags
    'M': PILL_ACCENT,
    'M 内容修改': PILL_ACCENT,
    'A': PILL_NEUTRAL,
    'A 访问': PILL_NEUTRAL,
    'C': PILL_SYSTEM,
    'C 元数据变更': PILL_SYSTEM,
    'B': PILL_OK,
    'B 创建': PILL_OK,
}


def semantic_pill(text: str | None, default: PillStyle | None = None) -> PillStyle | None:
    """按取证领域语义文本查询胶囊徽章配色；支持前缀回退。"""
    key = (text or '').strip()
    if not key:
        return default
    direct = SEMANTIC_PILLS.get(key)
    if direct is not None:
        return direct
    if key.startswith('已删除·重分配'):
        return PILL_WARN
    if key.startswith(('已删除', '不一致', '失败', '缺失', '校验失败', '错误')):
        return PILL_DANGER
    if key.startswith(('部分导出', '已取消', '待固定', '未固定', '受控写入')):
        return PILL_WARN
    if key.startswith(('校验通过', '成功', '通过', '一致', '运行中', '只读')):
        return PILL_OK
    if key.startswith(('MCP', '系统区域', '虚拟目录')):
        return PILL_SYSTEM
    return default


# ---------------------------------------------------------------------------
# 7. Safe DirectWrite-Verified Font Builders (Zero qt.text.font.db Warnings)
# ---------------------------------------------------------------------------
UI_FONT_CANDIDATES = (
    'Segoe UI Variable Text',
    'Segoe UI',
    'Microsoft YaHei UI',
    'Microsoft YaHei',
    'Noto Sans SC',
    'Noto Sans CJK SC',
)
BRAND_FONT_CANDIDATES = (
    'Segoe UI Variable Display',
    'Segoe UI',
    'Microsoft YaHei UI',
    'Microsoft YaHei',
)
MONO_FONT_CANDIDATES = (
    'Cascadia Mono',
    'Cascadia Code',
    'Consolas',
)
CJK_FALLBACK_CANDIDATES = (
    'Microsoft YaHei UI',
    'Microsoft YaHei',
    'Noto Sans SC',
    'Noto Sans CJK SC',
)


def _installed_families() -> set[str]:
    return set(QFontDatabase.families())


def _normalize_weight(weight) -> QFont.Weight:
    if isinstance(weight, QFont.Weight):
        return weight
    return QFont.Weight(int(weight))


def ui_font(size: float = 9.5, weight: QFont.Weight | int = QFont.Weight.Normal) -> QFont:
    """构造拉丁数字 + 简体中文清晰混排的无衬线界面字体。"""
    available = _installed_families()
    families = [name for name in UI_FONT_CANDIDATES if name in available]
    if families:
        font = QFont()
        font.setFamilies(families)
    else:
        app = QApplication.instance()
        font = QFont(app.font()) if app is not None else QFont()
    font.setPointSizeF(float(size))
    font.setWeight(_normalize_weight(weight))
    return font


def brand_font(size: float = 13.5, weight: QFont.Weight | int = QFont.Weight.Bold) -> QFont:
    """构造顶部命令带品牌标识字标字体。"""
    available = _installed_families()
    families = [name for name in BRAND_FONT_CANDIDATES if name in available]
    if families:
        font = QFont()
        font.setFamilies(families)
    else:
        font = ui_font(size, weight)
    font.setPointSizeF(float(size))
    font.setWeight(_normalize_weight(weight))
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.3)
    return font


def mono_font(
    size: float = 9.5,
    cjk_fallback: bool = True,
    weight: QFont.Weight | int = QFont.Weight.Normal,
) -> QFont:
    """构造等宽技术字体（字节数/inode/偏移/哈希/HEX/JSON/fsstat）。"""
    available = _installed_families()
    system_fixed = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    families = [name for name in MONO_FONT_CANDIDATES if name in available]
    if system_fixed.family() in available and system_fixed.family() not in families:
        families.append(system_fixed.family())
    if cjk_fallback:
        for name in CJK_FALLBACK_CANDIDATES:
            if name in available and name not in families:
                families.append(name)
    if families:
        font = QFont()
        font.setFamilies(families)
    else:
        font = QFont(system_fixed)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSizeF(float(size))
    font.setWeight(_normalize_weight(weight))
    return font


def repolish(widget) -> None:
    """在动态属性（custodyState/bannerState/statusState/role）变更后刷新样式。"""
    if widget is None:
        return
    style = widget.style()
    if style is not None:
        style.unpolish(widget)
        style.polish(widget)
    widget.update()


# ---------------------------------------------------------------------------
# 8. Archival Dossier & Operations Guide HTML Stylesheets
# ---------------------------------------------------------------------------
DOSSIER_CSS = f'''
body {{
    font-family: "Segoe UI Variable Text", "Segoe UI", "Microsoft YaHei UI", sans-serif;
    font-size: 13px;
    color: {TEXT_PRIMARY};
    background-color: {SURFACE_BG};
    margin: 0px;
}}
h2 {{
    font-size: 15px;
    font-weight: 700;
    color: {HEADER_BG};
    margin-top: 0px;
    margin-bottom: 3px;
}}
p {{
    font-size: 12px;
    color: {TEXT_MUTED};
    margin-top: 0px;
    margin-bottom: 10px;
}}
p.subtitle {{
    font-size: 12px;
    color: {TEXT_MUTED};
    margin-top: 0px;
    margin-bottom: 10px;
}}
hr {{
    border: 0px;
    height: 1px;
    color: {BORDER_SUBTLE};
    background-color: {BORDER_SUBTLE};
    margin-top: 4px;
    margin-bottom: 10px;
}}
h3 {{
    font-size: 12px;
    font-weight: 600;
    color: {ACCENT};
    margin-top: 12px;
    margin-bottom: 5px;
}}
table {{
    border-collapse: collapse;
    width: 100%;
    border: 1px solid #DDE3EC;
    margin-top: 0px;
    margin-bottom: 8px;
}}
td {{
    background-color: {SURFACE_BG};
    color: {TEXT_PRIMARY};
    border: 1px solid #E5EAF1;
    padding: 6px 10px;
    vertical-align: top;
}}
td.key {{
    width: 168px;
    background-color: #F4F6F9;
    color: {TEXT_SECONDARY};
    font-weight: 600;
}}
td.val {{
    background-color: {SURFACE_BG};
    color: {TEXT_PRIMARY};
}}
.mono, code {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    color: #1E2E40;
}}
.muted {{
    color: {TEXT_MUTED};
}}
.pill-ok {{
    color: {OK_FG};
    background-color: {OK_BG};
    font-weight: 600;
    padding: 1px 6px;
}}
.pill-danger {{
    color: {DANGER_FG};
    background-color: {DANGER_BG};
    font-weight: 600;
    padding: 1px 6px;
}}
.pill-warn {{
    color: {WARN_FG};
    background-color: {WARN_BG};
    font-weight: 600;
    padding: 1px 6px;
}}
.pill-system {{
    color: {SYSTEM_FG};
    background-color: {SYSTEM_BG};
    font-weight: 600;
    padding: 1px 6px;
}}
'''

GUIDE_CSS = f'''
body {{
    font-family: "Segoe UI Variable Text", "Segoe UI", "Microsoft YaHei UI", sans-serif;
    font-size: 13.5px;
    color: {TEXT_PRIMARY};
    background-color: {SURFACE_BG};
    margin: 0px;
}}
h1, h2 {{
    color: {HEADER_BG};
    font-weight: 700;
    margin-top: 4px;
    margin-bottom: 8px;
}}
h3 {{
    color: {ACCENT};
    font-weight: 600;
    margin-top: 12px;
    margin-bottom: 6px;
}}
p {{
    margin-top: 4px;
    margin-bottom: 9px;
    line-height: 155%;
}}
ol, ul {{
    margin-top: 4px;
    margin-bottom: 10px;
}}
li {{
    margin-top: 4px;
    margin-bottom: 6px;
    line-height: 155%;
}}
strong, b {{
    color: {HEADER_BG};
    font-weight: 600;
}}
code {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    background-color: #F1F4F8;
    color: {ACCENT_SOFT_TEXT};
}}
pre {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    background-color: #F4F6F9;
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_PANE};
    padding: 8px 10px;
    margin-top: 8px;
    margin-bottom: 8px;
}}
'''
