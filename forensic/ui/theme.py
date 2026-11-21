"""明净瓷白与晴空蓝（Daylight Porcelain & Cerulean Sky）浅色设计令牌、安全字体构造与 HTML 档案样式。"""
from typing import NamedTuple

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

# ---------------------------------------------------------------------------
# 1. Core Palette Tokens — Light Command Ribbon (Crisp Porcelain Top Bar)
# ---------------------------------------------------------------------------
HEADER_BG = '#FFFFFF'
HEADER_BORDER = '#DFE7F0'
HEADER_DIVIDER = '#E2EAF2'
HEADER_TEXT = '#1E293B'
HEADER_ICON = '#3B5570'
HEADER_MUTED = '#5E7288'
HEADER_BTN_BG = '#F7FAFD'
HEADER_BTN_BORDER = '#D4DFEB'
HEADER_BTN_HOVER = '#EDF5FD'
HEADER_BTN_HOVER_BORDER = '#AEC8E4'
HEADER_BTN_PRESSED = '#E1EFFC'
HEADER_GHOST_HOVER = '#F1F6FB'
HEADER_GHOST_HOVER_BORDER = '#DDE7F2'
HEADER_PRIMARY_BG = '#2674C4'
HEADER_PRIMARY_BORDER = '#2067B0'
HEADER_PRIMARY_HOVER = '#1F66B0'
HEADER_PRIMARY_PRESSED = '#185494'
HEADER_PRIMARY_DISABLED_BG = '#D6E6F8'
HEADER_PRIMARY_DISABLED_FG = '#7FA5CF'
HEADER_PRIMARY_DISABLED_BORDER = '#C7DCF4'

# ---------------------------------------------------------------------------
# 2. Core Palette Tokens — Daylight Porcelain Surfaces
# ---------------------------------------------------------------------------
CANVAS_BG = '#EFF4F9'
CHROME_BG = '#F7FAFD'
CHROME_SUBTLE = '#F2F6FB'
SURFACE_BG = '#FFFFFF'
SURFACE_SUBTLE = '#FAFCFE'
SURFACE_TINT = '#FCFDFE'
SURFACE_HOVER = '#EEF5FD'
SURFACE_SELECTED = '#E3F0FD'
SURFACE_SELECTED_INACTIVE = '#EBF3FC'
SURFACE_SELECTED_TEXT = '#144880'
SURFACE_DISABLED = '#F4F7FA'
IMAGE_BACKDROP = '#F2F6FA'

# ---------------------------------------------------------------------------
# 3. Core Palette Tokens — Borders & Structural Hairlines
# ---------------------------------------------------------------------------
BORDER_SUBTLE = '#E6ECF3'
BORDER_HAIRLINE = '#E4EBF2'
BORDER_PANE = '#DFE7F0'
BORDER_DEFAULT = '#D3DDE8'
BORDER_STRONG = '#AEBFD2'
BORDER_FOCUS = '#2674C4'
BORDER_SOFT_RULE = '#EFF3F8'

# ---------------------------------------------------------------------------
# 4. Core Palette Tokens — Text Hierarchy & Technical Readouts
# ---------------------------------------------------------------------------
TEXT_PRIMARY = '#1E293B'
TEXT_SECONDARY = '#45586E'
TEXT_MUTED = '#60748A'
TEXT_DISABLED = '#99AABF'
HEX_OFFSET_FG = '#356391'
HEX_NULL_FG = '#A8B5C4'
HEX_NULL_SELECTED_FG = '#6B8FB8'
HEX_CHAR_FG = '#334559'
HEX_DOT_FG = '#B2BECA'

# ---------------------------------------------------------------------------
# 5. Core Palette Tokens — Primary Accent (Cerulean Sky)
# ---------------------------------------------------------------------------
ACCENT = '#2674C4'
ACCENT_HOVER = '#1E63AC'
ACCENT_PRESSED = '#175291'
ACCENT_SOFT_BG = '#ECF5FF'
ACCENT_SOFT_BORDER = '#BDD9F7'
ACCENT_SOFT_TEXT = '#1B5A9D'
ACCENT_FILTER_BG = '#E5F1FE'
HEADER_HOVER_BG = '#EBF3FB'

# Header cell tokens (shared with FilterHeaderView)
HEADER_CELL_BG = CHROME_BG
HEADER_CELL_HOVER_BG = HEADER_HOVER_BG
HEADER_CELL_ACTIVE_BG = ACCENT_FILTER_BG
HEADER_CELL_FG = '#4C6075'
HEADER_CELL_BORDER = BORDER_DEFAULT
HEADER_CELL_DIVIDER = BORDER_HAIRLINE

# ---------------------------------------------------------------------------
# 6. Forensic Semantic Status Tokens
# ---------------------------------------------------------------------------
OK_FG = '#157347'
OK_BG = '#EAF8F0'
OK_BORDER = '#B6E6CB'

DANGER_FG = '#B92D22'
DANGER_BG = '#FEF0EF'
DANGER_BORDER = '#F6C6C2'
DELETED = DANGER_FG

WARN_FG = '#94540A'
WARN_BG = '#FFF7E6'
WARN_BORDER = '#F0D59C'

SYSTEM_FG = '#5B40A8'
SYSTEM_BG = '#F4F0FD'
SYSTEM_BORDER = '#D8CBF5'

NEUTRAL_FG = '#485A6E'
NEUTRAL_BG = '#F1F5F9'
NEUTRAL_BORDER = '#D6E0EB'


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
    color: {TEXT_PRIMARY};
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
    border: 1px solid {BORDER_PANE};
    margin-top: 0px;
    margin-bottom: 8px;
}}
td {{
    background-color: {SURFACE_BG};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_SUBTLE};
    padding: 6px 10px;
    vertical-align: top;
}}
td.key {{
    width: 168px;
    background-color: {CHROME_BG};
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
    color: #243952;
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
    color: {TEXT_PRIMARY};
    font-weight: 700;
    margin-top: 2px;
    margin-bottom: 8px;
}}
h3 {{
    color: {ACCENT};
    font-weight: 600;
    margin-top: 14px;
    margin-bottom: 6px;
}}
p {{
    margin-top: 4px;
    margin-bottom: 9px;
    line-height: 160%;
}}
ol, ul {{
    margin-top: 4px;
    margin-bottom: 10px;
}}
li {{
    margin-top: 5px;
    margin-bottom: 7px;
    line-height: 160%;
}}
strong, b {{
    color: {TEXT_PRIMARY};
    font-weight: 600;
}}
code {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    background-color: {ACCENT_SOFT_BG};
    color: {ACCENT_SOFT_TEXT};
}}
pre {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    font-size: 12px;
    background-color: {CHROME_BG};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_PANE};
    padding: 9px 12px;
    margin-top: 8px;
    margin-bottom: 10px;
}}
.callout {{
    background-color: {ACCENT_SOFT_BG};
    border: 1px solid {ACCENT_SOFT_BORDER};
    color: {TEXT_PRIMARY};
    padding: 8px 12px;
    margin-top: 10px;
    margin-bottom: 10px;
}}
.step-ref {{
    color: #C93D31;
    font-weight: 700;
}}
'''
