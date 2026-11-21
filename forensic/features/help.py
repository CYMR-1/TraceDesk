"""工作台内的图文分步操作说明与大图放大预览。"""
from html import escape
from pathlib import Path
import re
from typing import NamedTuple

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication, QDialog, QFrame, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QPushButton, QScrollArea, QSizePolicy, QTextBrowser, QVBoxLayout, QWidget,
)

from ..paths import ASSET_DIR
from ..ui import theme
from ..ui.delegates import ForensicItemDelegate
from ..ui.icons import ui_icon
from ..ui.metrics import CONTROL_GAP, ROW_HEIGHT_TABLE
from .api import Action, Feature

GUIDE_IMAGE_DIR = ASSET_DIR / 'guide'


class GuidePage(NamedTuple):
    title: str
    nav_label: str
    summary: str
    image: str
    caption: str
    content: str


GUIDE_PAGES: tuple[GuidePage, ...] = (
    GuidePage(
        title='用演示镜像走一遍流程',
        nav_label='快速上手：演示镜像',
        summary='用项目内置的 FAT16 演示镜像，5 步走通建案、浏览、预览、导出校验与报告生成闭环。',
        image='01_quickstart.png',
        caption='图 1 · 工作台分区布局与演示流程五大核心入口（点击查看大图）',
        content=r'''1. 点击顶部 ① **新建案件**。编号可填 `DEMO-01`，取证人员填自己的姓名，对象填“FAT16 演示镜像”。点击 **选择案件目录**，确认地址后点击 **创建案件**。
2. 点击右侧 ② **加载镜像**，选择项目里的 `evidence/demo.dd`。等待文件树自动建立后，在左侧 ③ 展开偏移 **2048 扇区** 的分区，进入 **DOCS**，选中 **CASE.TXT**。
3. 在下方 ④ **文本** 页应看到 `Case note inside a nested directory.`。切到 **十六进制**，首行偏移为 `00000000`，开头四个字节为 `43 61 73 65`（对应 “Case”）。
4. 点击预览区右上方的 **导出所选文件**，在结果窗口点 **打开文件所在文件夹**。回到工作台，右键同一个 `CASE.TXT`，选择 **校验一致性…**，选中刚导出的副本，结果应显示 **一致**。
5. 点击顶部 ⑤ **生成 Markdown 报告**，打开生成的文件，在“导出副本”和“文件取证发现”两节核对文件路径与 SHA-256 摘要。

> 提示：想快速体验完整演示案件，也可在项目目录运行 `.\.venv\Scripts\python.exe scripts/run_demo.py --gui`。''',
    ),
    GuidePage(
        title='创建案件、加载镜像与登记来源',
        nav_label='建案、加载与来源',
        summary='确保源镜像与案件库分离存放，在“镜像与文件系统”页核对固定摘要、卷声明范围与交付方摘要比对结果。',
        image='02_case_and_source.png',
        caption='图 2 · 镜像与文件系统页：固定摘要、覆盖范围评估与来源登记（点击查看大图）',
        content='''1. 双击项目中的 **启动取证工作台.bat**。点击 ① **新建案件**，填写案件编号、取证人员和取证对象；目录树选择上级目录，下方“案件目录地址”可直接修改完整路径与文件夹名。
2. 每个案件固定分析一份镜像，源镜像必须放在案件库目录之外（例如案件放在 `cases`，镜像放在同级 `evidence`）。点击 ② **加载镜像**，选择 RAW 镜像或分段 EWF 的 **.E01 首段**（所有续段需位于同一目录）。
3. 切换到 **镜像与文件系统**，点击右上角 ③ **登记证据来源**，填写证据编号、来源、采集时间与时区、采集工具；如交付方提供了 SHA-256，填入其 64 位十六进制摘要。
4. 在 ④ **证据固定 / 覆盖范围与证据来源** 区域核对路径、逻辑字节数、SHA-256、卷声明范围及交付方摘要比对结论；在 ⑤ 查看底层原始分区表（`mmls`）与文件系统信息（`fsstat`）。

> 继续已有案件：点击顶部 ① **打开案件**，选择案件目录中的 `case.json`。备份或移交案件时请复制整个案件文件夹（含压缩清单、审计链与导出材料）。''',
    ),
    GuidePage(
        title='大镜像、完整索引与 SHA-256',
        nav_label='大镜像与 SHA-256',
        summary='逻辑容量达到 1 GiB 时自动切换为按需目录浏览，可边浏览边在后台校验基线，按需建立完整索引。',
        image='03_large_image.png',
        caption='图 3 · 大容量镜像按需目录浏览、完整索引与后台校验入口（点击查看大图）',
        content='''- **先浏览，不阻塞**　小于 1 GiB 的镜像会自动固定摘要并扫描全部分区；达到 1 GiB 时先打开首个可读根目录，并在 ① 保管状态条标明“整镜像 SHA-256 待固定”。双击目录深入浏览，点击左侧 ② **返回上级目录** 回退。
- **按需建立完整索引**　需要全案内容搜索或 MACB 时间线时，点击左侧 ③ **建立完整文件索引**。写入完成前可随时点 **取消建立索引**，已有目录结果会保留；完成后清单压缩保存至 `inventory-*.jsonl.gz`，重开案件直接复用。
- **后台校验与固定基线**　点击右上角 ④ **校验完整性**。大镜像首次完整读取会建立 SHA-256 基线，后续校验与基线比对；读取期间可继续浏览目录，也可点击 **取消校验** 中止本次读取。EWF 首次解码逻辑介质并固定全部分段，后续逐段复算封装摘要。
- **正式报告前置条件**　大镜像在固定前导出的副本会标明“初步分析”；重新打开已固定大镜像案件后，需先完成本次会话的完整性校验，再导出副本或生成正式报告。

> 说明：Windows 在大镜像会话期间对 RAW 或全部 EWF 分段持有拒写/拒删除共享句柄。卷声明范围已覆盖仅说明声明结束位置落在镜像内，是否完整采集仍需结合采集记录核验。''',
    ),
    GuidePage(
        title='定位目录、筛选文件与多格式预览',
        nav_label='浏览、筛选与预览',
        summary='左侧保留完整目录树，筛选仅过滤当前范围列表；下方支持文本（9 编码）、图片与十六进制分页预览。',
        image='04_browse_preview.png',
        caption='图 4 · 文件树、条件筛选栏与十六进制/多编码分页预览（点击查看大图）',
        content='''1. 在左侧树选择镜像、分区或目录，可用 ① **全部展开 / 全部折叠** 控制层级。遇到跨分区同名文件，结合 **分区偏移、路径、inode** 精准区分。
2. 在 ② 筛选栏输入后缀（如 `.txt`）或路径关键词，或在状态下拉框选择 **现存文件 / 已删除**，按回车或点击 **筛选**；点击 **重置** 恢复当前范围。筛选不裁剪左侧完整树。
3. 在 ③ 文件列表核对状态胶囊、字节数、inode 与 MACB 四时间（UTC+8）。单击文件即可在下方预览；超过 1,000 项时列表自动按每页 100 项分页。
4. 在 ④ 切换 **文本 / 十六进制**，中文乱码时按来源在 **编码** 下拉框选择 UTF-8、UTF-16LE/BE、GBK、GB18030、Big5 等 9 种编码。可识别的图片自动显示 **图片** 页（上限 32 MiB、4000 万像素），并可随时切回 **十六进制** 核对原始字节。
5. 使用下方 **上一页 / 下一页** 翻页，或双击 ⑤ 页码徽标直接输入目标页号跳转（大普通文件可直接跳到末页）。''',
    ),
    GuidePage(
        title='搜索文件内容并实时复核命中',
        nav_label='内容搜索与复核',
        summary='支持 UTF-8、UTF-16LE、GBK 与 HEX 精确字节检索，结果实时流式展示，搜索期间即可筛选、排除并保存为取证发现。',
        image='05_content_search.png',
        caption='图 5 · 内容搜索与复核页：实时流式命中、三态全选与批量保存（点击查看大图）',
        content='''1. 切换到 **内容搜索与复核**。在 ① 输入搜索文字或十六进制字节，选择编码与范围（**全部文件** 或 **文件浏览中选中的文件**；大镜像全案搜索需先建立完整索引），点击 **搜索**。运行中按钮自动切换为 **取消搜索**。
2. 用演示镜像验证：选择编码 **HEX**，输入 `6E 6F 74 65`，点击 **搜索**，即可在 ④ 命中 `DOCS/CASE.TXT`，**文件内字节偏移为 5**（从文件开头的 0 起算）。
3. 搜索不设命中上限，结果一边扫描一边实时展示。搜索期间即可通过 ③ 表头 **全选** 三态复选框勾选命中，或点击 **分区偏移** 表头下拉筛选。
4. 双击 ④ 中任意命中行，直接弹出对应偏移的十六进制预览；勾选一条或多条命中后，点击 ② **排除所选项** 剔除误报，或点击 **保存为取证发现** 批量写入审计链。
5. 每次搜索的完整命中、范围、校验方式与失败明细均自动保存至案件 `reports/search_*.json`。

> 说明：内容搜索覆盖清单中可读取的文件及已删除记录，不解压归档文档、不扫描未分配空间。''',
    ),
    GuidePage(
        title='导出副本、恢复删除文件与取证发现',
        nav_label='导出与取证发现',
        summary='导出前后自动复核原镜像，支持已删除文件可读字节恢复；右键文件工具与“取证发现”页形成结构化证据归档。',
        image='06_export_findings.png',
        caption='图 6 · 取证发现页：表头筛选排序、一键批量导出与分栏取证详情（点击查看大图）',
        content='''1. **导出文件副本**：在 **文件浏览** 选中现存或已删除文件，点击 **导出所选文件**。副本保存至案件 `exports` 目录（重名时放入 `同名副本-*` 子目录保留原名），并记录副本 SHA-256。
2. **恢复已删除文件**：将状态切为 **已删除**，选中记录核对能否预览、目录记录大小及恢复提示后再导出。若提示“部分导出”、inode 已重分配或 FAT 起始簇已被占用，应如实记录实际字节数并结合内容研判。
3. **右键文件取证工具**：在文件树或列表右键普通文件，可使用 **记录取证发现**、**计算哈希值（SHA-256）** 或 **校验一致性…**（与本地副本逐字节比对），所有结果自动绑定镜像摘要、分区偏移与 inode 写入审计链。
4. **集中复核与一键导出**：打开 **取证发现**，通过 ② **状态 / 分区偏移** 表头下拉筛选或点击 **序号 / 最近记录** 切换正倒序；在 ③ 双击文件于下方 ④ 展开笔记、摘要与比对明细，点击右上角 ① **一键导出** 即可批量导出对应副本并生成汇总 Markdown。''',
    ),
    GuidePage(
        title='MACB 时间线与审计日志核验',
        nav_label='时间线与审计日志',
        summary='通过 MACB 时间线还原文件活动脉络，在审计日志中追踪人工与 MCP 全部操作并核验 SHA-256 哈希链。',
        image='07_timeline_audit.png',
        caption='图 7 · 审计日志页：人工/MCP 来源筛选、正倒序切换与哈希链详情（点击查看大图）',
        content='''1. 在 ① 模块标签栏切换 **MACB 时间线** 与 **审计日志**。大案件首次进入时间线时点击 **生成时间线** 在后台整理事件，序号在翻页与筛选后保持不变。
2. **理解 MACB 四时间**：**M** 为内容修改，**A** 为访问，**C** 为元数据变更，**B** 为创建。FAT 不保存 C 时间，查看创建时间请看 B 列；界面统一显示 UTC+8，解释 FAT 等无时区时间时请核对源设备时区。
3. **排序与表头下拉筛选**：在时间线与审计日志中，单击 ② **序号** 或 **时间（UTC+8）** 表头可切换正序/倒序；单击 ③ 表头可下拉筛选（时间线支持事件/状态/分区偏移；审计日志支持 **来源（人工/MCP）**、操作人员、操作、结果）。
4. **查看详情与防篡改校验**：双击任意记录在下方 ④ 展开完整详情（审计详情含操作来源、参数、结果及前序/当前 SHA-256 哈希值）。审计链与 `audit.head` 尾部锚点用于检出单方面修改或截断。

> 边界提示：本工具实施应用层只读约束与日志链校验；需要硬件级写保护的采集场景，须另行配合硬件写保护器。''',
    ),
    GuidePage(
        title='生成报告与交付可核验复核包',
        nav_label='报告与复核包',
        summary='生成结构化 Markdown 取证报告，并通过材料选择窗口按需构建可独立离线核验的复核包 ZIP。',
        image='08_report_bundle.png',
        caption='图 8 · 复核包材料选择弹窗：缺失中文清单提示、双标签勾选与导出（点击查看大图）',
        content=r'''1. **生成 Markdown 报告**：先在 **取证发现** 和 **镜像与文件系统** 核对内容，再点击顶部 **生成 Markdown 报告**。程序会执行完整性校验并将分节报告写入案件 `reports` 目录。
2. **按需选择复核包材料**：点击顶部 **导出复核包**。若案件存在历史导出副本或搜索记录，会弹出材料选择窗口：当部分本地文件已被清理或隔离时，顶部 ① 会给出清晰中文缺失清单，并支持下方 ④ **复制缺失清单**。
3. 在 ② 切换 **导出副本** 与 **内容搜索记录** 标签页，利用 ③ **全选可用项 / 全不选 / 仅看缺失项** 自由勾选要打入复核包的现存材料，点击 ④ **生成复核包**。未勾选或缺失的历史条目会如实记入 `manifest.json` 的 `omitted_exports` / `omitted_searches`。
4. **独立离线核验**：复核包与 `.zip.sha256` 保存于 `reports` 目录（不含原始镜像）。通过独立渠道交付 ZIP 摘要后，复核人在项目目录运行下方命令即可校验全部成员与审计链：

```powershell
.\.venv\Scripts\python.exe scripts/verify_bundle.py "复核包路径.zip" --sha256 交付方提供的64位摘要
```''',
    ),
    GuidePage(
        title='MCP 服务端接入与 AI 协同',
        nav_label='MCP 服务端接入',
        summary='内置标准 MCP 服务端 tracedesk_mcp（19 工具 + 2 资源），支持在桌面端一键复制配置、启停本地 HTTP 服务与释放案件锁。',
        image='09_mcp_dialog.png',
        caption='图 9 · MCP 服务配置弹窗：案件锁释放、本地 HTTP 启停与客户端配置（点击查看大图）',
        content=r'''1. 点击工作台顶部 **MCP 服务** 按钮打开配置窗口。所有 MCP 工具均遵守源镜像只读保护，受控写操作会以 **MCP** 来源（`origin="mcp"`）写入案件 SHA-256 审计链，可在 **审计日志** 中按人工/MCP 筛选核查。
2. **释放桌面端案件锁**：当桌面端已打开某案件并持有 `case.lock` 时，顶部 ① 会出现提示条。点击 **释放当前案件锁** 即可关闭当前案件，供外部 AI 客户端安全接入同一案件。
3. **选择传输方式**：本地桌面客户端（Claude Desktop、Cursor、Antigravity 等）推荐在 ③ 切换到 **stdio 接入配置**，由客户端按需拉起子进程；若客户端使用 HTTP 接入，可在 ② 设置端口并点击 **启动本地 HTTP 服务**（仅监听 `127.0.0.1` 回环并启用 DNS 重绑定防护，关闭主窗口时自动停止）。
4. 点击 ④ **复制配置 JSON** 或 **复制启动命令** 即可快速填入客户端配置；在 ③ **可用工具清单（19）** 可查阅全部工具及只读/受控写入标识。

> 命令行独立启动：`.\.venv\Scripts\python.exe mcp_server.py`（默认 stdio），或加 `--transport streamable-http --host 127.0.0.1 --port 8765`。''',
    ),
)


_INLINE_TOKEN = re.compile(r'`([^`]+)`|\*\*([^*]+)\*\*|([①②③④⑤])')


def _format_inline(text: str) -> str:
    parts = []
    cursor = 0
    for match in _INLINE_TOKEN.finditer(text):
        if match.start() > cursor:
            parts.append(escape(text[cursor:match.start()]))
        code_text, bold_text, ref_mark = match.groups()
        if code_text is not None:
            parts.append(f'<code>&nbsp;{escape(code_text)}&nbsp;</code>')
        elif bold_text is not None:
            parts.append(f'<strong>{escape(bold_text)}</strong>')
        else:
            parts.append(f'<span class="step-ref">{escape(ref_mark)}</span>')
        cursor = match.end()
    if cursor < len(text):
        parts.append(escape(text[cursor:]))
    return ''.join(parts)


def _guide_html(markdown_text: str) -> str:
    """将分步操作正文转换为语义 HTML，使 theme.GUIDE_CSS 完整生效。"""
    blocks = []
    list_tag = None
    in_code = False
    code_lines = []

    def close_list():
        nonlocal list_tag
        if list_tag is not None:
            blocks.append(f'</{list_tag}>')
            list_tag = None

    for raw_line in markdown_text.splitlines():
        line = raw_line.rstrip()
        if line.startswith('```'):
            if in_code:
                blocks.append(f'<pre>{escape(chr(10).join(code_lines))}</pre>')
                code_lines = []
                in_code = False
            else:
                close_list()
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        stripped = line.strip()
        if not stripped:
            close_list()
            continue
        if stripped.startswith('> '):
            close_list()
            blocks.append(f'<div class="callout">{_format_inline(stripped[2:])}</div>')
            continue
        ordered = re.match(r'^(\d+)\.\s+(.*)$', stripped)
        if ordered:
            if list_tag != 'ol':
                close_list()
                blocks.append('<ol>')
                list_tag = 'ol'
            blocks.append(f'<li>{_format_inline(ordered.group(2))}</li>')
            continue
        if stripped.startswith('- '):
            if list_tag != 'ul':
                close_list()
                blocks.append('<ul>')
                list_tag = 'ul'
            blocks.append(f'<li>{_format_inline(stripped[2:])}</li>')
            continue
        close_list()
        blocks.append(f'<p>{_format_inline(stripped)}</p>')

    if in_code and code_lines:
        blocks.append(f'<pre>{escape(chr(10).join(code_lines))}</pre>')
    close_list()
    return '\n'.join(blocks)


class GuideLightboxDialog(QDialog):
    """引导图高清大图查看器，支持适应窗口与 100% 原始像素切换。"""

    def __init__(self, parent, title: str, caption: str, pixmap: QPixmap):
        super().__init__(parent)
        self._pixmap = pixmap
        self._fit_mode = True
        self.setWindowTitle(f'引导图预览 · {title}')

        screen = (parent.screen() if parent is not None else None) or QApplication.primaryScreen()
        if screen is not None:
            area = screen.availableGeometry()
            target_w = min(pixmap.width() + 48, max(760, int(area.width() * 0.88)))
            target_h = min(pixmap.height() + 116, max(520, int(area.height() * 0.88)))
            self.resize(target_w, target_h)
        else:
            self.resize(1120, 760)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QFrame(self)
        header.setObjectName('dialogHeaderBar')
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(16, 10, 16, 10)
        h_layout.setSpacing(10)
        clean_caption = (caption or title).replace('（点击查看大图）', '').strip()
        title_lbl = QLabel(clean_caption, header)
        title_lbl.setProperty('role', 'section')
        title_lbl.setWordWrap(True)
        h_layout.addWidget(title_lbl, 1)
        self.zoom_button = QPushButton('原始尺寸 (100%)', header)
        self.zoom_button.setProperty('role', 'soft')
        self.zoom_button.setAutoDefault(False)
        self.zoom_button.clicked.connect(self._toggle_zoom)
        h_layout.addWidget(self.zoom_button)
        outer.addWidget(header)

        self.scroll = QScrollArea(self)
        self.scroll.setObjectName('guideScrollArea')
        self.scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll.setWidgetResizable(False)
        self.canvas = QLabel(self.scroll)
        self.canvas.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.canvas.setContentsMargins(12, 12, 12, 12)
        self.scroll.setWidget(self.canvas)
        outer.addWidget(self.scroll, 1)

        footer = QFrame(self)
        footer.setObjectName('dialogFooterBar')
        f_layout = QHBoxLayout(footer)
        f_layout.setContentsMargins(16, 10, 16, 10)
        f_layout.setSpacing(CONTROL_GAP)
        size_hint = QLabel(f'原始分辨率：{pixmap.width()} × {pixmap.height()} px', footer)
        size_hint.setProperty('role', 'muted')
        f_layout.addWidget(size_hint)
        f_layout.addStretch(1)
        close_btn = QPushButton('关闭', footer)
        close_btn.setProperty('role', 'accent')
        close_btn.clicked.connect(self.accept)
        f_layout.addWidget(close_btn)
        outer.addWidget(footer)

        self._render()

    def _toggle_zoom(self):
        self._fit_mode = not self._fit_mode
        self.zoom_button.setText('原始尺寸 (100%)' if self._fit_mode else '适应窗口')
        self._render()

    def _render(self):
        if self._pixmap.isNull():
            return
        if self._fit_mode:
            vp = self.scroll.viewport().size()
            base_w = vp.width() if vp.width() > 200 else max(600, self.width() - 24)
            base_h = vp.height() if vp.height() > 200 else max(400, self.height() - 104)
            avail_w = max(320, base_w - 28)
            avail_h = max(240, base_h - 28)
            dpr = max(1.0, float(self.devicePixelRatioF() or 1.0))
            scaled = self._pixmap.scaled(
                QSize(round(avail_w * dpr), round(avail_h * dpr)),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            scaled.setDevicePixelRatio(dpr)
            self.canvas.setPixmap(scaled)
            self.canvas.resize(
                round(scaled.width() / dpr) + 24,
                round(scaled.height() / dpr) + 24,
            )
        else:
            self.canvas.setPixmap(self._pixmap)
            self.canvas.resize(self._pixmap.width() + 24, self._pixmap.height() + 24)

    def showEvent(self, event):
        super().showEvent(event)
        if self._fit_mode:
            self._render()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._fit_mode:
            self._render()


class _ClickableImageLabel(QLabel):
    clicked = Signal()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class GuideFigureCard(QFrame):
    """自适应宽度的引导图卡片，支持点击图片或按钮打开高清大图。"""

    zoom_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName('guideFigureCard')
        self._source = QPixmap()
        self._available_width = 720

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.canvas = _ClickableImageLabel(self)
        self.canvas.setObjectName('guideImageCanvas')
        self.canvas.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.canvas.setCursor(Qt.CursorShape.PointingHandCursor)
        self.canvas.setToolTip('点击放大查看高清引导图')
        self.canvas.setContentsMargins(8, 8, 8, 8)
        self.canvas.clicked.connect(self.zoom_requested)
        layout.addWidget(self.canvas)

        footer = QFrame(self)
        footer.setObjectName('guideFigureFooter')
        f_layout = QHBoxLayout(footer)
        f_layout.setContentsMargins(12, 7, 12, 7)
        f_layout.setSpacing(CONTROL_GAP)
        self.caption_label = QLabel(footer)
        self.caption_label.setProperty('role', 'muted')
        self.caption_label.setWordWrap(True)
        f_layout.addWidget(self.caption_label, 1)
        self.zoom_button = QPushButton('查看大图', footer)
        self.zoom_button.setProperty('role', 'compact')
        self.zoom_button.setIcon(ui_icon('search', theme.TEXT_SECONDARY, 12))
        self.zoom_button.setIconSize(QSize(12, 12))
        self.zoom_button.setAutoDefault(False)
        self.zoom_button.clicked.connect(self.zoom_requested)
        f_layout.addWidget(self.zoom_button)
        layout.addWidget(footer)

    @property
    def source_pixmap(self) -> QPixmap:
        return self._source

    def set_figure(self, path: Path | None, caption: str) -> bool:
        pixmap = QPixmap(str(path)) if (path is not None and path.is_file()) else QPixmap()
        self._source = pixmap
        self.caption_label.setText(caption)
        if pixmap.isNull():
            self.canvas.clear()
            self.hide()
            return False
        self.show()
        self._rescale()
        return True

    def set_available_width(self, width: int) -> None:
        clamped = max(320, int(width))
        if clamped != self._available_width:
            self._available_width = clamped
            self._rescale()

    MAX_FIGURE_HEIGHT = 400

    def _rescale(self) -> None:
        if self._source.isNull():
            return
        max_w = max(280, min(self._available_width - 18, self._source.width()))
        max_h = min(self.MAX_FIGURE_HEIGHT, self._source.height())
        dpr = max(1.0, float(self.devicePixelRatioF() or 1.0))
        scaled = self._source.scaled(
            QSize(round(max_w * dpr), round(max_h * dpr)),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        scaled.setDevicePixelRatio(dpr)
        self.canvas.setPixmap(scaled)
        logical_h = round(scaled.height() / dpr) + 16
        self.canvas.setFixedHeight(logical_h)


class GuideDialog(QDialog):
    def __init__(self, parent, *, image_dir: Path | None = None):
        super().__init__(parent)
        self._image_dir = Path(image_dir) if image_dir is not None else GUIDE_IMAGE_DIR
        self._current_index = 0
        self.setWindowTitle('操作说明 · TraceDesk')
        self.setMinimumSize(780, 520)

        screen = (parent.screen() if parent is not None else None) or QApplication.primaryScreen()
        if screen is not None:
            area = screen.availableGeometry()
            self.resize(min(1040, max(820, area.width() - 80)), min(720, max(560, area.height() - 90)))
        else:
            self.resize(1040, 720)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # 顶部说明栏
        header_bar = QFrame(self)
        header_bar.setObjectName('dialogHeaderBar')
        header = QHBoxLayout(header_bar)
        header.setContentsMargins(18, 10, 18, 10)
        header.setSpacing(10)
        title_lbl = QLabel('TraceDesk 分步操作引导', header_bar)
        title_lbl.setProperty('role', 'section')
        header.addWidget(title_lbl)
        subtitle = QLabel('对照真实界面编号标注（①–⑤）快速定位控件 · 点击引导图可放大查看', header_bar)
        subtitle.setProperty('role', 'muted')
        header.addWidget(subtitle, 1)
        outer.addWidget(header_bar)

        # 中央分栏：左侧目录 + 右侧图文滚动区
        content_row = QHBoxLayout()
        content_row.setContentsMargins(0, 0, 0, 0)
        content_row.setSpacing(0)

        nav_panel = QFrame(self)
        nav_panel.setObjectName('guideNavPanel')
        nav_panel.setFixedWidth(226)
        nav_layout = QVBoxLayout(nav_panel)
        nav_layout.setContentsMargins(0, 10, 0, 0)
        nav_layout.setSpacing(4)
        nav_heading = QLabel(f'操作主题（{len(GUIDE_PAGES)}）', nav_panel)
        nav_heading.setProperty('role', 'muted')
        nav_heading.setContentsMargins(14, 0, 14, 4)
        nav_layout.addWidget(nav_heading)

        self.topics = QListWidget(nav_panel)
        self.topics.setObjectName('guideTopicList')
        self.topics.setItemDelegate(ForensicItemDelegate(self.topics, accent_column=0, row_height=ROW_HEIGHT_TABLE + 4))
        for idx, page in enumerate(GUIDE_PAGES, 1):
            item = QListWidgetItem(f'{idx:02d}  {page.nav_label}')
            item.setToolTip(page.title)
            self.topics.addItem(item)
        nav_layout.addWidget(self.topics, 1)
        content_row.addWidget(nav_panel)

        self.scroll = QScrollArea(self)
        self.scroll.setObjectName('guideScrollArea')
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._article = QWidget(self.scroll)
        self._article.setObjectName('guideArticle')
        article_layout = QVBoxLayout(self._article)
        article_layout.setContentsMargins(24, 18, 24, 20)
        article_layout.setSpacing(12)

        self.page_title = QLabel(self._article)
        self.page_title.setObjectName('guidePageTitle')
        self.page_title.setWordWrap(True)
        article_layout.addWidget(self.page_title)

        self.page_summary = QLabel(self._article)
        self.page_summary.setObjectName('guidePageSummary')
        self.page_summary.setWordWrap(True)
        article_layout.addWidget(self.page_summary)

        self.figure = GuideFigureCard(self._article)
        self.figure.zoom_requested.connect(self.open_lightbox)
        article_layout.addWidget(self.figure)

        self.body = QTextBrowser(self._article)
        self.body.setProperty('flush', True)
        self.body.setOpenExternalLinks(False)
        self.body.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.body.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.body.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.body.document().setDocumentMargin(2)
        self.body.document().setDefaultStyleSheet(theme.GUIDE_CSS)
        article_layout.addWidget(self.body)
        article_layout.addStretch(1)

        self.scroll.setWidget(self._article)
        content_row.addWidget(self.scroll, 1)
        outer.addLayout(content_row, 1)

        # 底部导航栏
        footer_bar = QFrame(self)
        footer_bar.setObjectName('dialogFooterBar')
        controls = QHBoxLayout(footer_bar)
        controls.setContentsMargins(16, 10, 16, 10)
        controls.setSpacing(CONTROL_GAP)
        self.position_label = QLabel(footer_bar)
        self.position_label.setProperty('role', 'muted')
        controls.addWidget(self.position_label)
        controls.addStretch(1)
        self.back_button = QPushButton('上一步', footer_bar)
        self.forward_button = QPushButton('下一步', footer_bar)
        self.forward_button.setProperty('role', 'soft')
        self.close_button = QPushButton('关闭', footer_bar)
        for button in (self.back_button, self.forward_button, self.close_button):
            button.setAutoDefault(False)
            controls.addWidget(button)
        outer.addWidget(footer_bar)

        self.topics.currentRowChanged.connect(self._on_topic_changed)
        self.back_button.clicked.connect(lambda: self.show_step(self._current_index - 1))
        self.forward_button.clicked.connect(lambda: self.show_step(self._current_index + 1))
        self.close_button.clicked.connect(self.accept)
        self.show_step(0)

    def _content_width(self) -> int:
        vp_w = self.scroll.viewport().width()
        fallback = max(480, self.width() - 226 - 24)
        base = vp_w if vp_w > 100 else fallback
        return max(360, base - 48)

    def _sync_article_layout(self) -> None:
        width = self._content_width()
        self.figure.set_available_width(width)
        self.body.document().setTextWidth(float(width))
        doc_h = int(self.body.document().size().height()) + 14
        self.body.setFixedHeight(max(120, doc_h))

    def _on_topic_changed(self, row: int) -> None:
        if 0 <= row < len(GUIDE_PAGES) and row != self._current_index:
            self.show_step(row)

    def show_step(self, index: int) -> None:
        if not (0 <= index < len(GUIDE_PAGES)):
            return
        self._current_index = index
        if self.topics.currentRow() != index:
            self.topics.blockSignals(True)
            self.topics.setCurrentRow(index)
            self.topics.blockSignals(False)

        page = GUIDE_PAGES[index]
        self.page_title.setText(f'{index + 1}. {page.title}')
        self.page_summary.setText(page.summary)
        image_path = self._image_dir / page.image if page.image else None
        self.figure.set_figure(image_path, page.caption)
        self.body.setHtml(_guide_html(page.content))
        self._sync_article_layout()
        self.scroll.verticalScrollBar().setValue(0)
        self.position_label.setText(f'第 {index + 1} / {len(GUIDE_PAGES)} 页')
        self.back_button.setEnabled(index > 0)
        self.forward_button.setEnabled(index + 1 < len(GUIDE_PAGES))

    def open_lightbox(self) -> None:
        pixmap = self.figure.source_pixmap
        if pixmap.isNull():
            return
        page = GUIDE_PAGES[self._current_index]
        dialog = GuideLightboxDialog(self, page.title, page.caption, pixmap)
        try:
            dialog.exec()
        finally:
            dialog.deleteLater()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._sync_article_layout()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._sync_article_layout()


def show_guide(context):
    dialog = GuideDialog(context.root)
    try:
        dialog.exec()
    finally:
        dialog.deleteLater()


FEATURE = Feature('help', actions=(Action('help', show_guide, '操作说明', 'brand', 'pager'),))
