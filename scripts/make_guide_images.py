"""生成操作说明内置的真实界面标注引导图（输出至 forensic/assets/guide/）。"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
if sys.platform == 'win32' and Path(r'C:\Windows\Fonts').is_dir():
    os.environ.setdefault('QT_QPA_FONTDIR', r'C:\Windows\Fonts')

from PySide6.QtCore import QPoint, QRect, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QImage, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication, QLabel, QMainWindow, QPlainTextEdit, QTextBrowser, QTreeWidget, QWidget,
)

from forensic.core.case import Case, sha256
from forensic.core.content_search import SearchControl, search as run_content_search
from forensic.core.file_tools import examine, record_note
from forensic.core.review import inspect_bundle_exports, inspect_bundle_searches
from forensic.features.mcp import LocalHttpMcpManager, McpDialog
from forensic.features.review import BundleExportDialog
from forensic.paths import ASSET_DIR, EVIDENCE_DIR, TEST_WORK_DIR
from forensic.ui import theme
from forensic.ui.controller import App

GUIDE_ASSET_DIR = ASSET_DIR / 'guide'

CALLOUT_STROKE = QColor('#D9483B')
CALLOUT_FILL = QColor(217, 72, 59, 18)
BADGE_BG = QColor('#D9483B')
BADGE_RING = QColor('#FFFFFF')
BADGE_FG = QColor('#FFFFFF')
LEGEND_BG = QColor('#F7FAFD')
LEGEND_BORDER = QColor('#DCE5F0')
LEGEND_TEXT = QColor('#1E293B')


def _widget_rect(root: QWidget, widget: QWidget, pad: int = 3) -> QRect:
    top_left = widget.mapTo(root, QPoint(0, 0))
    rect = QRect(top_left, widget.rect().size()).adjusted(-pad, -pad, pad, pad)
    return rect.intersected(QRect(2, 2, root.width() - 4, root.height() - 4))


def _union_rect(root: QWidget, widgets: list[QWidget], pad: int = 4) -> QRect:
    rect = QRect()
    for widget in widgets:
        r = _widget_rect(root, widget, pad=0)
        rect = r if rect.isNull() else rect.united(r)
    return rect.adjusted(-pad, -pad, pad, pad).intersected(QRect(2, 2, root.width() - 4, root.height() - 4))


def _header_section_rect(root: QWidget, tree: QTreeWidget, first_col: int, last_col: int | None = None) -> QRect:
    header = tree.header()
    end_col = first_col if last_col is None else last_col
    x1 = header.sectionViewportPosition(first_col)
    x2 = header.sectionViewportPosition(end_col) + header.sectionSize(end_col)
    tl = header.mapTo(root, QPoint(x1, 0))
    return QRect(tl.x(), tl.y(), max(24, x2 - x1), header.height()).adjusted(-2, -2, 2, 2)


def _tab_bar_rect(root: QWidget, tab_bar, first_idx: int, last_idx: int | None = None) -> QRect:
    end_idx = first_idx if last_idx is None else last_idx
    r = tab_bar.tabRect(first_idx).united(tab_bar.tabRect(end_idx))
    tl = tab_bar.mapTo(root, r.topLeft())
    return QRect(tl, r.size()).adjusted(-3, -2, 3, 2)


def _badge_center(rect: QRect, anchor: str, radius: int, canvas_w: int, canvas_h: int) -> QPoint:
    if anchor == 'tl':
        pt = QPoint(rect.left() - 2, rect.top() - 2)
    elif anchor == 'tr':
        pt = QPoint(rect.right() + 2, rect.top() - 2)
    elif anchor == 'bl':
        pt = QPoint(rect.left() - 2, rect.bottom() + 2)
    elif anchor == 'br':
        pt = QPoint(rect.right() + 2, rect.bottom() + 2)
    elif anchor == 'left':
        pt = QPoint(rect.left() - radius - 4, rect.center().y())
    elif anchor == 'right':
        pt = QPoint(rect.right() + radius + 4, rect.center().y())
    elif anchor == 'top':
        pt = QPoint(rect.center().x(), rect.top() - radius - 3)
    elif anchor == 'bottom':
        pt = QPoint(rect.center().x(), rect.bottom() + radius + 3)
    elif anchor == 'tl_in':
        pt = QPoint(rect.left() + radius + 5, rect.top() + radius + 5)
    elif anchor == 'tr_in':
        pt = QPoint(rect.right() - radius - 5, rect.top() + radius + 5)
    else:
        pt = QPoint(rect.left() + radius + 5, rect.top() + radius + 5)

    margin = radius + 4
    x = max(margin, min(canvas_w - margin, pt.x()))
    y = max(margin, min(canvas_h - margin, pt.y()))
    return QPoint(x, y)


def _annotate(pixmap: QPixmap, callouts: list[tuple[int, QRect, str, str]]) -> QImage:
    """在真实界面截图上叠加编号高亮框与底部图例条。"""
    src = pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)
    w, h = src.width(), src.height()

    legend_font = theme.ui_font(9.5, QFont.Weight.Medium)
    badge_font = theme.ui_font(9.5, QFont.Weight.Bold)
    legend_badge_font = theme.ui_font(8.5, QFont.Weight.Bold)
    fm = QFontMetrics(legend_font)

    # 计算底部图例排布（自动单行或两行折行）
    pad_x = 18
    item_gap = 20
    circle_d = 20
    text_gap = 7
    row_h = 30
    max_line_w = w - pad_x * 2

    rows: list[list[tuple[int, str, int]]] = [[]]
    cur_w = 0
    for number, _, label, _ in callouts:
        item_w = circle_d + text_gap + fm.horizontalAdvance(label)
        if rows[-1] and cur_w + item_gap + item_w > max_line_w:
            rows.append([])
            cur_w = 0
        if rows[-1]:
            cur_w += item_gap
        rows[-1].append((number, label, item_w))
        cur_w += item_w

    legend_h = 14 + len(rows) * row_h + 6
    canvas = QImage(w, h + legend_h, QImage.Format.Format_ARGB32)
    canvas.fill(QColor('#FFFFFF'))

    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)

    painter.drawImage(0, 0, src)

    # 绘制每个标注框与圆形编号徽标
    radius = 12
    for number, rect, _, anchor in callouts:
        rf = QRectF(rect).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(CALLOUT_FILL)
        painter.drawRoundedRect(rf, 6.0, 6.0)

        painter.setPen(QPen(CALLOUT_STROKE, 2.2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rf, 6.0, 6.0)

        center = _badge_center(rect, anchor, radius, w, h)
        # 外白描边保证徽标在任何控件背景上都清晰分离
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(BADGE_RING)
        painter.drawEllipse(center, radius + 2, radius + 2)
        painter.setBrush(BADGE_BG)
        painter.drawEllipse(center, radius, radius)

        painter.setFont(badge_font)
        painter.setPen(BADGE_FG)
        badge_rect = QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2)
        painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, str(number))

    # 绘制底部图例条
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(LEGEND_BG)
    painter.drawRect(QRectF(0, h, w, legend_h))
    painter.setPen(QPen(LEGEND_BORDER, 1.0))
    painter.drawLine(0, h, w, h)

    y = h + 10
    for row in rows:
        x = pad_x
        for number, label, item_w in row:
            cy = y + row_h // 2
            cx = x + circle_d // 2
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(BADGE_BG)
            painter.drawEllipse(QPoint(cx, cy), circle_d // 2, circle_d // 2)

            painter.setFont(legend_badge_font)
            painter.setPen(BADGE_FG)
            painter.drawText(
                QRectF(cx - circle_d / 2, cy - circle_d / 2, circle_d, circle_d),
                Qt.AlignmentFlag.AlignCenter,
                str(number),
            )

            painter.setFont(legend_font)
            painter.setPen(LEGEND_TEXT)
            painter.drawText(
                QRectF(x + circle_d + text_gap, y, item_w - circle_d - text_gap + 4, row_h),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                label,
            )
            x += item_w + item_gap
        y += row_h

    # 整体细外框
    painter.setPen(QPen(QColor('#D3DDE8'), 1.0))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawRect(QRectF(0.5, 0.5, w - 1.0, h + legend_h - 1.0))
    painter.end()
    return canvas


def _sanitize_widget_paths(widget: QWidget, replacements: list[tuple[str, str]]) -> None:
    """截图前将本机临时路径替换为中性教学路径，避免在内置引导图中泄露本机用户名。"""
    def clean(text: str) -> str:
        result = text
        for old, new in replacements:
            if old:
                result = result.replace(old, new)
                result = result.replace(old.replace('\\', '\\\\'), new.replace('\\', '\\\\'))
                result = result.replace(old.replace('\\', '/'), new.replace('\\', '/'))
        return result

    for lbl in widget.findChildren(QLabel):
        txt = lbl.text()
        if txt:
            updated = clean(txt)
            if updated != txt:
                lbl.setText(updated)
    for edit in widget.findChildren(QPlainTextEdit):
        txt = edit.toPlainText()
        if txt:
            updated = clean(txt)
            if updated != txt:
                edit.setPlainText(updated)
    for browser in widget.findChildren(QTextBrowser):
        html = browser.toHtml()
        updated = clean(html)
        if updated != html:
            browser.setHtml(updated)
    for tree in widget.findChildren(QTreeWidget):
        cols = tree.columnCount()

        def walk(item):
            for col in range(cols):
                txt = item.text(col)
                if txt:
                    updated = clean(txt)
                    if updated != txt:
                        item.setText(col, updated)
            for idx in range(item.childCount()):
                walk(item.child(idx))

        for i in range(tree.topLevelItemCount()):
            walk(tree.topLevelItem(i))


def _pump(qt: QApplication, app: App | None = None, seconds: float = 0.2) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        qt.processEvents()
        if app is not None:
            app.poll()
        time.sleep(0.015)
    qt.processEvents()


def _create_sparse_large_demo(target: Path) -> bool:
    """在 NTFS 上快速创建 2 GiB 稀疏 RAW 演示镜像（复用 demo_volume.dd）。"""
    target.touch()
    res = subprocess.run(['fsutil', 'sparse', 'setflag', str(target)], capture_output=True)
    if res.returncode != 0:
        return False
    size = 2 << 30
    volume = EVIDENCE_DIR / 'demo_volume.dd'
    length = volume.stat().st_size
    offset = 2048
    mbr = bytearray(512)
    struct.pack_into('<B3sB3sII', mbr, 446, 0, bytes(3), 6, bytes(3), offset, length // 512)
    mbr[510:] = bytes.fromhex('55aa')
    with target.open('r+b') as out, volume.open('rb') as src:
        out.write(mbr)
        out.seek(offset * 512)
        shutil.copyfileobj(src, out)
        out.seek(size - 1)
        out.write(b'\x00')
    return True


def _select_tab(app: App, keyword: str) -> int:
    bar = app.tabs.tabBar()
    for i in range(bar.count()):
        if keyword in bar.tabText(i):
            bar.setCurrentIndex(i)
            return i
    raise ValueError(f'未找到标签页：{keyword}')


def _find_nav_item(tree: QTreeWidget, needle: str):
    def walk(item):
        if needle in item.text(0):
            return item
        for i in range(item.childCount()):
            found = walk(item.child(i))
            if found is not None:
                return found
        return None

    for i in range(tree.topLevelItemCount()):
        found = walk(tree.topLevelItem(i))
        if found is not None:
            return found
    return None


def _save_figure(name: str, widget: QWidget, callouts: list[tuple[int, QRect, str, str]],
                 replacements: list[tuple[str, str]]) -> Path:
    _sanitize_widget_paths(widget, replacements)
    QApplication.processEvents()
    image = _annotate(widget.grab(), callouts)
    GUIDE_ASSET_DIR.mkdir(parents=True, exist_ok=True)
    dest = GUIDE_ASSET_DIR / name
    if not image.save(str(dest), 'PNG'):
        raise OSError(f'保存引导图失败：{dest}')
    print(f'generated {dest.relative_to(ROOT)} ({image.width()}x{image.height()}, {dest.stat().st_size:,} bytes)')
    return dest


def build_all() -> list[Path]:
    qt = QApplication.instance() or QApplication([])
    TEST_WORK_DIR.mkdir(exist_ok=True)
    outputs: list[Path] = []

    with tempfile.TemporaryDirectory(dir=TEST_WORK_DIR) as tmp_dir:
        tmp = Path(tmp_dir)
        cases_root = tmp / 'cases'
        cases_root.mkdir()
        ev_root = tmp / 'evidence'
        ev_root.mkdir()
        demo_copy = ev_root / 'demo.dd'
        shutil.copy2(EVIDENCE_DIR / 'demo.dd', demo_copy)

        replacements = [
            (str(ev_root.resolve()), r'D:\TraceDesk\evidence'),
            (str(cases_root.resolve()), r'D:\TraceDesk\cases'),
            (str(ROOT.resolve()), r'D:\TraceDesk'),
        ]

        win = QMainWindow()
        app = App(win)
        open_cases: list[Case] = []
        try:
            win.resize(1240, 760)
            win.show()

            # 构建完整真实演示案件（含来源登记、导出、哈希、比对、笔记、搜索与 MCP 审计来源）
            case = Case.create(cases_root, 'DEMO-2026-001', '张明', 'FAT16 教学镜像')
            open_cases.append(case)
            case.load(demo_copy)
            entries = case.scan_all()
            case.verify()
            demo_digest = sha256(demo_copy)
            case.register_source({
                'evidence_id': 'EVID-2026-01',
                'source': '课程演示移交包',
                'acquired': '2026-11-21 09:30 UTC+8',
                'tool': 'TraceDesk make_demo.py',
                'expected_sha256': demo_digest,
            })
            case_txt = next(e for e in entries if e['path'] == 'DOCS/CASE.TXT')
            readme_txt = next(e for e in entries if e['path'] == 'README.TXT')
            exported_case = case.export(case_txt)
            exported_readme = case.export(readme_txt)
            examine(case, case_txt)
            examine(case, case_txt, exported_case)
            record_note(case, case_txt, '文件内偏移 5 处命中字节 6E 6F 74 65（ASCII: note），已核验导出副本一致。')
            record_note(case, readme_txt, '根目录演示说明文件，确认只读分析流程。')

            # 追加一条真实 MCP 来源审计记录以便在审计日志引导图中直观区分 人工 / MCP
            case_folder = case.folder
            case.close()
            mcp_case = Case(case_folder, actor='张明', origin='mcp')
            try:
                mcp_case.log('FILE_HASH', 'DOCS/CASE.TXT', '成功',
                             offset=case_txt['offset'], inode=case_txt['inode'], deleted=False,
                             image_sha256=demo_digest, size=case_txt['size'], recorded_size=case_txt['size'],
                             sha256=sha256(exported_case))
            finally:
                mcp_case.close()

            case = Case(case_folder)
            open_cases.append(case)
            run_content_search(case, '6E 6F 74 65', 'HEX', SearchControl(), lambda *_: None)
            app._replace_case(case)
            _pump(qt, app, 0.25)

            # ------------------------------------------------------------------
            # 图 1：快速上手：工作台总览（定位 DOCS/CASE.TXT 并展示文本预览）
            # ------------------------------------------------------------------
            _select_tab(app, '文件浏览')
            app.browser.navigation.expandAll()
            _pump(qt, app, 0.1)
            docs_node = _find_nav_item(app.browser.navigation, 'DOCS')
            if docs_node is not None:
                app.browser.navigation.setCurrentItem(docs_node)
                _pump(qt, app, 0.15)
            for r in range(app.browser.tree.topLevelItemCount()):
                item = app.browser.tree.topLevelItem(r)
                if 'CASE.TXT' in item.text(0):
                    app.browser.tree.setCurrentItem(item)
                    break
            _pump(qt, app, 0.3)

            preview_frame = app.browser.preview.parentWidget()
            outputs.append(_save_figure(
                '01_quickstart.png',
                win,
                [
                    (1, _union_rect(win, [app.view.action_buttons['new_case'], app.view.action_buttons['open_case']]),
                     '新建 / 打开案件', 'bottom'),
                    (2, _union_rect(win, [app.view.action_buttons['load'], app.view.action_buttons['verify']]),
                     '加载镜像与校验', 'left'),
                    (3, _widget_rect(win, app.browser.navigation, pad=0).adjusted(2, 2, -2, -2),
                     '左侧文件树定位目录与文件', 'tr_in'),
                    (4, _widget_rect(win, preview_frame, pad=0).adjusted(2, 2, -2, -2),
                     '文本/十六进制预览与导出所选文件', 'top'),
                    (5, _union_rect(win, [app.view.action_buttons['report'], app.view.action_buttons['export_bundle']]),
                     '生成报告与导出复核包', 'bottom'),
                ],
                replacements,
            ))

            # ------------------------------------------------------------------
            # 图 4：浏览目录、筛选文件与多格式预览（筛选 .txt + 十六进制）
            # ------------------------------------------------------------------
            root_node = _find_nav_item(app.browser.navigation, 'demo.dd')
            if root_node is not None:
                app.browser.navigation.setCurrentItem(root_node)
                _pump(qt, app, 0.15)
            app.browser.suffix.setText('.txt')
            app.browser.apply_filter(case.filtered('.txt', ''))
            _pump(qt, app, 0.15)
            for r in range(app.browser.tree.topLevelItemCount()):
                item = app.browser.tree.topLevelItem(r)
                if 'CASE.TXT' in item.text(0):
                    app.browser.tree.setCurrentItem(item)
                    break
            _pump(qt, app, 0.25)
            app.browser.preview.formats.tabBar().setCurrentIndex(1)
            _pump(qt, app, 0.2)

            outputs.append(_save_figure(
                '04_browse_preview.png',
                win,
                [
                    (1, _union_rect(win, [app.browser.expand_button, app.browser.collapse_button]),
                     '展开 / 折叠完整目录树', 'bottom'),
                    (2, _union_rect(win, [app.browser.suffix, app.browser.keyword,
                                          app.browser.status_filter, app.browser.filter_button,
                                          app.browser.reset_button]),
                     '后缀、关键词与状态筛选', 'bottom'),
                    (3, _widget_rect(win, app.browser.tree, pad=0).adjusted(2, 2, -2, -2),
                     '文件状态、inode 与 MACB 时间列表', 'br'),
                    (4, _union_rect(win, [app.browser.preview.formats.tabBar(), app.browser.preview.encoding]),
                     '文本/图片/十六进制切换与 9 种编码', 'top'),
                    (5, _widget_rect(win, app.browser.preview.status, pad=4),
                     '双击页码直接跳页', 'right'),
                ],
                replacements,
            ))
            app.browser.reset_filter()
            app.browser.preview.formats.tabBar().setCurrentIndex(0)

            # ------------------------------------------------------------------
            # 图 2：新建案件、加载镜像与登记来源（镜像与文件系统页）
            # ------------------------------------------------------------------
            _select_tab(app, '镜像与文件系统')
            _pump(qt, app, 0.2)
            ev_panel = app.view.panels['info']
            ev_split = ev_panel.summary.parentWidget()
            if hasattr(ev_split, 'setSizes'):
                ev_split.setSizes([465, 195])
            _pump(qt, app, 0.15)
            outputs.append(_save_figure(
                '02_case_and_source.png',
                win,
                [
                    (1, _union_rect(win, [app.view.action_buttons['new_case'], app.view.action_buttons['open_case']]),
                     '新建案件（隔离目录）或打开 case.json', 'bottom'),
                    (2, _widget_rect(win, app.view.action_buttons['load']),
                     '只读加载 RAW 或 .E01 首段', 'left'),
                    (3, _widget_rect(win, ev_panel.source_button),
                     '登记证据来源与交付方 SHA-256', 'left'),
                    (4, _widget_rect(win, ev_panel.summary, pad=0).adjusted(4, 4, -4, -4),
                     '核对固定摘要、卷声明范围与比对结论', 'tr_in'),
                    (5, _widget_rect(win, ev_panel.text, pad=0).adjusted(4, 4, -4, -4),
                     '查看原始分区表与文件系统详情', 'tr_in'),
                ],
                replacements,
            ))

            # ------------------------------------------------------------------
            # 图 5：内容搜索与实时复核（真实 HEX 搜索 6E 6F 74 65）
            # ------------------------------------------------------------------
            _select_tab(app, '内容搜索与复核')
            _pump(qt, app, 0.15)
            rev_panel = app.view.panels['review']
            rev_panel.query.setText('6E 6F 74 65')
            rev_panel.encoding.setCurrentText('HEX')
            rev_panel.scope.setCurrentText('全部文件')
            rev_panel.start()
            deadline = time.monotonic() + 15
            while rev_panel.searching and time.monotonic() < deadline:
                qt.processEvents()
                rev_panel._poll_search()
                time.sleep(0.02)
            _pump(qt, app, 0.25)
            if rev_panel.table.topLevelItemCount() > 0:
                hit_item = rev_panel.table.topLevelItem(0)
                hit_item.setCheckState(0, Qt.CheckState.Checked)
                rev_panel.table.setCurrentItem(hit_item)
            _pump(qt, app, 0.15)
            hit_vp = _widget_rect(win, rev_panel.table.viewport(), pad=0)
            hit_band = QRect(hit_vp.left() + 4, hit_vp.top() + 1, hit_vp.width() - 8, 36)

            outputs.append(_save_figure(
                '05_content_search.png',
                win,
                [
                    (1, _union_rect(win, [rev_panel.query, rev_panel.encoding, rev_panel.scope, rev_panel.search_button]),
                     '输入文字/HEX、选编码与范围后搜索（运行中可取消）', 'top'),
                    (2, _union_rect(win, [rev_panel.exclude_button, rev_panel.save_button]),
                     '排除勾选命中或批量保存为取证发现', 'bottom'),
                    (3, _header_section_rect(win, rev_panel.table, 0, 3),
                     '三态全选框与分区偏移表头下拉筛选', 'tr'),
                    (4, hit_band,
                     '实时命中结果（双击直达文件内字节偏移十六进制）', 'bottom'),
                ],
                replacements,
            ))

            # ------------------------------------------------------------------
            # 图 6：导出副本、恢复删除文件与取证发现
            # ------------------------------------------------------------------
            _select_tab(app, '取证发现')
            _pump(qt, app, 0.2)
            find_panel = app.view.panels['findings']
            target_finding = None
            for idx in range(find_panel.table.topLevelItemCount()):
                item = find_panel.table.topLevelItem(idx)
                if 'CASE.TXT' in item.text(1):
                    target_finding = item
                    break
            if target_finding is None and find_panel.table.topLevelItemCount() > 0:
                target_finding = find_panel.table.topLevelItem(0)
            if target_finding is not None:
                find_panel.table.setCurrentItem(target_finding)
                find_panel._open_detail(target_finding, 0)
                find_panel.split.setSizes([145, 430])
            _pump(qt, app, 0.2)

            outputs.append(_save_figure(
                '06_export_findings.png',
                win,
                [
                    (1, _widget_rect(win, find_panel.export_button),
                     '一键批量导出对应文件与汇总清单', 'left'),
                    (2, _header_section_rect(win, find_panel.table, 2, 3),
                     '按状态与分区偏移下拉筛选（序号/时间支持正倒序）', 'top'),
                    (3, _widget_rect(win, find_panel.table, pad=0).adjusted(4, 34, -4, -4),
                     '按路径、分区偏移与 inode 归组的取证记录', 'br'),
                    (4, _widget_rect(win, find_panel.text, pad=0).adjusted(4, 4, -4, -4),
                     '双击展开笔记、SHA-256 摘要与一致性比对明细', 'tr_in'),
                ],
                replacements,
            ))

            # ------------------------------------------------------------------
            # 图 7：MACB 时间线与审计日志（同时呈现 人工 / MCP 胶囊与详情）
            # ------------------------------------------------------------------
            _select_tab(app, '审计日志')
            _pump(qt, app, 0.2)
            audit_panel = app.view.panels['audit']
            mcp_row = None
            for idx in range(audit_panel.table.topLevelItemCount()):
                item = audit_panel.table.topLevelItem(idx)
                if item.text(2) == 'MCP':
                    mcp_row = item
                    break
            chosen_row = mcp_row or (audit_panel.table.topLevelItem(0) if audit_panel.table.topLevelItemCount() else None)
            if chosen_row is not None:
                audit_panel.table.setCurrentItem(chosen_row)
                audit_panel._open_detail(chosen_row, 0)
                audit_panel.split.setSizes([275, 300])
            _pump(qt, app, 0.2)
            tab_bar = app.tabs.tabBar()
            t_idx = next(i for i in range(tab_bar.count()) if '时间线' in tab_bar.tabText(i))
            a_idx = next(i for i in range(tab_bar.count()) if '审计日志' in tab_bar.tabText(i))

            outputs.append(_save_figure(
                '07_timeline_audit.png',
                win,
                [
                    (1, _tab_bar_rect(win, tab_bar, t_idx, a_idx),
                     '在 MACB 时间线与审计日志间切换', 'bottom'),
                    (2, _header_section_rect(win, audit_panel.table, 0, 1),
                     '单击序号或时间列切换正序/倒序', 'top'),
                    (3, _header_section_rect(win, audit_panel.table, 2, 5),
                     '按来源（人工/MCP）、人员、操作与结果下拉筛选', 'top'),
                    (4, _widget_rect(win, audit_panel.text, pad=0).adjusted(4, 4, -4, -4),
                     '双击查看操作参数与前后关联 SHA-256 哈希链', 'tr_in'),
                ],
                replacements,
            ))

            # ------------------------------------------------------------------
            # 图 8：生成报告与交付复核包（真实复核包材料选择弹窗，含 1 项缺失提示）
            # ------------------------------------------------------------------
            exported_readme.unlink(missing_ok=True)
            export_rows = inspect_bundle_exports(case)
            search_rows = inspect_bundle_searches(case)
            bundle_dlg = BundleExportDialog(win, export_rows, search_rows)
            bundle_dlg.resize(920, 620)
            bundle_dlg.show()
            _pump(qt, None, 0.2)
            banner_widget = bundle_dlg.findChild(QWidget, 'bundleExportBanner')
            outputs.append(_save_figure(
                '08_report_bundle.png',
                bundle_dlg,
                [
                    (1, _widget_rect(bundle_dlg, banner_widget),
                     '缺失副本 / 搜索记录中文明细提示', 'br'),
                    (2, _tab_bar_rect(bundle_dlg, bundle_dlg.tabs.tabBar(), 0, bundle_dlg.tabs.count() - 1),
                     '导出副本与内容搜索记录双标签页', 'right'),
                    (3, _union_rect(bundle_dlg, [bundle_dlg.select_all_button, bundle_dlg.select_none_button,
                                                 bundle_dlg.toggle_missing_button]),
                     '按需勾选材料或切换“仅看缺失项”', 'right'),
                    (4, _union_rect(bundle_dlg, [bundle_dlg.copy_missing_button, bundle_dlg.confirm_button]),
                     '一键复制缺失清单并生成复核包 ZIP + .sha256', 'top'),
                ],
                replacements,
            ))
            bundle_dlg.close()
            bundle_dlg.deleteLater()

            # ------------------------------------------------------------------
            # 图 9：MCP 服务端接入与 AI 协同（真实 MCP 配置弹窗 + 案件锁提示）
            # ------------------------------------------------------------------
            manager = LocalHttpMcpManager(cases_root=cases_root)
            mcp_dlg = McpDialog(win, manager, active_case=case, release_case=lambda: True)
            mcp_dlg.resize(840, 610)
            mcp_dlg.show()
            _pump(qt, None, 0.2)
            outputs.append(_save_figure(
                '09_mcp_dialog.png',
                mcp_dlg,
                [
                    (1, _widget_rect(mcp_dlg, mcp_dlg.lock_banner),
                     '桌面端占用案件锁时可一键释放供 MCP 接入', 'tr'),
                    (2, _union_rect(mcp_dlg, [mcp_dlg.port_spin, mcp_dlg.toggle_button]),
                     '本机回环端口与本地 Streamable HTTP 启停', 'bottom'),
                    (3, _tab_bar_rect(mcp_dlg, mcp_dlg.tabs.tabBar(), 0, mcp_dlg.tabs.count() - 1),
                     '查看 stdio / HTTP 配置及全部 19 个工具清单', 'right'),
                    (4, _union_rect(mcp_dlg, [mcp_dlg.copy_stdio_json_btn, mcp_dlg.copy_stdio_cmd_btn]),
                     '一键复制客户端配置 JSON 或命令行启动指令', 'right'),
                ],
                replacements,
            ))
            mcp_dlg.close()
            mcp_dlg.deleteLater()

            # ------------------------------------------------------------------
            # 图 3：大镜像、完整索引与 SHA-256（真实 2 GiB 稀疏 RAW 按需目录浏览）
            # ------------------------------------------------------------------
            large_img = ev_root / 'large_disk.dd'
            if _create_sparse_large_demo(large_img):
                large_case = Case.create(cases_root, 'LARGE-2026-002', '张明', '2 GiB 大容量教学镜像')
                open_cases.append(large_case)
                large_case.load(large_img)
                app._replace_case(large_case)
                # 等待 first_root 后台任务完成后进入 DOCS 子目录，使“返回上级目录”按钮真实可见
                deadline = time.monotonic() + 15
                while app.busy and time.monotonic() < deadline:
                    qt.processEvents()
                    app.poll()
                    time.sleep(0.015)
                docs_entry = next((e for e in large_case.directory_entries if e['path'] == 'DOCS'), None)
                if docs_entry is not None:
                    large_case.browse_directory(2048, docs_entry['inode'], docs_entry['path'])
                    app.refresh(reset=True)
                _select_tab(app, '文件浏览')
                _pump(qt, app, 0.25)

                outputs.append(_save_figure(
                    '03_large_image.png',
                    win,
                    [
                        (1, _widget_rect(win, app.view.custody_bar, pad=0).adjusted(2, 2, -2, -2),
                         '保管状态条显示大镜像“待固定 / 初步分析”状态', 'tr_in'),
                        (2, _widget_rect(win, app.browser.parent_button),
                         '按需目录浏览：随时返回上级目录', 'right'),
                        (3, _widget_rect(win, app.browser.index_button),
                         '按需建立完整文件索引（执行中可随时取消）', 'right'),
                        (4, _widget_rect(win, app.view.action_buttons['verify']),
                         '后台校验 SHA-256 基线（校验期间可继续浏览）', 'tr'),
                    ],
                    replacements,
                ))
        finally:
            app._shutdown()
            for item in open_cases:
                try:
                    item.close()
                except Exception:
                    pass
            win.close()

    return outputs


if __name__ == '__main__':
    build_all()
