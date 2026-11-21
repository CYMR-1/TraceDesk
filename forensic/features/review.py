"""搜索、来源登记与复核材料入口。"""
import collections
import queue
from time import monotonic

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog, QFrame, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QTabWidget, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget)

from ..core.content_search import SearchControl, pattern, search
from ..core.coverage import SOURCE_FIELDS, source_status
from ..core.formatting import display_time
from ..core.preview import PAGE_BYTES
from ..core.review import (build_bundle, format_missing_exports, inspect_bundle_exports,
                           inspect_bundle_searches)
from ..core.tasks import TaskRunner
from ..engines.tsk import deleted_source_note
from ..ui import theme
from ..ui.delegates import ForensicItemDelegate
from ..ui.dialogs import edit_evidence_source
from ..ui.filter_header import FilterHeaderView
from ..ui.icons import ui_icon
from ..ui.metrics import CONTROL_GAP, DIALOG_MARGIN, ROW_HEIGHT_TABLE
from ..ui.preview import FilePreview
from ..ui.views import ExportResultDialog
from .api import Action, Feature, Panel

LIVE_DRAIN_LIMIT = 500


class ReviewPanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.case = self.control = self.record = self.name = self._active = None
        self.hits = []
        self._checked_indices = set()
        self._excluded_indices = set()
        self._offset_counts = collections.Counter()
        self.search_runner = TaskRunner()
        self._hit_queue = queue.Queue()
        self._progress = None
        self._notice = None
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(100)
        self._poll_timer.timeout.connect(self._poll_search)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        top_bar = QFrame(self)
        top_bar.setObjectName('panelTopBar')
        tools = QHBoxLayout(top_bar)
        tools.setContentsMargins(14, 8, 14, 8)
        tools.setSpacing(CONTROL_GAP)
        self.query = QLineEdit(top_bar)
        self.query.setPlaceholderText('输入文字或十六进制字节；搜索文件内容')
        self.query.setClearButtonEnabled(True)
        self.query.addAction(ui_icon('search', theme.TEXT_MUTED, 14), QLineEdit.ActionPosition.LeadingPosition)
        self.encoding = QComboBox(top_bar)
        self.encoding.addItems(['UTF-8', 'UTF-16LE', 'GBK', 'HEX'])
        self.encoding.setMinimumWidth(94)
        self.scope = QComboBox(top_bar)
        self.scope.addItems(['全部文件', '文件浏览中选中的文件'])
        self.scope.setMinimumWidth(148)
        tools.addWidget(self.query, 1)
        tools.addWidget(self.encoding)
        tools.addWidget(self.scope)
        self.search_button = QPushButton('搜索', top_bar)
        self.search_button.setProperty('role', 'accent')
        self.search_button.clicked.connect(self.toggle_search)
        tools.addWidget(self.search_button)

        divider = QFrame(top_bar)
        divider.setObjectName('toolbarDivider')
        tools.addWidget(divider)

        self.exclude_button = QPushButton('排除所选项', top_bar)
        self.exclude_button.setToolTip('在本次搜索中排除勾选（或当前选中）的命中')
        self.exclude_button.clicked.connect(self.exclude_selected)
        tools.addWidget(self.exclude_button)
        self.save_button = QPushButton('保存为取证发现', top_bar)
        self.save_button.setProperty('role', 'soft')
        self.save_button.setToolTip('将勾选（或当前选中）的命中保存为取证发现')
        self.save_button.clicked.connect(self.bookmark)
        tools.addWidget(self.save_button)
        layout.addWidget(top_bar)
        self.query.returnPressed.connect(self.start)

        sub_bar = QFrame(self)
        sub_bar.setObjectName('panelSubBar')
        sub_layout = QHBoxLayout(sub_bar)
        sub_layout.setContentsMargins(14, 6, 14, 6)
        sub_layout.setSpacing(CONTROL_GAP)
        self.status = QLabel(sub_bar)
        self.status.setWordWrap(True)
        self.status.setProperty('role', 'muted')
        self.status.setFont(theme.ui_font(8.5))
        sub_layout.addWidget(self.status, 1)
        layout.addWidget(sub_bar)

        self.table = QTreeWidget(self)
        self.table.setProperty('flush', True)
        self.table.setRootIsDecorated(False)
        self.table.setAlternatingRowColors(True)
        self.table.setUniformRowHeights(True)
        self.header = FilterHeaderView(self.table, checkable_column=0, check_label='全选', filter_columns=(3,))
        self.table.setHeader(self.header)
        self.table.setHeaderLabels(['', '序号', '文件内字节偏移', '分区偏移', 'inode', '镜像内路径', '前文 HEX', '后文 HEX'])
        self.table.headerItem().setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
        self.table.headerItem().setToolTip(0, '全选 / 取消全选')
        self.table.headerItem().setToolTip(3, '单击下拉筛选分区偏移')
        self.table.setItemDelegate(
            ForensicItemDelegate(
                self.table,
                mono_columns={1, 2, 3, 4, 6, 7},
                subtle_columns={6, 7},
                accent_column=0,
                row_height=ROW_HEIGHT_TABLE,
            )
        )
        self.header.toggled.connect(self._set_all_checked)
        self.header.filter_changed.connect(self._apply_offset_filter)
        for column, width in ((0, 68), (1, 64), (2, 118), (3, 110), (4, 88), (5, 320), (6, 168), (7, 168)):
            self.table.setColumnWidth(column, width)
        self.table.itemDoubleClicked.connect(self.preview)
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table, 1)

    def _set_search_button(self, text, role, enabled=True):
        self.search_button.setText(text)
        self.search_button.setProperty('role', role)
        theme.repolish(self.search_button)
        self.search_button.setEnabled(enabled)

    @property
    def searching(self):
        return self.search_runner.busy

    def shutdown(self):
        self._poll_timer.stop()
        self.cancel()

    def _refresh_offset_options(self):
        values = [str(offset) for offset in sorted(self._offset_counts)]
        self.header.set_filter_options(3, values)

    def _visible_counts(self):
        offset_filter = self.header.filter_value(3)
        if offset_filter is None:
            return self.table.topLevelItemCount(), len(self._checked_indices)
        visible = checked = 0
        for row in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(row)
            if not item.isHidden():
                visible += 1
                if item.checkState(0) == Qt.CheckState.Checked:
                    checked += 1
        return visible, checked

    def _sync_check_state(self, *_):
        total, checked = self._visible_counts()
        if not total or not checked:
            self.header.set_check_state(Qt.CheckState.Unchecked)
        elif checked == total:
            self.header.set_check_state(Qt.CheckState.Checked)
        else:
            self.header.set_check_state(Qt.CheckState.PartiallyChecked)
        self.save_button.setText(f'保存为取证发现 ({checked})' if checked else '保存为取证发现')
        self.exclude_button.setText(f'排除所选项 ({checked})' if checked else '排除所选项')

    def _on_item_changed(self, item, column):
        if column != 0:
            return
        index = item.data(0, Qt.ItemDataRole.UserRole)
        if item.checkState(0) == Qt.CheckState.Checked:
            self._checked_indices.add(index)
        else:
            self._checked_indices.discard(index)
        self._sync_check_state()

    def _apply_offset_filter(self, column, value):
        if column != 3:
            return
        self.table.setUpdatesEnabled(False)
        try:
            for row in range(self.table.topLevelItemCount()):
                item = self.table.topLevelItem(row)
                item.setHidden(value is not None and item.text(3) != value)
        finally:
            self.table.setUpdatesEnabled(True)
        self._sync_check_state()

    def _reset_results(self):
        self.table.clear()
        self.hits = []
        self._checked_indices.clear()
        self._excluded_indices.clear()
        self._offset_counts.clear()
        self.header.clear_filters(emit=False)
        self._refresh_offset_options()
        self._sync_check_state()

    def set_text(self, context):
        self.context = context
        case = context.case()
        if self.case is not case or not self.status.text():
            if self.case is not case:
                self.shutdown()
                self._set_search_button('搜索', 'accent', True)
            self._reset_results()
            self.record = self.name = self._active = None
            self.status.setText('搜索当前清单中的普通文件及删除记录，不含未分配空间。双击命中定位原始字节。')
        self.case = case

    def ready(self):
        if not self.context.available():
            return False
        if not self.case.data['evidence']:
            QMessageBox.information(self, '提示', '请先加载镜像。')
            return False
        return True

    def toggle_search(self):
        if self.searching:
            self.cancel()
        else:
            self.start()

    def start(self):
        if self.searching or not self.ready():
            return
        query, encoding = self.query.text(), self.encoding.currentText()
        try:
            needle = pattern(query, encoding)
        except ValueError as error:
            QMessageBox.warning(self, '搜索条件无效', str(error))
            return
        case, control = self.case, SearchControl()
        selected = self.context.selected_entry() if self.scope.currentIndex() else None
        if self.scope.currentIndex() and selected is None:
            QMessageBox.information(self, '提示', '请先在文件浏览中选中一个文件。')
            return
        self.control = control
        self.record = self.name = self._progress = self._notice = None
        self._hit_queue = queue.Queue()
        self._reset_results()
        self._active = dict(
            query=query, encoding=encoding, needle=needle.hex(),
            image_sha256=case.data['evidence']['sha256'],
            verification=case.source_note() or '搜索进行中（实时命中）',
        )
        self._set_search_button('取消搜索', 'warning', True)
        self.status.setText('正在后台搜索 · 命中将实时显示，可直接勾选、双击预览、排除或保存为取证发现。')

        def on_progress(stage, done, total):
            self._progress = (stage, done, total)

        def on_hit(batch):
            self._hit_queue.put(batch)

        def work():
            try:
                return search(case, query, encoding, control, on_progress, limit=None,
                              selected=selected, on_hit=on_hit)
            except Exception as error:
                return str(error)

        self.search_runner.submit(work, self.finished)
        self._poll_timer.start()

    def cancel(self):
        if self.control:
            self.control.cancel()
            if self.searching:
                self._set_search_button('正在取消…', 'warning', False)

    def _append_hits(self, batch):
        if not batch:
            return
        base = len(self.hits)
        self.hits.extend(batch)
        offset_filter = self.header.filter_value(3)
        existing_rows = self.table.topLevelItemCount()
        new_offsets = False
        items = []
        for pos_in_batch, (entry, pos, before, after) in enumerate(batch):
            index = base + pos_in_batch
            if index in self._excluded_indices:
                continue
            offset = entry['offset']
            if offset not in self._offset_counts:
                new_offsets = True
            self._offset_counts[offset] += 1
            seq = existing_rows + len(items) + 1
            item = QTreeWidgetItem(['', str(seq), str(pos), str(offset), str(entry['inode']),
                                    entry['path'], before, after])
            item.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setData(0, Qt.ItemDataRole.UserRole, index)
            items.append((item, str(offset)))
        if items:
            self.table.setUpdatesEnabled(False)
            self.table.blockSignals(True)
            try:
                self.table.addTopLevelItems([item for item, _ in items])
                if offset_filter is not None:
                    for item, offset_text in items:
                        if offset_text != offset_filter:
                            item.setHidden(True)
            finally:
                self.table.blockSignals(False)
                self.table.setUpdatesEnabled(True)
        if new_offsets:
            self._refresh_offset_options()
        self._sync_check_state()

    def _drain_hits(self, max_items=None):
        batch = []
        while max_items is None or len(batch) < max_items:
            try:
                batch.extend(self._hit_queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self._append_hits(batch)

    def _poll_search(self):
        self._drain_hits(LIVE_DRAIN_LIMIT)
        result = self.search_runner.poll()
        if result is None:
            shown = self.table.topLevelItemCount()
            excluded = len(self._excluded_indices)
            hit_text = f'已命中 {shown} 条' + (f'（已排除 {excluded} 条）' if excluded else '')
            progress = self._progress
            if progress:
                stage, done, total = progress
                if total:
                    percent = 100 * done // total
                    text = f'正在{stage} · {percent}%（{done:,}/{total:,}） · {hit_text} · 可随时勾选、预览、排除或保存'
                else:
                    text = f'正在{stage}… · {hit_text}'
            else:
                text = f'正在后台搜索… · {hit_text}'
            if self._notice and monotonic() < self._notice[0]:
                text = self._notice[1] + '  |  ' + text
            self.status.setText(text)
            return
        self._poll_timer.stop()
        self._drain_hits()
        if result.error:
            self.finished(str(result.error))
        else:
            self.finished(result.value)

    def _format_final_status(self):
        excluded = len(self._excluded_indices)
        shown = self.table.topLevelItemCount()
        excluded_note = f'（已排除 {excluded} 条，当前保留 {shown} 条）' if excluded else ''
        return (f"{self.record['status']} · 已处理 {self.record['visited']}/{self.record['eligible']} 项 · "
                f"命中 {len(self.hits)} 条{excluded_note} · 读取失败 {len(self.record['errors'])} 项。"
                f"{self.record['verification']}。清单及失败明细：reports/{self.name}")

    def finished(self, result):
        self.control = None
        self._set_search_button('搜索', 'accent', True)
        if isinstance(result, str):
            self.status.setText('搜索失败：' + result)
            return
        record, final_hits, name = result
        self.record, self.name = record, name
        self._active = dict(
            query=record['query'], encoding=record['encoding'], needle=record['needle'],
            image_sha256=record['image_sha256'], verification=record['verification'],
        )
        if not final_hits and self.hits:
            self._reset_results()
        elif len(final_hits) > len(self.hits):
            self._append_hits(final_hits[len(self.hits):])
        self.status.setText(self._format_final_status())
        if hasattr(self.context, 'refresh'):
            self.context.refresh()

    def preview(self, item, column):
        if column == 0 or not self.case or not self.case.data['evidence']:
            return
        meta = self.record or self._active
        if not meta:
            return
        entry, pos, _, _ = self.hits[item.data(0, Qt.ItemDataRole.UserRole)]
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{entry['path']} · 命中字节 0x{pos:X}")
        dialog.resize(860, 550)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        header_bar = QFrame(dialog)
        header_bar.setObjectName('dialogHeaderBar')
        header_layout = QHBoxLayout(header_bar)
        header_layout.setContentsMargins(14, 10, 14, 10)
        header_layout.setSpacing(CONTROL_GAP)
        meta_label = QLabel(f"文件内偏移 {pos}（0x{pos:X}） · {meta['encoding']} · {meta['needle'][:96]}", header_bar)
        meta_label.setFont(theme.mono_font(9.5))
        meta_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        meta_label.setWordWrap(True)
        header_layout.addWidget(meta_label, 1)
        layout.addWidget(header_bar)
        view = FilePreview(dialog)
        layout.addWidget(view, 1)
        validate = self.case.check_source if self.case.data['evidence'].get('large_image') else None
        view.open_file(self.case.image(), entry, validate=validate)
        view.formats.setCurrentIndex(1)
        pending = True

        def poll():
            nonlocal pending
            view.poll()
            if pending and view.window:
                view.formats.setCurrentIndex(1)
                target = pos // PAGE_BYTES
                if target != view.page:
                    view.turn(target - view.page)
                else:
                    highlight()
                pending = False
            elif not pending and view.page == pos // PAGE_BYTES and view.window:
                highlight()
                timer.timeout.disconnect(poll)
                timer.timeout.connect(view.poll)

        def highlight():
            row = view.rows.topLevelItem(pos % PAGE_BYTES // 16)
            if row:
                view.rows.setCurrentItem(row)
                view.rows.scrollToItem(row)

        timer = QTimer(dialog)
        timer.timeout.connect(poll)
        timer.start(50)
        try:
            dialog.exec()
        finally:
            timer.stop()
            view.clear()
            dialog.deleteLater()

    def checked_items(self):
        return [item for item in map(self.table.topLevelItem, range(self.table.topLevelItemCount()))
                if not item.isHidden() and item.checkState(0) == Qt.CheckState.Checked]

    def _target_items(self):
        items = self.checked_items()
        if items:
            return items
        current = self.table.currentItem()
        return [current] if current is not None and not current.isHidden() else []

    def _set_all_checked(self, checked):
        count = self.table.topLevelItemCount()
        if not count:
            self.header.set_check_state(Qt.CheckState.Unchecked)
            return
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)
        try:
            for row in range(count):
                item = self.table.topLevelItem(row)
                if item.isHidden():
                    continue
                item.setCheckState(0, state)
                index = item.data(0, Qt.ItemDataRole.UserRole)
                if checked:
                    self._checked_indices.add(index)
                else:
                    self._checked_indices.discard(index)
        finally:
            self.table.blockSignals(False)
            self.table.setUpdatesEnabled(True)
        self._sync_check_state()

    def toggle_all(self, column=0):
        if column != 0 or not self.table.topLevelItemCount():
            return
        self._set_all_checked(self.header.check_state() != Qt.CheckState.Checked)

    def exclude_selected(self):
        items = self._target_items()
        if not items:
            return
        rows = sorted((self.table.indexOfTopLevelItem(item) for item in items), reverse=True)
        first_row = rows[-1]
        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)
        try:
            for row in rows:
                removed = self.table.takeTopLevelItem(row)
                index = removed.data(0, Qt.ItemDataRole.UserRole)
                self._excluded_indices.add(index)
                self._checked_indices.discard(index)
                offset = self.hits[index][0]['offset']
                self._offset_counts[offset] -= 1
                if self._offset_counts[offset] <= 0:
                    del self._offset_counts[offset]
            for row in range(first_row, self.table.topLevelItemCount()):
                self.table.topLevelItem(row).setText(1, str(row + 1))
        finally:
            self.table.blockSignals(False)
            self.table.setUpdatesEnabled(True)
        self._refresh_offset_options()
        self._sync_check_state()
        message = f'已从本次搜索中排除 {len(rows)} 项，当前保留 {self.table.topLevelItemCount()} 项。'
        if self.searching:
            self._notice = (monotonic() + 4.0, message)
        elif self.record:
            self.status.setText(self._format_final_status())
        else:
            self.status.setText(message)

    def bookmark(self):
        items = self._target_items()
        meta = self.record or self._active
        if not items or not meta or not self.ready():
            return
        record, name = self.record, self.name or '实时搜索中'
        selected = []
        for item in items:
            index = item.data(0, Qt.ItemDataRole.UserRole)
            hit = self.hits[index]
            source_note = (record['hits'][index]['source_note']
                           if record and index < len(record['hits']) else deleted_source_note(hit[0]))
            selected.append((hit, source_note))

        def save():
            for (entry, pos, before, after), source_note in selected:
                self.case.log('FILE_NOTE', entry['path'], '成功', offset=entry['offset'], inode=entry['inode'],
                              deleted=entry['deleted'], image_sha256=meta['image_sha256'],
                              source_verification=meta['verification'],
                              note=f"内容命中：{meta['query']}；{meta['encoding']}；文件内字节偏移 {pos}",
                              file_byte=pos, needle=meta['needle'], before=before, after=after, search_record=name,
                              source_note=source_note, reallocated=entry.get('reallocated', False))

        def done(_):
            message = f'已保存 {len(selected)} 条命中，可在“取证发现”中查看。'
            if self.searching:
                self._notice = (monotonic() + 4.0, message)
            else:
                self.status.setText(message)

        self.context.task('保存命中记录', save, done)

    def source(self):
        if not self.ready():
            return
        values = edit_evidence_source(self, SOURCE_FIELDS, self.case.data['evidence'].get('provenance'))
        if values is not None:
            self.context.task('登记来源', lambda: self.case.register_source(values),
                              lambda _: self.status.setText(source_status(self.case.data['evidence'])))

    def bundle(self):
        export_bundle(self.context)


class BundleExportDialog(QDialog):
    """导出复核包前展示缺失材料清单（导出副本与搜索记录）并允许自由勾选要纳入的材料。"""

    def __init__(self, parent, rows, search_rows=()):
        super().__init__(parent)
        self.rows = list(rows)
        self.search_rows = list(search_rows)
        self.missing_rows = [row for row in self.rows if not row['exists']]
        self.available_rows = [row for row in self.rows if row['exists']]
        self.missing_searches = [row for row in self.search_rows if not row['exists']]
        self.available_searches = [row for row in self.search_rows if row['exists']]
        self._only_missing = False
        self._only_missing_searches = False
        self.setWindowTitle('导出复核包 · 选择纳入材料')
        self.resize(900, 620)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        body = QWidget(self)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(DIALOG_MARGIN, 16, DIALOG_MARGIN, 14)
        layout.setSpacing(12)

        banner = QFrame(body)
        banner.setObjectName('bundleExportBanner')
        banner_layout = QVBoxLayout(banner)
        banner_layout.setContentsMargins(14, 10, 14, 10)
        banner_layout.setSpacing(8)

        banner_row = QHBoxLayout()
        banner_row.setContentsMargins(0, 0, 0, 0)
        banner_row.setSpacing(10)
        banner_icon = QLabel(banner)
        banner_icon.setFixedSize(18, 18)
        self.banner_label = QLabel(banner)
        self.banner_label.setWordWrap(True)
        has_missing = bool(self.missing_rows or self.missing_searches)
        if has_missing:
            banner.setProperty('bannerState', 'warning')
            banner_icon.setPixmap(ui_icon('warning', theme.WARN_FG, 18).pixmap(18, 18))
            self.banner_label.setFont(theme.ui_font(9.5, QFont.Weight.DemiBold))
            parts = []
            if self.missing_rows:
                parts.append(f'{len(self.missing_rows)} 条历史导出副本')
            if self.missing_searches:
                parts.append(f'{len(self.missing_searches)} 条历史内容搜索记录')
            self.banner_label.setText(
                f'检测到 {" 与 ".join(parts)} 在本地目录中缺失（可能已被手动清理或被安全软件隔离）。'
                '缺失项已标红且不可勾选；您可以自由勾选现存材料继续生成复核包，未纳入项会如实记入 manifest.json：'
            )
            banner_row.addWidget(banner_icon, 0, Qt.AlignmentFlag.AlignTop)
            banner_row.addWidget(self.banner_label, 1)
            banner_layout.addLayout(banner_row)
            self.missing_text = QPlainTextEdit(banner)
            self.missing_text.setReadOnly(True)
            self.missing_text.setProperty('surface', 'code')
            self.missing_text.setFont(theme.mono_font(9.0))
            self.missing_text.setPlainText(format_missing_exports(self.missing_rows, self.missing_searches))
            self.missing_text.setMaximumHeight(112)
            banner_layout.addWidget(self.missing_text)
        else:
            banner.setProperty('bannerState', 'ok')
            banner_icon.setPixmap(ui_icon('check_shield', theme.OK_FG, 18).pixmap(18, 18))
            self.banner_label.setText(
                f'全部历史导出副本（{len(self.available_rows)} 条）与内容搜索记录（{len(self.available_searches)} 条）均完整存在。'
                '默认全部勾选，您可自由取消不需要打入复核包的条目。'
            )
            banner_row.addWidget(banner_icon, 0, Qt.AlignmentFlag.AlignVCenter)
            banner_row.addWidget(self.banner_label, 1)
            banner_layout.addLayout(banner_row)
            self.missing_text = None
        theme.repolish(banner)
        layout.addWidget(banner)

        self.tabs = QTabWidget(body)

        # Tab 1: 导出副本
        exports_tab = QWidget()
        exports_layout = QVBoxLayout(exports_tab)
        exports_layout.setContentsMargins(10, 10, 10, 10)
        exports_layout.setSpacing(CONTROL_GAP)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(CONTROL_GAP)
        self.select_all_button = QPushButton('全选可用副本')
        self.select_all_button.setProperty('role', 'soft')
        self.select_all_button.clicked.connect(lambda: self._set_all_checked(self.table, True))
        self.select_none_button = QPushButton('全不选')
        self.select_none_button.clicked.connect(lambda: self._set_all_checked(self.table, False))
        toolbar.addWidget(self.select_all_button)
        toolbar.addWidget(self.select_none_button)

        self.toggle_missing_button = QPushButton(f'仅看缺失项 ({len(self.missing_rows)})')
        self.toggle_missing_button.clicked.connect(self._toggle_missing_filter)
        self.toggle_missing_button.setVisible(bool(self.missing_rows))
        toolbar.addWidget(self.toggle_missing_button)
        toolbar.addStretch(1)
        exports_layout.addLayout(toolbar)

        self.table = self._build_exports_table()
        exports_layout.addWidget(self.table, 1)
        self.tabs.addTab(exports_tab, self._tab_title('导出副本', len(self.available_rows), len(self.missing_rows)))

        # Tab 2: 内容搜索记录
        self.search_table = self._build_searches_table()
        self.select_all_searches_button = QPushButton('全选可用记录')
        self.select_all_searches_button.setProperty('role', 'soft')
        self.select_all_searches_button.clicked.connect(lambda: self._set_all_checked(self.search_table, True))
        self.select_none_searches_button = QPushButton('全不选')
        self.select_none_searches_button.clicked.connect(lambda: self._set_all_checked(self.search_table, False))
        self.toggle_missing_searches_button = QPushButton(f'仅看缺失项 ({len(self.missing_searches)})')
        self.toggle_missing_searches_button.clicked.connect(self._toggle_missing_search_filter)
        self.toggle_missing_searches_button.setVisible(bool(self.missing_searches))
        if self.search_rows:
            searches_tab = QWidget()
            searches_layout = QVBoxLayout(searches_tab)
            searches_layout.setContentsMargins(10, 10, 10, 10)
            searches_layout.setSpacing(CONTROL_GAP)
            s_toolbar = QHBoxLayout()
            s_toolbar.setSpacing(CONTROL_GAP)
            s_toolbar.addWidget(self.select_all_searches_button)
            s_toolbar.addWidget(self.select_none_searches_button)
            s_toolbar.addWidget(self.toggle_missing_searches_button)
            s_toolbar.addStretch(1)
            searches_layout.addLayout(s_toolbar)
            searches_layout.addWidget(self.search_table, 1)
            self.tabs.addTab(
                searches_tab,
                self._tab_title('内容搜索记录', len(self.available_searches), len(self.missing_searches)),
            )

        layout.addWidget(self.tabs, 1)
        outer.addWidget(body, 1)

        footer_bar = QFrame(self)
        footer_bar.setObjectName('dialogFooterBar')
        footer = QHBoxLayout(footer_bar)
        footer.setContentsMargins(DIALOG_MARGIN, 10, DIALOG_MARGIN, 10)
        footer.setSpacing(CONTROL_GAP)
        self.summary_label = QLabel(footer_bar)
        self.summary_label.setProperty('role', 'muted')
        footer.addWidget(self.summary_label, 1)
        self.copy_missing_button = QPushButton('复制缺失清单', footer_bar)
        self.copy_missing_button.setIcon(ui_icon('copy', theme.TEXT_SECONDARY, 14))
        self.copy_missing_button.setAutoDefault(False)
        self.copy_missing_button.clicked.connect(self._copy_missing)
        self.copy_missing_button.setVisible(has_missing)
        footer.addWidget(self.copy_missing_button)
        cancel_btn = QPushButton('取消', footer_bar)
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)
        self.confirm_button = QPushButton('生成复核包', footer_bar)
        self.confirm_button.setProperty('role', 'accent')
        self.confirm_button.setDefault(True)
        self.confirm_button.clicked.connect(self.accept)
        footer.addWidget(cancel_btn)
        footer.addWidget(self.confirm_button)
        outer.addWidget(footer_bar)
        self._update_summary()

    @staticmethod
    def _tab_title(name, available, missing):
        return f'{name}（可用 {available} · 缺失 {missing}）' if missing else f'{name}（{available}）'

    def _style_material_item(self, item, row, status_col, tip_col):
        item.setData(0, Qt.ItemDataRole.UserRole, row)
        item.setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
        item.setTextAlignment(status_col, Qt.AlignmentFlag.AlignCenter)
        if row['exists']:
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Checked)
        else:
            item.setFlags((item.flags() | Qt.ItemFlag.ItemIsUserCheckable) & ~Qt.ItemFlag.ItemIsEnabled)
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setToolTip(status_col, row['missing_reason'])
            item.setToolTip(tip_col, row['missing_reason'])

    def _build_exports_table(self):
        table = QTreeWidget()
        table.setRootIsDecorated(False)
        table.setAlternatingRowColors(True)
        table.setUniformRowHeights(True)
        table.setHeaderLabels(['', '序号', '副本状态', '本地副本路径', '镜像内路径', '字节数', '导出时间（UTC+8）'])
        table.headerItem().setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
        table.headerItem().setTextAlignment(2, Qt.AlignmentFlag.AlignCenter)
        table.setItemDelegate(
            ForensicItemDelegate(
                table,
                pill_columns={2},
                mono_columns={1, 3, 5, 6},
                subtle_columns={6},
                accent_column=0,
                row_height=ROW_HEIGHT_TABLE,
            )
        )
        for row in self.rows:
            item = QTreeWidgetItem([
                '',
                str(row['index']),
                '正常' if row['exists'] else '缺失',
                row['display_path'],
                row['source'],
                f'{row["size"]:,}',
                display_time(row['time'], compact=True) if row['time'] else '未记录',
            ])
            item.setTextAlignment(5, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._style_material_item(item, row, 2, 3)
            table.addTopLevelItem(item)
        header = table.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(0, 38)
        table.setColumnWidth(1, 52)
        table.setColumnWidth(2, 82)
        table.setColumnWidth(3, 210)
        table.setColumnWidth(5, 108)
        table.setColumnWidth(6, 168)
        table.itemChanged.connect(lambda *_: self._update_summary())
        return table

    def _build_searches_table(self):
        table = QTreeWidget()
        table.setRootIsDecorated(False)
        table.setAlternatingRowColors(True)
        table.setUniformRowHeights(True)
        table.setHeaderLabels(['', '序号', '文件状态', '本地记录路径', '搜索内容', '编码', '命中数', '搜索时间（UTC+8）'])
        table.headerItem().setTextAlignment(1, Qt.AlignmentFlag.AlignCenter)
        table.headerItem().setTextAlignment(2, Qt.AlignmentFlag.AlignCenter)
        table.setItemDelegate(
            ForensicItemDelegate(
                table,
                pill_columns={2},
                mono_columns={1, 3, 5, 6, 7},
                subtle_columns={7},
                accent_column=0,
                row_height=ROW_HEIGHT_TABLE,
            )
        )
        for row in self.search_rows:
            item = QTreeWidgetItem([
                '',
                str(row['index']),
                '正常' if row['exists'] else '缺失',
                row['display_path'],
                str(row['query']),
                str(row['encoding']),
                str(row['hits']),
                display_time(row['time'], compact=True) if row['time'] else '未记录',
            ])
            item.setTextAlignment(6, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._style_material_item(item, row, 2, 3)
            table.addTopLevelItem(item)
        header = table.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(0, 38)
        table.setColumnWidth(1, 50)
        table.setColumnWidth(2, 80)
        table.setColumnWidth(3, 200)
        table.setColumnWidth(5, 72)
        table.setColumnWidth(6, 58)
        table.setColumnWidth(7, 162)
        table.itemChanged.connect(lambda *_: self._update_summary())
        return table

    def _set_all_checked(self, table, checked):
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        table.blockSignals(True)
        try:
            for i in range(table.topLevelItemCount()):
                item = table.topLevelItem(i)
                row = item.data(0, Qt.ItemDataRole.UserRole)
                if row['exists']:
                    item.setCheckState(0, state)
        finally:
            table.blockSignals(False)
        self._update_summary()

    def _toggle_missing_filter(self):
        self._only_missing = not self._only_missing
        for i in range(self.table.topLevelItemCount()):
            item = self.table.topLevelItem(i)
            row = item.data(0, Qt.ItemDataRole.UserRole)
            item.setHidden(self._only_missing and row['exists'])
        self.toggle_missing_button.setText('显示全部' if self._only_missing else f'仅看缺失项 ({len(self.missing_rows)})')

    def _toggle_missing_search_filter(self):
        self._only_missing_searches = not self._only_missing_searches
        for i in range(self.search_table.topLevelItemCount()):
            item = self.search_table.topLevelItem(i)
            row = item.data(0, Qt.ItemDataRole.UserRole)
            item.setHidden(self._only_missing_searches and row['exists'])
        self.toggle_missing_searches_button.setText(
            '显示全部' if self._only_missing_searches else f'仅看缺失项 ({len(self.missing_searches)})'
        )

    def _copy_missing(self):
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(format_missing_exports(self.missing_rows, self.missing_searches))
        self.summary_label.setText('已复制缺失材料清单到剪贴板')

    @staticmethod
    def _checked_indices(table):
        chosen = []
        for i in range(table.topLevelItemCount()):
            item = table.topLevelItem(i)
            row = item.data(0, Qt.ItemDataRole.UserRole)
            if row['exists'] and item.checkState(0) == Qt.CheckState.Checked:
                chosen.append(row['index'])
        return chosen

    def selected_indices(self):
        return self._checked_indices(self.table)

    def selected_search_indices(self):
        return self._checked_indices(self.search_table)

    def _update_summary(self):
        parts = [f'导出副本 {len(self.selected_indices())}/{len(self.available_rows)}']
        if self.missing_rows:
            parts[-1] += f'（缺失 {len(self.missing_rows)}）'
        if self.search_rows:
            s_text = f'搜索记录 {len(self.selected_search_indices())}/{len(self.available_searches)}'
            if self.missing_searches:
                s_text += f'（缺失 {len(self.missing_searches)}）'
            parts.append(s_text)
        self.summary_label.setText('已选：' + '  ·  '.join(parts))


def export_bundle(context):
    if not context.available():
        return
    case = context.case()
    if not case.data['evidence']:
        QMessageBox.information(context.root, '提示', '请先加载镜像。')
        return
    try:
        rows = inspect_bundle_exports(case)
        search_rows = inspect_bundle_searches(case)
    except Exception as error:
        QMessageBox.critical(context.root, '检查复核包材料失败', str(error))
        return
    selected_indices = None
    selected_search_indices = None
    if rows or search_rows:
        dialog = BundleExportDialog(context.root, rows, search_rows)
        try:
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            selected_indices = dialog.selected_indices()
            selected_search_indices = dialog.selected_search_indices()
        finally:
            dialog.deleteLater()
    context.task(
        '校验并生成复核包',
        lambda: build_bundle(
            case,
            selected_indices=selected_indices,
            selected_search_indices=selected_search_indices,
        ),
        lambda path: ExportResultDialog(context.root, path, '复核包已生成').exec(),
    )


FEATURE = Feature('review', requires=('evidence', 'files'), actions=(
    Action('export_bundle', export_bundle, '导出复核包', 'header'),
), panels=(
    Panel('review', '内容搜索与复核', lambda ctx: ctx, lambda ctx: id(ctx.case()), ReviewPanel),))
