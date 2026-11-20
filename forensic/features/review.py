"""搜索、来源登记与复核材料入口。"""
import collections
import queue
from time import monotonic

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
                               QLabel, QLineEdit, QMessageBox, QPushButton,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core.content_search import SearchControl, pattern, search
from ..core.coverage import SOURCE_FIELDS, source_status
from ..core.preview import PAGE_BYTES
from ..core.review import build_bundle
from ..core.tasks import TaskRunner
from ..engines.tsk import deleted_source_note
from ..ui.filter_header import FilterHeaderView
from ..ui.preview import FilePreview
from ..ui.views import ExportResultDialog
from .api import Feature, Panel

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
        tools = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText('输入文字或十六进制字节；搜索文件内容')
        self.encoding = QComboBox()
        self.encoding.addItems(['UTF-8', 'UTF-16LE', 'GBK', 'HEX'])
        self.scope = QComboBox()
        self.scope.addItems(['全部文件', '文件浏览中选中的文件'])
        tools.addWidget(self.query, 1)
        tools.addWidget(self.encoding)
        tools.addWidget(self.scope)
        self.search_button = QPushButton('搜索')
        self.search_button.clicked.connect(self.toggle_search)
        tools.addWidget(self.search_button)
        for title, callback in [('登记证据来源', self.source), ('导出复核包', self.bundle)]:
            button = QPushButton(title)
            button.clicked.connect(callback)
            tools.addWidget(button)
        layout.addLayout(tools)
        self.query.returnPressed.connect(self.start)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.table = QTreeWidget()
        self.table.setRootIsDecorated(False)
        self.table.setUniformRowHeights(True)
        self.header = FilterHeaderView(self.table, checkable_column=0, check_label='全选', filter_columns=(3,))
        self.table.setHeader(self.header)
        self.table.setHeaderLabels(['', '序号', '文件内字节偏移', '分区偏移', 'inode', '镜像内路径', '前文 HEX', '后文 HEX'])
        self.table.headerItem().setToolTip(0, '全选 / 取消全选')
        self.table.headerItem().setToolTip(3, '单击下拉筛选分区偏移')
        self.header.toggled.connect(self._set_all_checked)
        self.header.filter_changed.connect(self._apply_offset_filter)
        for column, width in ((0, 68), (1, 64), (3, 110), (5, 320)):
            self.table.setColumnWidth(column, width)
        self.table.itemDoubleClicked.connect(self.preview)
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table, 1)

        actions = QHBoxLayout()
        self.exclude_button = QPushButton('在本次搜索中排除所选项')
        self.exclude_button.clicked.connect(self.exclude_selected)
        self.save_button = QPushButton('将所选命中保存为取证发现')
        self.save_button.clicked.connect(self.bookmark)
        actions.addWidget(self.exclude_button, 1)
        actions.addWidget(self.save_button, 2)
        layout.addLayout(actions)

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
        self.save_button.setText(f'将勾选的 {checked} 条命中保存为取证发现' if checked else '将所选命中保存为取证发现')
        self.exclude_button.setText(f'在本次搜索中排除勾选的 {checked} 项' if checked else '在本次搜索中排除所选项')

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
                self.search_button.setText('搜索')
                self.search_button.setEnabled(True)
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
        self.search_button.setText('取消搜索')
        self.search_button.setEnabled(True)
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
                self.search_button.setText('正在取消…')
                self.search_button.setEnabled(False)

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
        self.search_button.setText('搜索')
        self.search_button.setEnabled(True)
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
        layout.addWidget(QLabel(f"文件内偏移 {pos}（0x{pos:X}） · {meta['encoding']} · {meta['needle'][:96]}"))
        view = FilePreview(dialog)
        layout.addWidget(view)
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
        dialog = QDialog(self)
        dialog.setWindowTitle('登记证据来源')
        dialog.setMinimumWidth(580)
        form = QFormLayout(dialog)
        form.setContentsMargins(16, 14, 16, 14)
        form.setSpacing(10)
        fields = {}
        for key, label in SOURCE_FIELDS.items():
            fields[key] = QLineEdit(self.case.data['evidence'].get('provenance', {}).get(key, ''))
            form.addRow(label, fields[key])
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        form.addRow(buttons)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        dialog.resize(600, 270)
        if dialog.exec():
            values = {k: field.text() for k, field in fields.items()}
            self.context.task('登记来源', lambda: self.case.register_source(values),
                              lambda _: self.status.setText(source_status(self.case.data['evidence'])))
        dialog.deleteLater()

    def bundle(self):
        if self.ready():
            self.context.task('校验并生成复核包', lambda: build_bundle(self.case),
                              lambda path: ExportResultDialog(self, path, '复核包已生成').exec())


FEATURE = Feature('review', requires=('evidence', 'files'), panels=(
    Panel('review', '内容搜索与复核', lambda ctx: ctx, lambda ctx: id(ctx.case()), ReviewPanel),))
