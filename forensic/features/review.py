"""搜索、来源登记与复核材料入口。"""
import queue
from time import monotonic

from PySide6.QtCore import QPointF, QRect, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..core.content_search import SearchControl, pattern, search
from ..core.coverage import SOURCE_FIELDS, source_status
from ..core.preview import PAGE_BYTES
from ..core.review import build_bundle
from ..core.tasks import TaskRunner
from ..engines.tsk import deleted_source_note
from ..ui.preview import FilePreview
from ..ui.views import ExportResultDialog
from .api import Feature, Panel


class CheckableHeader(QHeaderView):
    """在首列表头绘制与浅色绿色主题一致的三态全选复选框。"""

    toggled = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(Qt.Orientation.Horizontal, parent)
        self.setObjectName('recordHeader')
        self.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.setSectionsClickable(True)
        self.setMouseTracking(True)
        self._check_state = Qt.CheckState.Unchecked
        self._hovered = False

    def check_state(self):
        return self._check_state

    def set_check_state(self, state):
        if self._check_state != state:
            self._check_state = state
            self.viewport().update()

    @staticmethod
    def _checkbox_rect(rect):
        size = 17
        # QTreeView::indicator 为 15px 内容 + 1px 边框（总 17px），左起点与行复选框对齐。
        x = rect.left() + 8
        y = rect.top() + (rect.height() - size) // 2
        return QRect(x, y, size, size)

    def paintSection(self, painter, rect, logicalIndex):
        super().paintSection(painter, rect, logicalIndex)
        if logicalIndex != 0:
            return
        box = QRectF(self._checkbox_rect(rect)).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        checked = self._check_state != Qt.CheckState.Unchecked
        fill = QColor('#087f6b') if checked else QColor('#ffffff')
        border = QColor('#087f6b') if (checked or self._hovered) else QColor('#b8c7bf')
        painter.setPen(QPen(border, 1.0))
        painter.setBrush(fill)
        painter.drawRoundedRect(box, 4.0, 4.0)
        if self._check_state == Qt.CheckState.Checked:
            path = QPainterPath()
            path.moveTo(box.left() + box.width() * 0.22, box.top() + box.height() * 0.52)
            path.lineTo(box.left() + box.width() * 0.42, box.top() + box.height() * 0.72)
            path.lineTo(box.left() + box.width() * 0.78, box.top() + box.height() * 0.30)
            pen = QPen(QColor('#ffffff'), 1.8, Qt.PenStyle.SolidLine,
                       Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)
        elif self._check_state == Qt.CheckState.PartiallyChecked:
            y = box.center().y()
            pen = QPen(QColor('#ffffff'), 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)
            painter.drawLine(QPointF(box.left() + 3.5, y), QPointF(box.right() - 3.5, y))
        painter.restore()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.logicalIndexAt(event.position().toPoint()) == 0:
            self.toggled.emit(self._check_state != Qt.CheckState.Checked)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        hovered = self.logicalIndexAt(event.position().toPoint()) == 0
        if hovered != self._hovered:
            self._hovered = hovered
            self.viewport().update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        if self._hovered:
            self._hovered = False
            self.viewport().update()
        super().leaveEvent(event)


class ReviewPanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.case = self.control = self.record = self.name = self._active = None
        self.hits = []
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
        buttons = {}
        for key, title, callback in [('search', '搜索', self.start), ('cancel', '取消搜索', self.cancel),
                                     ('source', '登记证据来源', self.source), ('bundle', '导出复核包', self.bundle)]:
            button = QPushButton(title)
            button.clicked.connect(callback)
            tools.addWidget(button)
            buttons[key] = button
        self.search_button = buttons['search']
        self.cancel_button = buttons['cancel']
        self.cancel_button.setEnabled(False)
        layout.addLayout(tools)
        self.query.returnPressed.connect(self.start)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.table = QTreeWidget()
        self.table.setRootIsDecorated(False)
        self.header = CheckableHeader(self.table)
        self.table.setHeader(self.header)
        self.table.setHeaderLabels(['', '序号', '文件内字节偏移', '分区偏移', 'inode', '镜像内路径', '前文 HEX', '后文 HEX'])
        self.table.headerItem().setToolTip(0, '全选 / 取消全选')
        self.header.toggled.connect(self._set_all_checked)
        for column, width in ((0, 38), (1, 64), (5, 320)):
            self.table.setColumnWidth(column, width)
        self.table.itemDoubleClicked.connect(self.preview)
        self.table.itemChanged.connect(self._sync_check_state)
        layout.addWidget(self.table, 1)
        self.save_button = QPushButton('将所选命中保存为取证发现')
        self.save_button.clicked.connect(self.bookmark)
        layout.addWidget(self.save_button)

    @property
    def searching(self):
        return self.search_runner.busy

    def shutdown(self):
        self._poll_timer.stop()
        self.cancel()

    def _sync_check_state(self, *_):
        total = self.table.topLevelItemCount()
        checked = len(self.checked_items())
        if not total or not checked:
            self.header.set_check_state(Qt.CheckState.Unchecked)
        elif checked == total:
            self.header.set_check_state(Qt.CheckState.Checked)
        else:
            self.header.set_check_state(Qt.CheckState.PartiallyChecked)
        self.save_button.setText(f'将勾选的 {checked} 条命中保存为取证发现' if checked else '将所选命中保存为取证发现')

    def set_text(self, context):
        self.context = context
        case = context.case()
        if self.case is not case or not self.status.text():
            if self.case is not case:
                self.shutdown()
            self.table.clear()
            self.hits = []
            self.record = self.name = self._active = None
            self._sync_check_state()
            self.status.setText('搜索当前清单中的普通文件及删除记录，不含未分配空间。双击命中定位原始字节。')
        self.case = case

    def ready(self):
        if not self.context.available():
            return False
        if not self.case.data['evidence']:
            QMessageBox.information(self, '提示', '请先加载镜像。')
            return False
        return True

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
        self.table.clear()
        self.hits = []
        self._sync_check_state()
        self._active = dict(
            query=query, encoding=encoding, needle=needle.hex(),
            image_sha256=case.data['evidence']['sha256'],
            verification=case.source_note() or '搜索进行中（实时命中）',
        )
        self.search_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status.setText('正在后台搜索 · 命中将实时显示，可直接勾选、双击预览或保存为取证发现。')

        def on_progress(stage, done, total):
            self._progress = (stage, done, total)

        def on_hit(batch):
            self._hit_queue.put(batch)

        def work():
            try:
                return search(case, query, encoding, control, on_progress, selected=selected, on_hit=on_hit)
            except Exception as error:
                return str(error)

        self.search_runner.submit(work, self.finished)
        self._poll_timer.start()

    def cancel(self):
        if self.control:
            self.control.cancel()

    def _append_hits(self, batch):
        if not batch:
            return
        base = len(self.hits)
        self.hits.extend(batch)
        items = []
        for offset, (entry, pos, before, after) in enumerate(batch):
            index = base + offset
            item = QTreeWidgetItem(['', str(index + 1), str(pos), str(entry['offset']), str(entry['inode']),
                                    entry['path'], before, after])
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setData(0, Qt.ItemDataRole.UserRole, index)
            items.append(item)
        self.table.blockSignals(True)
        try:
            self.table.addTopLevelItems(items)
        finally:
            self.table.blockSignals(False)
        self._sync_check_state()

    def _drain_hits(self):
        batch = []
        while True:
            try:
                batch.extend(self._hit_queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self._append_hits(batch)

    def _poll_search(self):
        self._drain_hits()
        result = self.search_runner.poll()
        if result is None:
            progress = self._progress
            if progress:
                stage, done, total = progress
                if total:
                    percent = 100 * done // total
                    text = f'正在{stage} · {percent}%（{done:,}/{total:,}） · 已命中 {len(self.hits)} 条 · 可随时勾选、双击预览或保存为取证发现'
                else:
                    text = f'正在{stage}… · 已命中 {len(self.hits)} 条'
            else:
                text = f'正在后台搜索… · 已命中 {len(self.hits)} 条'
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

    def finished(self, result):
        self.control = None
        self.search_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
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
            self.table.clear()
            self.hits = []
            self._sync_check_state()
        elif len(final_hits) > len(self.hits):
            self._append_hits(final_hits[len(self.hits):])
        self.status.setText(f"{self.record['status']} · 已处理 {self.record['visited']}/{self.record['eligible']} 项 · "
                            f"命中 {len(self.hits)} 条 · 读取失败 {len(self.record['errors'])} 项。{self.record['verification']}。清单及失败明细：reports/{self.name}")
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
                if item.checkState(0) == Qt.CheckState.Checked]

    def _set_all_checked(self, checked):
        count = self.table.topLevelItemCount()
        if not count:
            self.header.set_check_state(Qt.CheckState.Unchecked)
            return
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self.table.blockSignals(True)
        try:
            for row in range(count):
                self.table.topLevelItem(row).setCheckState(0, state)
        finally:
            self.table.blockSignals(False)
        self._sync_check_state()

    def toggle_all(self, column=0):
        if column != 0 or not self.table.topLevelItemCount():
            return
        self._set_all_checked(self.header.check_state() != Qt.CheckState.Checked)

    def bookmark(self):
        items = self.checked_items() or ([self.table.currentItem()] if self.table.currentItem() else [])
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
        form = QFormLayout(dialog)
        fields = {}
        for key, label in SOURCE_FIELDS.items():
            fields[key] = QLineEdit(self.case.data['evidence'].get('provenance', {}).get(key, ''))
            form.addRow(label, fields[key])
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        form.addRow(buttons)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
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
