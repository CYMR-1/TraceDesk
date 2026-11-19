"""搜索、来源登记与复核材料入口。"""
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
                               QLabel, QLineEdit, QMessageBox, QPushButton, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout, QWidget)
from ..core.content_search import SearchControl, pattern, search
from ..core.coverage import SOURCE_FIELDS, source_status
from ..core.preview import PAGE_BYTES
from ..core.review import build_bundle
from ..ui.preview import FilePreview
from ..ui.views import ExportResultDialog
from .api import Feature, Panel


class ReviewPanel(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.case = self.control = None
        self.hits = []
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
        for title, callback in [('搜索', self.start), ('取消搜索', self.cancel), ('登记证据来源', self.source),
                                ('导出复核包', self.bundle)]:
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
        self.table.header().setObjectName('recordHeader')
        self.table.setHeaderLabels(['文件内字节偏移', '分区偏移', 'inode', '镜像内路径', '前文 HEX', '后文 HEX'])
        self.table.setColumnWidth(3, 320)
        self.table.itemDoubleClicked.connect(self.preview)
        layout.addWidget(self.table, 1)
        save = QPushButton('将所选命中保存为取证发现')
        save.clicked.connect(self.bookmark)
        layout.addWidget(save)

    def set_text(self, context):
        self.context = context
        case = context.case()
        if self.case is not case or not self.status.text():
            self.table.clear()
            self.hits = []
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
        if not self.ready():
            return
        query, encoding = self.query.text(), self.encoding.currentText()
        try:
            pattern(query, encoding)
        except ValueError as error:
            QMessageBox.warning(self, '搜索条件无效', str(error))
            return
        case, control = self.case, SearchControl()
        selected = self.context.selected_entry() if self.scope.currentIndex() else None
        if self.scope.currentIndex() and selected is None:
            QMessageBox.information(self, '提示', '请先在文件浏览中选中一个文件。')
            return
        self.control = control
        self.table.clear()
        self.hits = []
        self.status.setText('正在后台搜索；进度见窗口底部。')
        def work():
            try:
                return search(case, query, encoding, control, self.context.progress, selected=selected)
            except Exception as error:
                return str(error)
        self.context.task('搜索文件内容', work, self.finished)

    def cancel(self):
        if self.control:
            self.control.cancel()

    def finished(self, result):
        self.control = None
        if isinstance(result, str):
            self.status.setText('搜索失败：' + result)
            return
        self.record, self.hits, self.name = result
        for index, (entry, pos, before, after) in enumerate(self.hits):
            item = QTreeWidgetItem(self.table, [str(pos), str(entry['offset']), str(entry['inode']), entry['path'], before, after])
            item.setData(0, Qt.ItemDataRole.UserRole, index)
        self.status.setText(f"{self.record['status']} · 已处理 {self.record['visited']}/{self.record['eligible']} 项 · "
                            f"命中 {len(self.hits)} 条 · 读取失败 {len(self.record['errors'])} 项。{self.record['verification']}。清单及失败明细：reports/{self.name}")

    def preview(self, item, column):
        if not self.ready():
            return
        entry, pos, _, _ = self.hits[item.data(0, Qt.ItemDataRole.UserRole)]
        dialog = QDialog(self)
        dialog.setWindowTitle(f"{entry['path']} · 命中字节 0x{pos:X}")
        dialog.resize(860, 550)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(f"文件内偏移 {pos}（0x{pos:X}） · {self.record['encoding']} · {self.record['needle'][:96]}"))
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

    def bookmark(self):
        item = self.table.currentItem()
        if item is None or not self.ready():
            return
        entry, pos, before, after = self.hits[item.data(0, Qt.ItemDataRole.UserRole)]
        reference = self.record['hits'][item.data(0, Qt.ItemDataRole.UserRole)]
        def save():
            self.case.log('FILE_NOTE', entry['path'], '成功', offset=entry['offset'], inode=entry['inode'],
                          deleted=entry['deleted'], image_sha256=self.record['image_sha256'],
                          source_verification=self.record['verification'],
                          note=f"内容命中：{self.record['query']}；{self.record['encoding']}；文件内字节偏移 {pos}",
                          file_byte=pos, needle=self.record['needle'], before=before, after=after, search_record=self.name,
                          source_note=reference['source_note'], reallocated=entry.get('reallocated', False))
        self.context.task('保存命中记录', save, lambda _: self.status.setText('已保存，可在“取证发现”中查看。'))

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
            values = {k:field.text() for k,field in fields.items()}
            self.context.task('登记来源', lambda: self.case.register_source(values),
                              lambda _: self.status.setText(source_status(self.case.data['evidence'])))
        dialog.deleteLater()

    def bundle(self):
        if self.ready():
            self.context.task('校验并生成复核包', lambda: build_bundle(self.case),
                              lambda path: ExportResultDialog(self, path, '复核包已生成').exec())


FEATURE = Feature('review', requires=('evidence','files'), panels=(
    Panel('review', '内容搜索与复核', lambda ctx: ctx, lambda ctx: id(ctx.case()), ReviewPanel),))
