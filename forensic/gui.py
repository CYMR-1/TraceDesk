"""应用控制器：协调案件模型、工作台视图和后台任务。"""
import sys
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QTimer, Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QMessageBox

from .appearance import DesktopAppearance
from .core import Case, deleted_export_summary, display_time
from .tasks import TaskRunner
from .tsk import ROOT, can_export, entry_status
from .views import NewCaseDialog
from .workspace import WorkbenchView


class App(QObject):
    """保留原有操作接口，将布局、任务执行与案件逻辑委托给独立对象。"""

    def __init__(self, root):
        super().__init__(root)
        self.root, self.case = root, None
        self.runner = TaskRunner()
        self._closed = False
        self.appearance = DesktopAppearance(root)
        self.appearance.configure()
        commands = {name: getattr(self, name) for name in
                    ('new_case', 'open_case', 'load', 'verify', 'export', 'report', 'scan', 'filter', 'select')}
        self.view = WorkbenchView(root, self.appearance, commands)
        self.browser = self.view.browser
        # 控制器公开原生 Qt 控件，布局细节由视图管理。
        for name in ('partition', 'suffix', 'keyword', 'tree', 'preview', 'detail'):
            setattr(self, name, getattr(self.browser, name))
        for name in ('tabs', 'summary', 'status', 'progress'):
            setattr(self, name, getattr(self.view, name))
        self.files = self.browser
        for name, panel in self.view.panels.items():
            setattr(self, name, panel.text)
        self.set_text(self.help, HELP_TEXT)
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self.poll)
        self._timer.start()
        root.installEventFilter(self)

    @property
    def busy(self):
        return self.runner.busy

    @property
    def entries(self):
        return self.browser.entries

    @staticmethod
    def set_text(widget, value):
        widget.setPlainText(value)

    def available(self, case=True):
        if self.busy:
            QMessageBox.information(self.root, '正在处理', '请等待当前任务完成。')
            return False
        if case and not self.case:
            QMessageBox.information(self.root, '提示', '请先新建或打开案件。')
            return False
        return True

    def task(self, label, work, callback=None):
        if not self.available():
            return
        self.runner.submit(work, callback)
        self.status.setText(label + '…')
        self.view.set_busy(True)

    def poll(self):
        if self._closed:
            return
        try:
            self.preview.poll()
            result = self.runner.poll()
            if result is not None:
                self.view.set_busy(False)
                self.status.setText('操作失败' if result.error else '操作完成 · 应用层只读模式')
                if result.error:
                    QMessageBox.critical(self.root, '操作失败', str(result.error))
                elif result.callback:
                    result.callback(result.value)
                self.refresh()
        except Exception as error:
            self.status.setText('显示失败')
            QMessageBox.critical(self.root, '显示失败', str(error))

    def new_case(self):
        if self.available(False):
            NewCaseDialog(self.root, self.create_case).exec()

    def create_case(self, folder, number, examiner, target):
        case = Case.create(folder, number, examiner, target)
        if self.case:
            self.case.close()
        self.case = case
        self.refresh(reset=True)

    def display(self, entries):
        self.browser.display(entries)

    def open_case(self):
        if not self.available(False):
            return
        path, _ = QFileDialog.getOpenFileName(
            self.root, '打开案件 case.json', str(ROOT / 'cases'), '案件元数据 (case.json)',
            options=QFileDialog.Option.DontUseNativeDialog)
        if path:
            try:
                case = Case(Path(path).parent)
                case.log('CASE_OPEN', path, '成功')
                if self.case:
                    self.case.close()
                self.case = case
                self.refresh(reset=True)
            except Exception as error:
                QMessageBox.critical(self.root, '打开失败', str(error))

    def load(self):
        if self.available():
            path, _ = QFileDialog.getOpenFileName(
                self.root, '选择案件库之外的 RAW 镜像', str(ROOT / 'evidence'),
                'RAW 镜像 (*.dd *.raw *.img);;所有文件 (*)',
                options=QFileDialog.Option.DontUseNativeDialog)
            if path:
                self.task('固定镜像并识别分区', lambda: self.case.load(path), lambda _: self.refresh(reset=True))

    def scan(self):
        if self.available():
            index = self.partition.currentIndex()
            if index < 0:
                QMessageBox.information(self.root, '提示', '请先加载镜像并选择分区。')
                return
            offset = self.case.data['evidence']['partitions'][index]['offset']
            self.task('读取文件系统与文件树', lambda: self.case.scan(offset), self.display)

    def filter(self):
        if self.available():
            suffix, keyword = self.suffix.text(), self.keyword.text()
            self.task('筛选文件', lambda: self.case.filtered(suffix, keyword), self.display)

    def verify(self):
        if self.available():
            self.task('流式校验 SHA-256', self.case.verify, lambda ok: QMessageBox.information(
                self.root, '完整性校验', '通过：与初始固定值一致。' if ok else '失败：原始镜像已发生变化！'))

    def selected_entry(self):
        selected = self.tree.selectedItems()
        return selected[0].data(0, Qt.ItemDataRole.UserRole) if selected else None

    def export(self):
        if not self.available():
            return
        entry = self.selected_entry()
        if not entry or not can_export(entry):
            QMessageBox.information(self.root, '导出文件', '请选择一个现存或已删除的文件。')
            return

        def done(path):
            record = next(r for r in reversed(self.case.data['exports']) if r['path'] == str(path))
            message = '\n\n'.join(filter(None, (str(path), deleted_export_summary(record))))
            title = '部分导出' if record['size'] < entry['size'] else '导出成功'
            QMessageBox.information(self.root, title, message)

        self.task('校验并导出证据副本', lambda: self.case.export(entry), done)

    def report(self):
        if self.available():
            self.task('校验并生成 Markdown 报告', self.case.report, lambda path: QMessageBox.information(
                self.root, '报告已生成', str(path)))

    def select(self, event=None):
        selected = self.tree.selectedItems()
        entry = self.selected_entry()
        if entry is None:
            self.preview.clear('请选择目录中的文件' if selected else '请选择文件')
            if selected:
                self.detail.setText(selected[0].text(0))
            return
        self.detail.setText(f'{entry["path"]}  ·  {entry_status(entry)}  ·  inode {entry["inode"] or "—"}  ·  {entry["size"]} 字节  ·  分区偏移 {entry["offset"]}')
        if entry['directory'] or entry['mode'].startswith('V/'):
            self.preview.clear('请选择目录中的文件')
        else:
            self.preview.open_file(self.case.image(), entry)

    def refresh(self, reset=False):
        if not self.case:
            return
        data = self.case.data
        evidence = data['evidence']
        self.summary.setText(f'案件 {data["number"]}  ·  取证人员 {data["examiner"]}  ·  对象 {data["target"]}\n' + (f'SHA-256  {evidence["sha256"]}' if evidence else '尚未加载镜像'))
        values = [f'{p["offset"]} 扇区 · {p["description"]}' for p in evidence['partitions']] if evidence else []
        previous = self.partition.currentIndex()
        if values != [self.partition.itemText(i) for i in range(self.partition.count())]:
            self.partition.clear()
            self.partition.addItems(values)
            self.partition.setCurrentIndex(min(previous, len(values) - 1))
        if values and (reset or self.partition.currentIndex() < 0):
            self.partition.setCurrentIndex(next((i for i,p in enumerate(evidence['partitions']) if p['offset'] == data.get('offset')), 0))
        if reset:
            self.display(data['inventory'])
        info_key = (id(evidence), data.get('fsstat'))
        if reset or getattr(self, '_info_key', None) != info_key:
            self._info_key = info_key
            self.set_text(self.info, (f'原始镜像：{evidence["path"]}\n字节数：{evidence["size"]}\n固定时间：{display_time(evidence["fixed_at"])}\nSHA-256：{evidence["sha256"]}\n\n{evidence["layout"]}' if evidence else '尚未加载镜像') + '\n\n' + data.get('fsstat',''))
        records = self.case.check_audit()
        self.set_text(self.audit, f'审计哈希链验证通过 · {len(records)} 条记录\n\n' + '\n\n'.join(f'#{r["seq"]} {display_time(r["timestamp"])}  {r["actor"]}\n{r["action"]}  {r["subject"]}\n结果：{r["result"]}  哈希：{r["hash"]}' for r in records))
        # 显示时间线不调用会追加日志的接口，避免界面刷新产生重复审计。
        if getattr(self, '_timeline_inventory', None) is not data['inventory']:
            events = self.case.timeline_events()
            self.set_text(self.timeview, 'MAC/B 时间线 · 东八区（UTC+8）\n\n' + '\n'.join(
                f"{row['time']}  {row['event']}  {row['path']}  ·  {row['status']}  ·  inode {row['inode']}" for row in events))
            self._timeline_inventory = data['inventory']

    def close(self):
        return self.root.close()

    def eventFilter(self, watched, event):
        if watched is self.root and event.type() == QEvent.Type.Close:
            if self.busy:
                QMessageBox.information(self.root, '正在处理', '请等待当前取证任务完成后再退出。')
                event.ignore()
                return True
            self._shutdown()
        return super().eventFilter(watched, event)

    def _shutdown(self):
        if self._closed:
            return
        self._closed = True
        self._timer.stop()
        self.browser.cancel_display()
        self.preview.clear()
        if self.case:
            self.case.close()


HELP_TEXT = '''操作顺序

1. 新建案件：填写编号、取证人员、对象，选择案件库。
2. 加载 RAW 镜像：镜像必须放在案件库之外。自动流式计算 SHA-256 并读取分区。
3. 选择分区，读取文件树；支持后缀及路径关键词筛选。
4. 校验完整性；选择现存或已删除的文件导出。导出前后自动校验原镜像。
5. 查看审计日志、MAC 时间线，生成 Markdown 报告。

界面操作
拖动文件树和预览之间的分隔条可调整区域大小。
表格底部可横向滚动，查看全部时间列或十六进制内容。
双击“启动取证工作台.bat”启动；脚本使用本项目虚拟环境，保留终端窗口，运行失败时暂停。

说明
案件时间按东八区（UTC+8）显示；C 为元数据变更时间。
本工具仅承诺应用层只读，不替代硬件写保护。
本地审计哈希链可检测单独修改及截断，不能抵御全案重写。
每案固定一个证据镜像；支持标准 512 字节扇区 RAW 镜像，不支持 E01。
案件目录分离不等于不同物理磁盘，物理介质隔离由操作人员安排。

演示镜像：evidence/demo.dd（分区偏移 2048）与 evidence/demo_volume.dd（偏移 0）。
'''


def main(case=None):
    from .launcher import ErrorReporter

    qt_app = QApplication.instance() or QApplication(sys.argv)
    qt_app.setApplicationName('TraceDesk')
    root = QMainWindow()
    reporter = ErrorReporter()
    reporter.install(root)
    app = None
    try:
        app = App(root)
        if case is not None:
            app.case = case
            app.refresh(reset=True)
        root.show()
        return qt_app.exec()
    finally:
        if app is not None:
            app._shutdown()
        reporter.restore()
