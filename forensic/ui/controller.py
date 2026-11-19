"""应用装配与生命周期：功能实现位于 forensic.features。"""
import sys
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QTimer, Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox

from .appearance import DesktopAppearance
from .branding import set_window_icon, set_windows_app_id
from ..core.tasks import TaskRunner
from ..features.api import FeatureContext, FeatureRegistry
from ..features.catalog import load_features
from .workspace import WorkbenchView


class App(QObject):
    """持有案件、后台任务和窗口；保留现有脚本使用的公开操作接口。"""

    def __init__(self, root, *, features=None):
        super().__init__(root)
        self.root, self.case = root, None
        self.runner = TaskRunner()
        self._work_progress = None
        self._closed = False
        self.appearance = DesktopAppearance(root)
        self.appearance.configure()
        set_window_icon(root)
        context = FeatureContext(
            root=root, case=lambda: self.case, browser=lambda: self.browser,
            available=lambda *args: self.available(*args),
            task=lambda *args: self.task(*args),
            refresh=lambda **kwargs: self.refresh(**kwargs),
            replace_case=self._replace_case, selected_entry=lambda: self.selected_entry(),
            progress=self._report_progress,
        )
        self.features = FeatureRegistry(load_features() if features is None else features, context)
        self.view = WorkbenchView(root, self.appearance, self.features)
        self.browser = self.view.browser
        for name in ('suffix', 'keyword', 'tree', 'preview', 'detail'):
            setattr(self, name, getattr(self.browser, name))
        for name in ('tabs', 'summary', 'status', 'progress'):
            setattr(self, name, getattr(self.view, name))
        self.files = self.browser
        for name in ('info', 'audit', 'timeview', 'help'):
            if name in self.view.panels:
                setattr(self, name, self.view.panels[name].text)
        self.features.refresh_panels(self.view.panels, reset=True)
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

    def task(self, label, work, callback=None, requires_case=True):
        if not self.available(requires_case):
            return
        self._work_progress = None
        self.runner.submit(work, callback)
        self.status.setText(label + '…')
        self.view.set_busy(True)

    def _report_progress(self, stage, done, total):
        self._work_progress = stage, done, total

    def poll(self):
        if self._closed:
            return
        try:
            self.preview.poll()
            result = self.runner.poll()
            progress = self._work_progress
            if result is None and self.busy and progress:
                stage, done, total = progress
                percent = 100 * done // total if total else 0
                self.progress.setRange(0, 100 if total else 0)
                self.progress.setValue(percent)
                self.status.setText(f'{stage} · {percent}%' if total else stage + '…')
            if result is not None:
                self.view.set_busy(False)
                self.status.setText('操作失败' if result.error else '操作完成 · 应用层只读模式')
                if result.error:
                    QMessageBox.critical(self.root, '操作失败', str(result.error))
                elif result.callback:
                    result.callback(result.value)
                if not self.busy:
                    self.refresh()
        except Exception as error:
            self.status.setText('显示失败')
            QMessageBox.critical(self.root, '显示失败', str(error))

    def _replace_case(self, case):
        if self.case:
            self.case.close()
        self.case = case
        self.refresh(reset=True)
        self.features.case_changed()

    def display(self, entries):
        self.browser.display(entries)

    def new_case(self):
        return self.features.invoke('new_case')

    def open_case(self):
        return self.features.invoke('open_case')

    def load(self):
        return self.features.invoke('load')

    def scan(self):
        return self.features.invoke('scan')

    def resume_partitions(self):
        return self.features.invoke('resume_partitions')

    def filter(self):
        return self.features.invoke('filter')

    def verify(self):
        return self.features.invoke('verify')

    def export(self):
        return self.features.invoke('export')

    def report(self):
        return self.features.invoke('report')

    def create_case(self, folder, number, examiner, target):
        return self.features.invoke('create_case', folder, number, examiner, target)

    def select(self, event=None):
        return self.features.invoke('select', event)

    def selected_entry(self):
        selected = self.tree.selectedItems()
        return selected[0].data(0, Qt.ItemDataRole.UserRole) if selected else None

    def refresh(self, reset=False):
        if not self.case:
            return
        data = self.case.data
        evidence = data['evidence']
        self.summary.setText(f'案件 {data["number"]}  ·  取证人员 {data["examiner"]}  ·  对象 {data["target"]}\n' + (f'证据 {Path(evidence["path"]).name}  ·  已固定 SHA-256（完整摘要见“镜像与文件系统”）' if evidence else '尚未加载镜像'))
        self.summary.setToolTip(f'SHA-256：{evidence["sha256"]}' if evidence else '')
        self.browser.set_context(evidence, data.get('partition_scans', []), data.get('fsstat', ''))
        if reset:
            prepared = vars(self.case).pop('browser_index', None)
            if prepared:
                self.browser.display(data['inventory'], prepared)
            else:
                self.display(data['inventory'])
        self.features.refresh_panels(self.view.panels, reset=reset)

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


def main(case=None):
    from ..launcher import ErrorReporter

    set_windows_app_id()
    qt_app = QApplication.instance() or QApplication(sys.argv)
    qt_app.setApplicationName('TraceDesk')
    root = QMainWindow()
    reporter = ErrorReporter()
    reporter.install(root)
    app = None
    try:
        app = App(root)
        if case is not None:
            app._replace_case(case)
        root.show()
        return qt_app.exec()
    finally:
        if app is not None:
            app._shutdown()
        reporter.restore()
