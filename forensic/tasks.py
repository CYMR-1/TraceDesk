"""后台任务只处理数据；界面线程负责取回结果与更新控件。"""
import queue
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass(frozen=True)
class TaskResult:
    value: Any = None
    callback: Optional[Callable] = None
    error: Optional[Exception] = None


class TaskRunner:
    """同一时刻运行一个任务，不从工作线程调用任何 Tk API。"""

    def __init__(self):
        self.results = queue.Queue()
        self.busy = False

    def submit(self, work, callback=None):
        if self.busy:
            raise RuntimeError('请等待当前任务完成。')
        self.busy = True
        try:
            threading.Thread(target=self._run, args=(work, callback), daemon=True).start()
        except Exception:
            self.busy = False
            raise

    def _run(self, work, callback):
        try:
            result = TaskResult(value=work(), callback=callback)
        except Exception as error:
            result = TaskResult(error=error)
        self.results.put(result)

    def poll(self):
        try:
            result = self.results.get_nowait()
        except queue.Empty:
            return None
        self.busy = False
        return result
