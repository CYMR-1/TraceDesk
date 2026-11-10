"""验证后台任务的串行执行和界面线程交接。"""
import threading
import time
import unittest
from unittest.mock import patch

from forensic.tasks import TaskRunner


class TaskRunnerTests(unittest.TestCase):
    def result(self, runner):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = runner.poll()
            if result is not None:
                return result
            time.sleep(0.005)
        self.fail('后台任务未及时返回结果')

    def test_busy_task_rejects_second_submission(self):
        runner = TaskRunner()
        released = threading.Event()
        self.addCleanup(released.set)
        runner.submit(lambda: released.wait(3))
        self.assertTrue(runner.busy)
        self.assertIsNone(runner.poll())
        self.assertTrue(runner.busy)
        with self.assertRaises(RuntimeError):
            runner.submit(lambda: '不应执行')
        released.set()
        self.assertTrue(self.result(runner).value)
        self.assertFalse(runner.busy)

    def test_callback_runs_only_when_caller_consumes_result(self):
        runner = TaskRunner()
        caller = threading.get_ident()
        callback_threads = []
        worker_threads = []

        def work():
            worker_threads.append(threading.get_ident())
            return '已读取证据'

        def callback(value):
            callback_threads.append(threading.get_ident())
            self.assertEqual(value, '已读取证据')

        runner.submit(work, callback)
        result = self.result(runner)
        self.assertEqual(callback_threads, [])
        self.assertNotEqual(worker_threads, [caller])
        self.assertIsNone(result.error)
        result.callback(result.value)
        self.assertEqual(callback_threads, [caller])

    def test_task_error_is_returned_and_next_task_can_run(self):
        runner = TaskRunner()
        failure = OSError('镜像不可读取')

        def failed_work():
            raise failure

        runner.submit(failed_work)
        result = self.result(runner)
        self.assertIs(result.error, failure)
        self.assertIsNone(result.callback)
        self.assertFalse(runner.busy)
        runner.submit(lambda: 42)
        self.assertEqual(self.result(runner).value, 42)

    def test_none_value_is_a_completed_task(self):
        runner = TaskRunner()
        runner.submit(lambda: None)
        result = self.result(runner)
        self.assertIsNotNone(result)
        self.assertIsNone(result.value)
        self.assertIsNone(result.error)
        self.assertIsNone(runner.poll())
        self.assertFalse(runner.busy)

    def test_thread_start_failure_restores_idle_state(self):
        runner = TaskRunner()
        with patch('forensic.tasks.threading.Thread.start', side_effect=RuntimeError('无法创建线程')):
            with self.assertRaisesRegex(RuntimeError, '无法创建线程'):
                runner.submit(lambda: None)
        self.assertFalse(runner.busy)
        self.assertIsNone(runner.poll())


if __name__ == '__main__':
    unittest.main()
