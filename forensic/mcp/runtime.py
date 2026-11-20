"""本地 Streamable HTTP MCP 服务生命周期管理与客户端配置生成（不依赖 Qt）。"""
import asyncio
import json
from pathlib import Path
import socket
import sys
import threading
from time import monotonic
from typing import Any

import uvicorn

from ..paths import CASES_DIR, ROOT
from .server import DEFAULT_HOST, DEFAULT_HTTP_PATH, DEFAULT_PORT, create_server


LOOPBACK_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1'})


def validate_loopback_host(host: str) -> str:
    value = (host or DEFAULT_HOST).strip()
    if value not in LOOPBACK_HOSTS:
        raise ValueError('出于证据保护边界限制，本地 HTTP MCP 服务仅允许监听本机回环地址（127.0.0.1 / localhost）。')
    return value


def python_executable() -> str:
    venv_python = ROOT / '.venv' / 'Scripts' / 'python.exe'
    if venv_python.is_file():
        return str(venv_python.resolve())
    return str(Path(sys.executable).resolve())


def entrypoint_script() -> str:
    return str((ROOT / 'mcp_server.py').resolve())


def build_stdio_config(*, cases_root: Path | str | None = None) -> dict[str, Any]:
    args = [entrypoint_script()]
    if cases_root and Path(cases_root).resolve() != CASES_DIR.resolve():
        args.extend(['--cases-dir', str(Path(cases_root).resolve())])
    return {
        'mcpServers': {
            'tracedesk': {
                'command': python_executable(),
                'args': args,
            }
        }
    }


def build_http_config(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    path: str = DEFAULT_HTTP_PATH,
) -> dict[str, Any]:
    clean_path = '/' + path.strip('/')
    return {
        'mcpServers': {
            'tracedesk': {
                'url': f'http://{host}:{port}{clean_path}',
            }
        }
    }


def build_cli_command(
    *,
    transport: str = 'stdio',
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    path: str = DEFAULT_HTTP_PATH,
) -> str:
    py = python_executable()
    script = entrypoint_script()
    if transport == 'streamable-http':
        clean_path = '/' + path.strip('/')
        return f'& "{py}" "{script}" --transport streamable-http --host {host} --port {port} --path {clean_path}'
    return f'& "{py}" "{script}"'


def format_config_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


class LocalHttpMcpManager:
    """在后台线程托管本地 127.0.0.1 Streamable HTTP MCP 服务，供桌面端与测试启停。"""

    def __init__(self, *, cases_root: Path | str | None = None, default_actor: str | None = None):
        self.cases_root = Path(cases_root).resolve() if cases_root else CASES_DIR.resolve()
        self.default_actor = default_actor
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._server: uvicorn.Server | None = None
        self._host = DEFAULT_HOST
        self._port = DEFAULT_PORT
        self._path = DEFAULT_HTTP_PATH
        self._error: Exception | None = None

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive() and self._server and self._server.started)

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def path(self) -> str:
        return self._path

    @property
    def url(self) -> str:
        clean_path = '/' + self._path.strip('/')
        return f'http://{self._host}:{self._port}{clean_path}'

    @staticmethod
    def _check_port_available(host: str, port: int) -> None:
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, port))
            except OSError as error:
                raise OSError(f'端口 {host}:{port} 已被占用或无法监听，请更换端口后重试。') from error

    def start(
        self,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        path: str = DEFAULT_HTTP_PATH,
        timeout: float = 5.0,
    ) -> str:
        with self._lock:
            if self.running:
                return self.url
            host = validate_loopback_host(host)
            if not (1 <= int(port) <= 65535):
                raise ValueError('端口号必须在 1 到 65535 之间。')
            clean_path = '/' + path.strip('/')
            self._check_port_available(host, int(port))

            mcp = create_server(
                cases_root=self.cases_root,
                default_actor=self.default_actor,
                host=host,
                port=int(port),
                streamable_http_path=clean_path,
            )
            app = mcp.streamable_http_app()
            config = uvicorn.Config(
                app,
                host=host,
                port=int(port),
                log_level='warning',
                access_log=False,
            )
            server = uvicorn.Server(config)
            server.install_signal_handlers = lambda: None

            self._host = host
            self._port = int(port)
            self._path = clean_path
            self._server = server
            self._error = None

            def run() -> None:
                try:
                    asyncio.run(server.serve())
                except BaseException as exc:  # pragma: no cover - 启动失败分支
                    self._error = exc if isinstance(exc, Exception) else RuntimeError(str(exc))

            thread = threading.Thread(target=run, name='tracedesk-mcp-http', daemon=True)
            self._thread = thread
            thread.start()

        deadline = monotonic() + timeout
        while monotonic() < deadline:
            if self._error is not None:
                self.stop()
                raise RuntimeError(f'启动本地 MCP HTTP 服务失败：{self._error}') from self._error
            if server.started:
                return self.url
            if not thread.is_alive():
                self.stop()
                raise RuntimeError('本地 MCP HTTP 服务提前退出，请检查端口占用或依赖状态。')
            threading.Event().wait(0.05)

        self.stop()
        raise TimeoutError(f'启动本地 MCP HTTP 服务超时（{timeout} 秒）。')

    def stop(self, *, timeout: float = 5.0) -> None:
        with self._lock:
            server = self._server
            thread = self._thread
            self._server = None
            self._thread = None
        if server is not None:
            server.should_exit = True
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
