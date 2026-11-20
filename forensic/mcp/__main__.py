"""命令行启动 TraceDesk MCP 服务端：支持 stdio（默认）和本地 Streamable HTTP。"""
import argparse
import os
from pathlib import Path
import sys
from typing import Sequence

from ..paths import CASES_DIR
from .runtime import DEFAULT_HOST, DEFAULT_HTTP_PATH, DEFAULT_PORT, validate_loopback_host
from .server import create_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='tracedesk-mcp',
        description='启动 TraceDesk 电子数据取证 MCP 服务端（支持 stdio 与本地 Streamable HTTP）。',
    )
    parser.add_argument(
        '--transport',
        choices=('stdio', 'streamable-http'),
        default='stdio',
        help='MCP 传输方式：stdio（默认，供本地桌面客户端拉起）或 streamable-http（本地 HTTP 服务）。',
    )
    parser.add_argument(
        '--host',
        default=DEFAULT_HOST,
        help=f'streamable-http 监听地址，仅允许本机回环（默认 {DEFAULT_HOST}）。',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=DEFAULT_PORT,
        help=f'streamable-http 监听端口（默认 {DEFAULT_PORT}）。',
    )
    parser.add_argument(
        '--path',
        default=DEFAULT_HTTP_PATH,
        help=f'streamable-http 挂载路径（默认 {DEFAULT_HTTP_PATH}）。',
    )
    parser.add_argument(
        '--cases-dir',
        default=os.environ.get('TRACEDESK_CASES_DIR', str(CASES_DIR)),
        help='默认案件库根目录（也可通过环境变量 TRACEDESK_CASES_DIR 指定）。',
    )
    parser.add_argument(
        '--actor',
        default=os.environ.get('TRACEDESK_MCP_ACTOR', ''),
        help='默认写入审计链的操作人员标识（省略时使用案件取证人员；审计来源固定标记为 MCP）。',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.transport == 'streamable-http':
        host = validate_loopback_host(args.host)
        if not (1 <= args.port <= 65535):
            parser.error('端口号必须在 1 到 65535 之间。')
    else:
        host = DEFAULT_HOST
    clean_path = '/' + args.path.strip('/')
    mcp = create_server(
        cases_root=Path(args.cases_dir),
        default_actor=args.actor or None,
        host=host,
        port=args.port,
        streamable_http_path=clean_path,
    )
    if args.transport == 'streamable-http':
        print(
            f'[TraceDesk MCP] Streamable HTTP listening on http://{host}:{args.port}{clean_path}',
            file=sys.stderr,
            flush=True,
        )
    mcp.run(transport=args.transport)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
