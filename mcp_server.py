"""TraceDesk MCP 服务端独立入口；使用项目 .venv 启动，支持 stdio 与本地 Streamable HTTP。"""
from forensic.mcp.__main__ import main

if __name__ == '__main__':
    raise SystemExit(main())
