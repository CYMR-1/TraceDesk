//! MCP `stdio` 传输实现：按行读取 UTF-8 JSON-RPC 2.0 请求并输出单行 JSON 响应。

use std::io::{self, BufRead, BufReader, Write};

use crate::service::McpResult;
use crate::tools::McpServer;

/// 在任意 [`BufRead`] 输入流与 [`Write`] 输出流上运行 MCP `stdio` JSON-RPC 2.0 消息循环。
pub fn run_stdio_loop<R: BufRead, W: Write>(
    server: &McpServer,
    mut reader: R,
    mut writer: W,
) -> McpResult<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(resp) = server.handle_jsonrpc_str(trimmed) {
            writer.write_all(resp.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// 在进程标准输入/输出 (`stdin` / `stdout`) 上启动阻塞式 MCP `stdio` 传输服务。
pub fn run_stdio(server: &McpServer) -> McpResult<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let reader = BufReader::new(stdin.lock());
    let writer = stdout.lock();
    run_stdio_loop(server, reader, writer)
}
