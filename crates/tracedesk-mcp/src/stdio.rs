//! MCP `stdio` 传输实现：按行读取 UTF-8 JSON-RPC 2.0 请求并输出单行 JSON 响应，
//! 并在单个 stdio 会话期间持续记住 `initialize` 传入的 `clientInfo`。

use std::io::{self, BufRead, BufReader, Write};

use uuid::Uuid;

use crate::service::McpResult;
use crate::tools::{McpRequestContext, McpServer};

/// 退出 stdio 消息循环时自动清理该会话对应的 `clientInfo` 缓存。
struct StdioSessionGuard<'a> {
    server: &'a McpServer,
    session_id: String,
}

impl Drop for StdioSessionGuard<'_> {
    fn drop(&mut self) {
        self.server.remove_session(&self.session_id);
    }
}

/// 在任意 [`BufRead`] 输入流与 [`Write`] 输出流上运行 MCP `stdio` JSON-RPC 2.0 消息循环。
pub fn run_stdio_loop<R: BufRead, W: Write>(
    server: &McpServer,
    mut reader: R,
    mut writer: W,
) -> McpResult<()> {
    let session_id = Uuid::new_v4().simple().to_string();
    let _guard = StdioSessionGuard {
        server,
        session_id: session_id.clone(),
    };
    let ctx = McpRequestContext {
        session_id: Some(session_id),
        ..Default::default()
    };

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
        if let Some(resp) = server.handle_jsonrpc_str_with_context(trimmed, &ctx) {
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
