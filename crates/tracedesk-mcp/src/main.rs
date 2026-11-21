//! TraceDesk MCP 服务端独立命令行入口（`tracedesk-mcp.exe`），兼容原 `mcp_server.py` 全部参数。

use std::env;
use std::process::ExitCode;

use tracedesk_mcp::{parse_cli_args, run_with_config};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match parse_cli_args(args).and_then(run_with_config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(2)
        }
    }
}
