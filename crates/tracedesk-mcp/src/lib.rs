//! TraceDesk MCP 服务端库（`tracedesk_mcp`）：
//! - 19 个标准电子数据取证 MCP 工具与 2 个 MCP 资源（`tools`）
//! - 单次调用自动加锁与立即释放 `case.lock`、只读视图/时间线缓存、`origin="mcp"` 审计写入（`service`）
//! - `stdio` 行分隔 JSON-RPC 2.0 传输（`stdio`）
//! - 本地回环 `streamable-http` 传输、DNS 重绑定防护（`Host` / `Origin` 校验）与 `McpHttpServerHandle`（`http`）
//! - 桌面端进程内 `LocalHttpMcpManager` 与 Claude / Cursor / 通用客户端接入配置生成（`runtime`）

pub mod http;
pub mod runtime;
pub mod service;
pub mod stdio;
pub mod tools;

use std::env;
use std::path::PathBuf;

use tracedesk_core::AppPaths;

pub use http::{
    DEFAULT_HOST, DEFAULT_HTTP_PATH, DEFAULT_PORT, LOOPBACK_HOSTS, MAX_HTTP_BODY_BYTES,
    McpHttpServerHandle, check_port_available, normalize_http_path, run_http_blocking,
    validate_loopback_host, verify_dns_rebinding,
};
pub use runtime::{
    LocalHttpMcpManager, McpStatusSnapshot, build_claude_config, build_cli_command,
    build_cursor_config, build_http_config, build_stdio_config, format_config_json,
    mcp_executable_path,
};
pub use service::{
    CaseService, McpError, McpResult, force_release_case_lock, format_entry, normalize_entry_path,
    paginate,
};
pub use stdio::{run_stdio, run_stdio_loop};
pub use tools::{
    DEFAULT_PROTOCOL_VERSION, McpResourceContent, McpResourceDefinition, McpServer, McpTextContent,
    McpToolAnnotations, McpToolCallOutput, McpToolDefinition, ResponseFormat, SERVER_INSTRUCTIONS,
    SERVER_NAME, SERVER_VERSION, TOOL_CATALOG, ToolCatalogItem, WORKFLOW_GUIDE_MARKDOWN,
};

/// 便捷构建绑定指定案件库根目录与默认操作人的 [`McpServer`]。
pub fn create_server(cases_root: Option<PathBuf>, default_actor: Option<String>) -> McpServer {
    McpServer::new(cases_root, default_actor)
}

/// MCP 传输模式枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Stdio,
    StreamableHttp,
}

impl TransportMode {
    pub fn parse(raw: &str) -> McpResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "stdio" => Ok(Self::Stdio),
            "streamable-http" => Ok(Self::StreamableHttp),
            other => Err(McpError::ValueError(format!(
                "不支持的传输模式：{other}（可选：stdio 或 streamable-http）"
            ))),
        }
    }
}

/// 命令行启动参数（100% 兼容 `forensic/mcp/__main__.py` 与 `mcp-contract.md` §1.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCliConfig {
    pub transport: TransportMode,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub cases_dir: PathBuf,
    pub actor: Option<String>,
    pub show_help: bool,
    pub show_version: bool,
}

impl Default for McpCliConfig {
    fn default() -> Self {
        let default_cases = env::var("TRACEDESK_CASES_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| PathBuf::from(s.trim()))
            .unwrap_or_else(|| AppPaths::discover().cases_dir);
        let default_actor = env::var("TRACEDESK_MCP_ACTOR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            transport: TransportMode::Stdio,
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            path: DEFAULT_HTTP_PATH.to_string(),
            cases_dir: default_cases,
            actor: default_actor,
            show_help: false,
            show_version: false,
        }
    }
}

/// 返回命令行帮助文本。
pub fn cli_help_text() -> String {
    format!(
        "usage: tracedesk-mcp [--transport {{stdio,streamable-http}}] [--host HOST] [--port PORT] [--path PATH] [--cases-dir DIR] [--actor ACTOR]\n\n\
         启动 TraceDesk 电子数据取证 MCP 服务端（支持 stdio 与本地 Streamable HTTP）。\n\n\
         options:\n  \
           -h, --help            显示帮助信息并退出\n  \
           -V, --version         显示版本号并退出\n  \
           --transport {{stdio,streamable-http}}\n                        \
                                 MCP 传输方式：stdio（默认，供本地桌面客户端拉起）或 streamable-http（本地 HTTP 服务）。\n  \
           --host HOST           streamable-http 监听地址，仅允许本机回环（默认 {DEFAULT_HOST}）。\n  \
           --port PORT           streamable-http 监听端口 1..=65535（默认 {DEFAULT_PORT}）。\n  \
           --path PATH           streamable-http 挂载路径（默认 {DEFAULT_HTTP_PATH}）。\n  \
           --cases-dir DIR       默认案件库根目录（也可通过环境变量 TRACEDESK_CASES_DIR 指定）。\n  \
           --actor ACTOR         默认写入审计链的操作人员标识（省略时使用案件取证人员；审计来源固定标记为 MCP）。"
    )
}

/// 解析命令行参数列表（不含 `argv[0]`）。
pub fn parse_cli_args<I, S>(args: I) -> McpResult<McpCliConfig>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut cfg = McpCliConfig::default();
    let vec: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    let mut i = 0usize;

    while i < vec.len() {
        let arg = vec[i].as_str();
        let (flag, inline_val) = match arg.split_once('=') {
            Some((k, v)) if k.starts_with('-') => (k, Some(v)),
            _ => (arg, None),
        };

        let mut next_val = |flag_name: &str| -> McpResult<String> {
            if let Some(v) = inline_val {
                Ok(v.to_string())
            } else {
                i += 1;
                vec.get(i).cloned().ok_or_else(|| {
                    McpError::ValueError(format!("命令行参数 {flag_name} 缺少对应值"))
                })
            }
        };

        match flag {
            "-h" | "--help" => {
                cfg.show_help = true;
            }
            "-V" | "--version" => {
                cfg.show_version = true;
            }
            "--transport" => {
                let val = next_val("--transport")?;
                cfg.transport = TransportMode::parse(&val)?;
            }
            "--host" => {
                cfg.host = next_val("--host")?;
            }
            "--port" => {
                let raw = next_val("--port")?;
                let parsed: i64 = raw.trim().parse().map_err(|_| {
                    McpError::ValueError(format!("无效的端口号：{raw}（端口号必须在 1 到 65535 之间。）"))
                })?;
                if !(1..=65535).contains(&parsed) {
                    return Err(McpError::ValueError(
                        "端口号必须在 1 到 65535 之间。".to_string(),
                    ));
                }
                cfg.port = parsed as u16;
            }
            "--path" => {
                let raw = next_val("--path")?;
                cfg.path = normalize_http_path(&raw);
            }
            "--cases-dir" => {
                let raw = next_val("--cases-dir")?;
                cfg.cases_dir = PathBuf::from(raw.trim());
            }
            "--actor" => {
                let raw = next_val("--actor")?;
                let trimmed = raw.trim();
                cfg.actor = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            other => {
                return Err(McpError::ValueError(format!("未知的命令行参数：{other}")));
            }
        }
        i += 1;
    }

    if cfg.transport == TransportMode::StreamableHttp {
        cfg.host = validate_loopback_host(&cfg.host)?;
    } else {
        cfg.host = DEFAULT_HOST.to_string();
    }
    cfg.path = normalize_http_path(&cfg.path);

    Ok(cfg)
}

/// 根据 [`McpCliConfig`] 启动 `stdio` 或 `streamable-http` MCP 服务。
pub fn run_with_config(cfg: McpCliConfig) -> McpResult<()> {
    if cfg.show_help {
        println!("{}", cli_help_text());
        return Ok(());
    }
    if cfg.show_version {
        println!("{SERVER_NAME} {SERVER_VERSION}");
        return Ok(());
    }
    let server = McpServer::new(Some(cfg.cases_dir), cfg.actor);
    match cfg.transport {
        TransportMode::Stdio => run_stdio(&server),
        TransportMode::StreamableHttp => {
            run_http_blocking(server, &cfg.host, cfg.port, &cfg.path)
        }
    }
}
