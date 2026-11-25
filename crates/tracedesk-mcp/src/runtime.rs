//! 本地 Streamable HTTP MCP 服务生命周期管理（`LocalHttpMcpManager`）与 Claude / Cursor / 通用客户端接入配置生成。

use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::{Value, json};
use tracedesk_core::{AppPaths, resolve_clean};

use crate::activity::McpActivitySink;
use crate::http::{
    DEFAULT_HOST, DEFAULT_HTTP_PATH, DEFAULT_PORT, McpHttpServerHandle, normalize_http_path,
    validate_loopback_host,
};
use crate::service::{McpError, McpResult};
use crate::tools::{McpServer, TOOL_CATALOG, ToolCatalogItem};

/// 定位 `tracedesk-mcp` 独立可执行文件的绝对路径。
pub fn mcp_executable_path() -> PathBuf {
    let bin_name = if cfg!(windows) {
        "tracedesk-mcp.exe"
    } else {
        "tracedesk-mcp"
    };

    if let Ok(exe) = env::current_exe() {
        let clean = resolve_clean(&exe);
        if clean
            .file_stem()
            .is_some_and(|s| s.to_string_lossy().eq_ignore_ascii_case("tracedesk-mcp"))
        {
            return clean;
        }
        if let Some(dir) = clean.parent() {
            let sibling = dir.join(bin_name);
            if sibling.is_file() {
                return resolve_clean(&sibling);
            }
        }
    }

    let paths = AppPaths::discover();
    for candidate in [
        paths.root.join("target").join("release").join(bin_name),
        paths.root.join("target").join("debug").join(bin_name),
        paths.root.join(bin_name),
    ] {
        if candidate.is_file() {
            return resolve_clean(&candidate);
        }
    }

    paths.root.join(bin_name)
}

fn is_non_default_cases_root(cases_root: Option<&Path>) -> Option<PathBuf> {
    let provided = cases_root?;
    if provided.as_os_str().is_empty() {
        return None;
    }
    let resolved = resolve_clean(provided);
    let default_cases = resolve_clean(&AppPaths::discover().cases_dir);
    if resolved != default_cases {
        Some(resolved)
    } else {
        None
    }
}

/// 生成标准 `stdio` MCP 客户端接入配置 JSON（`mcp-contract.md` §4）。
///
/// 若 `cases_root` 为非默认案件库路径，则自动在 `args` 中追加 `["--cases-dir", "<path>"]`。
pub fn build_stdio_config(cases_root: Option<&Path>) -> Value {
    let exe = mcp_executable_path().to_string_lossy().into_owned();
    let args: Vec<String> = match is_non_default_cases_root(cases_root) {
        Some(custom_root) => vec![
            "--cases-dir".to_string(),
            custom_root.to_string_lossy().into_owned(),
        ],
        None => Vec::new(),
    };
    json!({
        "mcpServers": {
            "tracedesk": {
                "command": exe,
                "args": args
            }
        }
    })
}

/// 生成标准 `Streamable HTTP` MCP 客户端接入配置 JSON（`mcp-contract.md` §4）。
pub fn build_http_config(host: &str, port: u16, path: &str) -> Value {
    let clean_host = if host.trim().is_empty() {
        DEFAULT_HOST
    } else {
        host.trim()
    };
    let clean_path = normalize_http_path(path);
    let url_host = if clean_host == "::1" {
        "[::1]"
    } else {
        clean_host
    };
    json!({
        "mcpServers": {
            "tracedesk": {
                "url": format!("http://{url_host}:{port}{clean_path}")
            }
        }
    })
}

/// 生成 Claude Desktop `claude_desktop_config.json` 配置对象（默认采用 `stdio` 子进程模式）。
pub fn build_claude_config(cases_root: Option<&Path>) -> Value {
    build_stdio_config(cases_root)
}

/// 生成 Cursor `.cursor/mcp.json` 配置对象（支持 `stdio` 或 `streamable-http` 模式）。
pub fn build_cursor_config(cases_root: Option<&Path>, use_http: bool, port: u16) -> Value {
    if use_http {
        build_http_config(DEFAULT_HOST, port, DEFAULT_HTTP_PATH)
    } else {
        build_stdio_config(cases_root)
    }
}

/// 生成 PowerShell / CLI 启动命令行字符串。
pub fn build_cli_command(
    transport: &str,
    host: &str,
    port: u16,
    path: &str,
    cases_root: Option<&Path>,
) -> String {
    let exe = mcp_executable_path().to_string_lossy().into_owned();
    let extra_cases = is_non_default_cases_root(cases_root)
        .map(|p| format!(" --cases-dir \"{}\"", p.display()))
        .unwrap_or_default();

    if transport.trim().eq_ignore_ascii_case("streamable-http") {
        let clean_host = if host.trim().is_empty() {
            DEFAULT_HOST
        } else {
            host.trim()
        };
        let clean_path = normalize_http_path(path);
        format!(
            "& \"{exe}\" --transport streamable-http --host {clean_host} --port {port} --path {clean_path}{extra_cases}"
        )
    } else {
        format!("& \"{exe}\"{extra_cases}")
    }
}

/// 将配置 JSON 格式化为 2 空格缩进的 UTF-8 字符串。
pub fn format_config_json(payload: &Value) -> String {
    serde_json::to_string_pretty(payload).unwrap_or_else(|_| payload.to_string())
}

/// 桌面端 MCP 服务弹窗状态快照（100% 对齐 `ui-contract.md` §3.5 `McpStatus`）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStatusSnapshot {
    pub running: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub url: String,
    pub stdio_config_json: String,
    pub stdio_cli: String,
    pub http_config_json: String,
    pub http_cli: String,
    pub tools: Vec<ToolCatalogItem>,
    pub active_case_number: Option<String>,
}

struct ManagerState {
    handle: Option<McpHttpServerHandle>,
    host: String,
    port: u16,
    path: String,
}

/// 进程内托管本地 `127.0.0.1` Streamable HTTP MCP 服务的生命周期管理器（供 `src-tauri` 桌面端与测试启停）。
pub struct LocalHttpMcpManager {
    cases_root: PathBuf,
    default_actor: Option<String>,
    activity_sink: Option<Arc<dyn McpActivitySink>>,
    state: Mutex<ManagerState>,
}

impl LocalHttpMcpManager {
    /// 创建绑定到指定案件库目录与默认操作人的 [`LocalHttpMcpManager`]。
    pub fn new(cases_root: Option<PathBuf>, default_actor: Option<String>) -> Self {
        let resolved_root = match cases_root {
            Some(p) if !p.as_os_str().is_empty() => resolve_clean(&p),
            _ => AppPaths::discover().cases_dir,
        };
        let clean_actor = default_actor
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        Self {
            cases_root: resolved_root,
            default_actor: clean_actor,
            activity_sink: None,
            state: Mutex::new(ManagerState {
                handle: None,
                host: DEFAULT_HOST.to_string(),
                port: DEFAULT_PORT,
                path: DEFAULT_HTTP_PATH.to_string(),
            }),
        }
    }

    /// 链式配置自定义实时活动遥测接收器（便于测试隔离或自定义消费，未设置时默认写入共享 JSONL）。
    pub fn with_activity_sink(mut self, sink: Arc<dyn McpActivitySink>) -> Self {
        self.activity_sink = Some(sink);
        self
    }

    pub fn cases_root(&self) -> &Path {
        &self.cases_root
    }

    pub fn default_actor(&self) -> Option<&str> {
        self.default_actor.as_deref()
    }

    /// 当前本地 HTTP MCP 服务是否正在运行。
    pub fn running(&self) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.handle.as_ref().map(McpHttpServerHandle::is_running))
            .unwrap_or(false)
    }

    pub fn is_running(&self) -> bool {
        self.running()
    }

    pub fn host(&self) -> String {
        self.state
            .lock()
            .map(|s| s.host.clone())
            .unwrap_or_else(|_| DEFAULT_HOST.to_string())
    }

    pub fn port(&self) -> u16 {
        self.state.lock().map(|s| s.port).unwrap_or(DEFAULT_PORT)
    }

    pub fn path(&self) -> String {
        self.state
            .lock()
            .map(|s| s.path.clone())
            .unwrap_or_else(|_| DEFAULT_HTTP_PATH.to_string())
    }

    pub fn url(&self) -> String {
        let (host, port, path) = self
            .state
            .lock()
            .map(|s| (s.host.clone(), s.port, s.path.clone()))
            .unwrap_or_else(|_| {
                (
                    DEFAULT_HOST.to_string(),
                    DEFAULT_PORT,
                    DEFAULT_HTTP_PATH.to_string(),
                )
            });
        let clean_path = normalize_http_path(&path);
        let url_host = if host == "::1" { "[::1]" } else { &host };
        format!("http://{url_host}:{port}{clean_path}")
    }

    /// 启动本地 Streamable HTTP MCP 服务并返回完整 URL（如 `"http://127.0.0.1:8765/mcp"`）。
    pub fn start(&self, host: &str, port: u16, path: &str) -> McpResult<String> {
        let clean_host = validate_loopback_host(host)?;
        if port == 0 {
            return Err(McpError::ValueError(
                "端口号必须在 1 到 65535 之间。".to_string(),
            ));
        }
        let clean_path = normalize_http_path(path);

        let mut guard = self
            .state
            .lock()
            .map_err(|_| McpError::RuntimeError("MCP 服务状态锁异常".to_string()))?;

        if let Some(ref existing) = guard.handle
            && existing.is_running()
        {
            // 若已在相同监听端点运行则幂等返回；若请求了新的主机/端口/路径则平滑重启到新端点。
            if existing.host() == clean_host
                && existing.port() == port
                && existing.path() == clean_path
            {
                return Ok(existing.url().to_string());
            }
            if let Some(mut old) = guard.handle.take() {
                old.stop();
            }
        }

        let mut server = McpServer::new(Some(self.cases_root.clone()), self.default_actor.clone());
        if let Some(ref sink) = self.activity_sink {
            server = server.with_activity_sink(Arc::clone(sink));
        }
        let handle = McpHttpServerHandle::start(server, &clean_host, port, &clean_path)?;
        let url = handle.url().to_string();
        guard.host = handle.host().to_string();
        guard.port = handle.port();
        guard.path = handle.path().to_string();
        guard.handle = Some(handle);
        Ok(url)
    }

    /// 使用默认 `127.0.0.1` 与 `/mcp` 在指定端口启动服务。
    pub fn start_on_port(&self, port: u16) -> McpResult<String> {
        self.start(DEFAULT_HOST, port, DEFAULT_HTTP_PATH)
    }

    /// 停止本地 Streamable HTTP MCP 服务。
    pub fn stop(&self) {
        if let Ok(mut guard) = self.state.lock()
            && let Some(mut handle) = guard.handle.take()
        {
            handle.stop();
        }
    }

    /// 生成供桌面端 UI 渲染的完整 [`McpStatusSnapshot`]。
    pub fn status(
        &self,
        requested_port: Option<u16>,
        active_case_number: Option<String>,
    ) -> McpStatusSnapshot {
        let (running, host, active_port, path) = match self.state.lock() {
            Ok(guard) => {
                let is_run = guard
                    .handle
                    .as_ref()
                    .is_some_and(McpHttpServerHandle::is_running);
                (is_run, guard.host.clone(), guard.port, guard.path.clone())
            }
            Err(_) => (
                false,
                DEFAULT_HOST.to_string(),
                DEFAULT_PORT,
                DEFAULT_HTTP_PATH.to_string(),
            ),
        };

        let display_port = if running {
            active_port
        } else {
            requested_port.filter(|&p| p > 0).unwrap_or(active_port)
        };
        let clean_path = normalize_http_path(&path);
        let url_host = if host == "::1" { "[::1]" } else { &host };
        let url = format!("http://{url_host}:{display_port}{clean_path}");

        let stdio_cfg = build_stdio_config(Some(&self.cases_root));
        let http_cfg = build_http_config(&host, display_port, &clean_path);

        McpStatusSnapshot {
            running,
            host: host.clone(),
            port: display_port,
            path: clean_path.clone(),
            url,
            stdio_config_json: format_config_json(&stdio_cfg),
            stdio_cli: build_cli_command(
                "stdio",
                &host,
                display_port,
                &clean_path,
                Some(&self.cases_root),
            ),
            http_config_json: format_config_json(&http_cfg),
            http_cli: build_cli_command(
                "streamable-http",
                &host,
                display_port,
                &clean_path,
                Some(&self.cases_root),
            ),
            tools: TOOL_CATALOG.to_vec(),
            active_case_number,
        }
    }
}

impl Drop for LocalHttpMcpManager {
    fn drop(&mut self) {
        self.stop();
    }
}
