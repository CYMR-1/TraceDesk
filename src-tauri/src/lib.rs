//! TraceDesk Tauri 2 桌面工作台宿主库（`tracedesk_desktop_lib`）。

pub mod commands;
pub mod mcp_http;
pub mod state;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::{Manager, WindowEvent};
use tracedesk_core::now;

pub use state::AppState;

/// 向 `<logs_dir>/startup.log` 追加一条带时间戳的诊断日志
/// （若项目日志目录不可写，则回退至 `%TEMP%/TraceDesk/logs/startup.log`）。
fn append_startup_log(logs_dir: &Path, level: &str, message: &str) -> Option<PathBuf> {
    let candidates = [
        logs_dir.to_path_buf(),
        std::env::temp_dir().join("TraceDesk").join("logs"),
    ];
    let ts = now();
    let line = format!("[{ts}] [{level}] {message}\n");
    for dir in candidates {
        if std::fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let log_path = dir.join("startup.log");
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path)
            && file.write_all(line.as_bytes()).is_ok()
        {
            let _ = file.flush();
            return Some(log_path);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn show_windows_error_dialog(title: &str, body: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONERROR: u32 = 0x0000_0010;
    const MB_SETFOREGROUND: u32 = 0x0001_0000;

    unsafe extern "system" {
        fn MessageBoxW(
            hwnd: *mut std::ffi::c_void,
            text: *const u16,
            caption: *const u16,
            utype: u32,
        ) -> i32;
    }

    let wide_body: Vec<u16> = OsStr::new(body).encode_wide().chain(Some(0)).collect();
    let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(Some(0)).collect();
    // SAFETY: 两个缓冲区在本次调用期间均为有效的以 NUL 结尾的 UTF-16 字符串，
    // 且 Win32 `MessageBoxW` 文档明确允许传入空的所属窗口句柄（NULL HWND）。
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide_body.as_ptr(),
            wide_title.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
    }
}

#[cfg(not(target_os = "windows"))]
fn show_windows_error_dialog(_title: &str, _body: &str) {}

fn install_panic_logger(logs_dir: PathBuf) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = if let Some(msg) = info.payload().downcast_ref::<&str>() {
            (*msg).to_string()
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            msg.clone()
        } else {
            "non-string panic payload".to_string()
        };
        let detail = format!("panic at {location}: {payload}");
        let log_path = append_startup_log(&logs_dir, "PANIC", &detail);
        previous(info);

        #[cfg(all(target_os = "windows", not(debug_assertions)))]
        {
            let log_hint = log_path
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "logs/startup.log".to_string());
            let body = format!(
                "TraceDesk 原生桌面工作台发生未捕获异常并退出。\n\n错误信息：{detail}\n\n详细日志已写入：\n{log_hint}"
            );
            show_windows_error_dialog("TraceDesk 启动异常", &body);
        }
        #[cfg(not(all(target_os = "windows", not(debug_assertions))))]
        {
            let _ = log_path;
        }
    }));
}

/// 构建并运行 TraceDesk Tauri 2 桌面应用程序。
pub fn run() {
    let app_state = AppState::new();
    let logs_dir = app_state.app_paths.logs_dir.clone();
    install_panic_logger(logs_dir.clone());
    let _ = append_startup_log(
        &logs_dir,
        "INFO",
        &format!(
            "starting TraceDesk desktop workbench (root={}, custom_protocol={})",
            app_state.app_paths.root.display(),
            cfg!(feature = "custom-protocol")
        ),
    );

    let logs_dir_setup = logs_dir.clone();
    let run_result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::clone(&app_state))
        .setup(move |app| {
            // 绑定 Tauri AppHandle 并启动 MCP 跨进程遥测日志后台尾随线程（350ms 轻量轮询）。
            let st = app.state::<Arc<AppState>>();
            st.set_app_handle(app.handle().clone());
            st.start_activity_tailer();

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = append_startup_log(
                    &logs_dir_setup,
                    "INFO",
                    "main WebView2 window initialized and shown",
                );
            } else {
                let _ = append_startup_log(
                    &logs_dir_setup,
                    "WARN",
                    "setup completed without a 'main' webview window",
                );
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::Destroyed)
                && let Some(st) = window.try_state::<Arc<AppState>>()
            {
                st.shutdown_all();
            }
        })
        .invoke_handler(tauri::generate_handler![
            // §3.1 应用状态与案件管理命令
            commands::get_app_paths,
            commands::suggest_case_dir,
            commands::create_case,
            commands::open_case,
            commands::close_case,
            commands::release_case_lock,
            commands::get_case_snapshot,
            commands::list_recent_cases,
            // §3.2 证据镜像与文件浏览命令
            commands::load_image,
            commands::verify_integrity,
            commands::fix_hash,
            commands::cancel_verify_integrity,
            commands::register_source,
            commands::export_fsstat,
            commands::scan_all_partitions,
            commands::scan_partition,
            commands::cancel_scan_partitions,
            commands::cancel_task,
            commands::browse_directory,
            commands::get_tree_children,
            commands::query_files_page,
            commands::locate_file_in_scope,
            // §3.3 文件预览、导出与取证发现命令
            commands::preview_file_page,
            commands::preview_file_image,
            commands::export_file,
            commands::record_finding_note,
            commands::examine_file,
            commands::list_findings,
            commands::export_findings,
            // §3.4 时间线、审计、内容搜索与复核包命令
            commands::build_timeline,
            commands::query_timeline_page,
            commands::list_audit_log,
            commands::start_content_search,
            commands::cancel_content_search,
            commands::bookmark_search_hits,
            commands::load_search_record,
            commands::generate_report,
            commands::inspect_bundle_materials,
            commands::inspect_review_bundle,
            commands::prepare_review_bundle,
            commands::build_review_bundle,
            // §3.5 MCP 托管、实时遥测监控与系统工具命令
            commands::get_mcp_status,
            commands::start_mcp_http,
            commands::stop_mcp_http,
            commands::list_mcp_activities,
            commands::clear_mcp_activities,
            commands::open_in_os,
            commands::check_busy_before_close,
            commands::get_guide_pages,
        ])
        .run(tauri::generate_context!());

    if let Err(err) = run_result {
        let detail = format!("error while running TraceDesk Tauri desktop application: {err}");
        let log_path = append_startup_log(&logs_dir, "ERROR", &detail);
        eprintln!("{detail}");
        let log_hint = log_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| logs_dir.join("startup.log").display().to_string());
        let dialog_body = format!(
            "无法启动 TraceDesk 原生桌面工作台。\n\n\
             错误信息：{err}\n\n\
             排查建议：\n\
             1. 请确认系统已安装 Microsoft Edge WebView2 Runtime。\n\
             2. 请查看启动日志获取完整上下文：\n{log_hint}"
        );
        show_windows_error_dialog("TraceDesk 启动失败", &dialog_body);
        std::process::exit(1);
    }
}
