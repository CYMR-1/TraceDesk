//! TraceDesk Tauri 2 desktop workbench host library (`tracedesk_desktop_lib`).

pub mod commands;
pub mod mcp_http;
pub mod state;

use std::sync::Arc;

use tauri::{Manager, WindowEvent};

pub use state::AppState;

/// Build and run the TraceDesk Tauri 2 desktop application.
pub fn run() {
    let app_state = AppState::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::clone(&app_state))
        .on_window_event(|window, event| {
            if matches!(event, WindowEvent::Destroyed)
                && let Some(st) = window.try_state::<Arc<AppState>>()
            {
                st.shutdown_all();
            }
        })
        .invoke_handler(tauri::generate_handler![
            // §3.1 App 状态与案件管理 Commands
            commands::get_app_paths,
            commands::suggest_case_dir,
            commands::create_case,
            commands::open_case,
            commands::close_case,
            commands::release_case_lock,
            commands::get_case_snapshot,
            commands::list_recent_cases,
            // §3.2 证据镜像与文件浏览 Commands
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
            // §3.3 文件预览、导出与取证发现 Commands
            commands::preview_file_page,
            commands::preview_file_image,
            commands::export_file,
            commands::record_finding_note,
            commands::examine_file,
            commands::list_findings,
            commands::export_findings,
            // §3.4 时间线、审计、内容搜索与复核包 Commands
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
            // §3.5 MCP 托管与系统工具 Commands
            commands::get_mcp_status,
            commands::start_mcp_http,
            commands::stop_mcp_http,
            commands::open_in_os,
            commands::check_busy_before_close,
            commands::get_guide_pages,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TraceDesk Tauri desktop application");
}
