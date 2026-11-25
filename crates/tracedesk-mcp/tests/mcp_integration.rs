//! TraceDesk MCP 服务端端到端集成测试：
//! - 全部 19 个 MCP 工具 + 2 个资源在真实 `evidence/demo.dd` 上的完整取证闭环
//! - `origin="mcp"` 与 `origin="manual"` 审计链记录、筛选与篡改检测
//! - ZIP64 复核包构建与原生验签
//! - `case.lock` 并发冲突提示、单次调用立即释放锁与 `force_release_case_lock`
//! - 多分区同名文件消歧与 FAT16 已删除文件筛选/预览
//! - `stdio` JSON-RPC 2.0 协议循环与真实 `tracedesk-mcp.exe` 子进程端到端通信
//! - `streamable-http` 回环 HTTP 服务、生命周期管理与 DNS 重绑定恶意 `Host` / `Origin` 拦截

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tracedesk_core::{
    AppPaths, AuditOrigin, Case, audit_mcp_user, audit_origin_label, verify_audit_chain_at,
    verify_bundle,
};
use tracedesk_mcp::{
    ACTIVITY_LOG_FILENAME, ActivityLogTailer, DEFAULT_MCP_CLIENT_LABEL, FileActivitySink,
    LocalHttpMcpManager, MAX_HTTP_BODY_BYTES, McpActivityRecord, McpActivityStore,
    McpHttpServerHandle, McpServer, TOOL_CATALOG, TransportMode, build_claude_config,
    build_cli_command, build_cursor_config, build_http_config, build_stdio_config, create_server,
    force_release_case_lock, format_config_json, parse_cli_args, run_stdio_loop,
    validate_loopback_host,
};

fn free_local_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

/// 复制 `evidence/demo.dd` 到临时目录并返回 `(image_path, manifest_map)`。
fn prepare_demo_image(dest_dir: &Path) -> (PathBuf, HashMap<String, Value>) {
    let paths = AppPaths::discover();
    let src_image = paths.evidence_dir.join("demo.dd");
    let src_manifest = paths.evidence_dir.join("demo.manifest.json");
    assert!(
        src_image.is_file(),
        "missing demo image: {}",
        src_image.display()
    );
    fs::create_dir_all(dest_dir).expect("create evidence dir");
    let dst_image = dest_dir.join("demo_mcp.dd");
    fs::copy(&src_image, &dst_image).expect("copy demo.dd");

    let manifest_raw = fs::read_to_string(&src_manifest).expect("read demo.manifest.json");
    let manifest_val: Value = serde_json::from_str(&manifest_raw).expect("parse manifest");
    let files_obj = manifest_val
        .get("files")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(|| manifest_val.as_object().cloned().unwrap_or_default());
    let map: HashMap<String, Value> = files_obj.into_iter().collect();
    (dst_image, map)
}

/// 基于 `evidence/demo_volume.dd` 构造包含两个 FAT16 分区（偏移 2048 与 20480 扇区）的多分区镜像，
/// 并将第一分区第二条根目录记录改为 `0xE5` 已删除标记，第二分区 `README.TXT` 开头改为 `"SECOND FS"`。
fn create_multi_partition_test_image(dest_path: &Path) {
    let paths = AppPaths::discover();
    let vol_path = paths.evidence_dir.join("demo_volume.dd");
    assert!(
        vol_path.is_file(),
        "missing demo_volume.dd: {}",
        vol_path.display()
    );
    let volume = fs::read(&vol_path).expect("read demo_volume.dd");
    let offsets: [u32; 2] = [2048, 20480];
    let sectors = (volume.len() / 512) as u32;
    let total_sectors = offsets[1] + sectors;
    let mut image = vec![0u8; (total_sectors as usize) * 512];
    image[510] = 0x55;
    image[511] = 0xAA;

    for (idx, &offset) in offsets.iter().enumerate() {
        let mut data = volume.clone();
        data[28..32].copy_from_slice(&offset.to_le_bytes());
        if idx == 1 {
            let start = (1 + 2 * 64 + 32) * 512;
            data[start..start + 9].copy_from_slice(b"SECOND FS");
        }
        let byte_off = (offset as usize) * 512;
        image[byte_off..byte_off + data.len()].copy_from_slice(&data);

        // 在偏移 446 + idx * 16 处写入 MBR 分区表项。
        let entry_off = 446 + idx * 16;
        image[entry_off] = 0;
        image[entry_off + 1..entry_off + 4].copy_from_slice(&[0, 2, 0]);
        image[entry_off + 4] = 0x06; // FAT16 分区类型
        image[entry_off + 5..entry_off + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
        image[entry_off + 8..entry_off + 12].copy_from_slice(&offset.to_le_bytes());
        image[entry_off + 12..entry_off + 16].copy_from_slice(&sectors.to_le_bytes());
    }

    // 将第一分区（偏移 2048 扇区）的第二条根目录项标记为已删除（0xE5）。
    let root_dir_offset = ((2048 + 1 + 2 * 64) as usize) * 512;
    image[root_dir_offset + 32] = 0xE5;

    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    fs::write(dest_path, &image).expect("write multi.dd");
}

fn call_json(server: &McpServer, tool_name: &str, mut args: Value) -> Value {
    if let Some(obj) = args.as_object_mut() {
        obj.insert("response_format".to_string(), Value::String("json".to_string()));
    }
    let out = server.call_tool(tool_name, args);
    assert!(
        !out.is_error && !out.text().starts_with("Error ("),
        "tool {tool_name} failed: {}",
        out.text()
    );
    serde_json::from_str(out.text())
        .unwrap_or_else(|e| panic!("invalid JSON from {tool_name}: {e}\n{}", out.text()))
}

fn call_text(server: &McpServer, tool_name: &str, args: Value) -> String {
    server.call_tool_text(tool_name, args)
}

#[test]
fn test_tool_catalog_resources_and_config_generation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    fs::create_dir_all(&cases_dir).expect("create cases dir");
    let server = create_server(Some(cases_dir.clone()), None);

    let tools = server.list_tools();
    assert_eq!(tools.len(), 19);
    assert_eq!(tools.len(), TOOL_CATALOG.len());
    for (def, cat) in tools.iter().zip(TOOL_CATALOG.iter()) {
        assert_eq!(def.name, cat.name);
        assert_eq!(def.annotations.read_only_hint, cat.read_only);
        assert!(!def.annotations.destructive_hint);
        assert!(!def.annotations.open_world_hint);
        assert_eq!(
            def.input_schema
                .get("additionalProperties")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    let resources = server.list_resources();
    assert_eq!(resources.len(), 2);
    let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
    assert_eq!(uris, vec!["tracedesk://cases", "tracedesk://guide/workflow"]);

    // 验证客户端接入配置与命令行辅助函数
    let stdio_cfg = build_stdio_config(Some(&cases_dir));
    assert!(stdio_cfg["mcpServers"]["tracedesk"]["command"].is_string());
    let args_arr = stdio_cfg["mcpServers"]["tracedesk"]["args"]
        .as_array()
        .expect("args array");
    assert_eq!(args_arr[0].as_str(), Some("--cases-dir"));

    let http_cfg = build_http_config("127.0.0.1", 8765, "/mcp");
    assert_eq!(
        http_cfg["mcpServers"]["tracedesk"]["url"].as_str(),
        Some("http://127.0.0.1:8765/mcp")
    );
    assert_eq!(build_claude_config(Some(&cases_dir)), stdio_cfg);
    assert_eq!(build_cursor_config(Some(&cases_dir), true, 8765), http_cfg);
    assert!(format_config_json(&http_cfg).contains("http://127.0.0.1:8765/mcp"));
    assert!(
        build_cli_command("streamable-http", "127.0.0.1", 8765, "/mcp", None)
            .contains("--transport streamable-http --host 127.0.0.1 --port 8765 --path /mcp")
    );

    // 验证命令行参数解析
    let parsed_default = parse_cli_args(Vec::<String>::new()).expect("default cli args");
    assert_eq!(parsed_default.transport, TransportMode::Stdio);
    assert_eq!(parsed_default.host, "127.0.0.1");
    assert_eq!(parsed_default.port, 8765);
    assert_eq!(parsed_default.path, "/mcp");

    let parsed_http = parse_cli_args([
        "--transport",
        "streamable-http",
        "--host",
        "localhost",
        "--port",
        "9876",
        "--path",
        "mcp/",
        "--actor",
        "MCP审计员",
    ])
    .expect("http cli args");
    assert_eq!(parsed_http.transport, TransportMode::StreamableHttp);
    assert_eq!(parsed_http.host, "localhost");
    assert_eq!(parsed_http.port, 9876);
    assert_eq!(parsed_http.path, "/mcp");
    assert_eq!(parsed_http.actor.as_deref(), Some("MCP审计员"));

    assert!(
        parse_cli_args(["--transport", "streamable-http", "--host", "0.0.0.0"]).is_err(),
        "non-loopback host must be rejected"
    );
}

#[test]
fn test_full_real_tsk_forensic_workflow_all_19_tools_and_2_resources() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    fs::create_dir_all(&cases_dir).expect("create cases_dir");
    let (image_path, manifest) = prepare_demo_image(&tmp.path().join("evidence"));
    let server = create_server(Some(cases_dir.clone()), None);

    // 1. tracedesk_create_case（同时验证旧版包装格式 {"params": {...}} 的兼容性）
    let created = call_json(
        &server,
        "tracedesk_create_case",
        json!({
            "params": {
                "number": "MCP-001",
                "examiner": "张取证",
                "target": "FAT16 演示镜像",
                "response_format": "json"
            }
        }),
    );
    let case_dir = created["case_dir"].as_str().expect("case_dir").to_string();
    assert!(Path::new(&case_dir).join("case.json").is_file());
    assert_eq!(created["origin"].as_str(), Some("mcp"));
    assert_eq!(
        created["origin_label"].as_str(),
        Some("MCP · 本地 MCP 客户端")
    );
    assert_eq!(
        created["mcp_client"].as_str(),
        Some(DEFAULT_MCP_CLIENT_LABEL)
    );

    // 2. tracedesk_list_cases（JSON 与 Markdown 输出）
    let listed = call_json(&server, "tracedesk_list_cases", json!({}));
    assert_eq!(listed["total"].as_u64(), Some(1));
    assert_eq!(listed["items"][0]["number"].as_str(), Some("MCP-001"));
    let listed_md = call_text(&server, "tracedesk_list_cases", json!({}));
    assert!(listed_md.contains("# TraceDesk 案件列表"));
    assert!(listed_md.contains("MCP-001"));

    // 3. tracedesk_load_image（加载镜像）
    let loaded = call_json(
        &server,
        "tracedesk_load_image",
        json!({
            "case_dir": case_dir,
            "image_path": image_path.to_string_lossy(),
            "scan_all": true
        }),
    );
    assert_eq!(loaded["scanned_all_partitions"].as_bool(), Some(true));
    assert!(loaded["inventory_count"].as_u64().unwrap_or(0) > 0);
    let image_sha = loaded["sha256"].as_str().expect("sha256").to_string();
    assert_eq!(image_sha.len(), 64);

    // 4. tracedesk_register_source（登记证据来源）
    let registered = call_json(
        &server,
        "tracedesk_register_source",
        json!({
            "case_dir": case_dir,
            "evidence_id": "EV-01",
            "source": "教学实验室",
            "acquired": "2026-09-01 08:00 UTC+8",
            "tool": "make_demo",
            "expected_sha256": image_sha
        }),
    );
    assert!(
        registered["source_comparison"]
            .as_str()
            .unwrap_or("")
            .contains("一致")
    );

    // 5. tracedesk_verify_integrity（校验镜像完整性）
    let verified = call_json(
        &server,
        "tracedesk_verify_integrity",
        json!({ "case_dir": case_dir }),
    );
    assert_eq!(verified["ok"].as_bool(), Some(true));

    // 6. tracedesk_get_case_summary（Markdown 与 JSON 输出）
    let summary_md = call_text(
        &server,
        "tracedesk_get_case_summary",
        json!({ "case_dir": case_dir }),
    );
    assert!(summary_md.contains("MCP-001"));
    assert!(summary_md.contains(&image_sha));
    let summary_json = call_json(
        &server,
        "tracedesk_get_case_summary",
        json!({ "case_dir": case_dir }),
    );
    assert_eq!(summary_json["audit_chain_valid"].as_bool(), Some(true));

    // 7. tracedesk_scan_partitions（显式验证分区扫描工具）
    let rescanned = call_json(
        &server,
        "tracedesk_scan_partitions",
        json!({ "case_dir": case_dir, "partition_offset": 2048 }),
    );
    assert!(rescanned["inventory_count"].as_u64().unwrap_or(0) > 0);

    // 8. tracedesk_list_files（JSON 与 Markdown 输出，同时覆盖只读视图缓存）
    let files = call_json(
        &server,
        "tracedesk_list_files",
        json!({
            "case_dir": case_dir,
            "suffix": "txt",
            "keyword": "case",
            "files_only": true
        }),
    );
    assert_eq!(files["total"].as_u64(), Some(1));
    let case_txt = &files["items"][0];
    assert_eq!(case_txt["path"].as_str(), Some("DOCS/CASE.TXT"));
    assert_eq!(case_txt["partition_offset"].as_u64(), Some(2048));
    let case_inode = case_txt["inode"].as_str().expect("inode").to_string();

    let files_md = call_text(
        &server,
        "tracedesk_list_files",
        json!({ "case_dir": case_dir, "path_prefix": "DOCS" }),
    );
    assert!(files_md.contains("# 文件列表（full_inventory）"));
    assert!(files_md.contains("DOCS/CASE.TXT"));

    // 9. tracedesk_preview_file（JSON 与 Markdown 输出）
    let preview = call_json(
        &server,
        "tracedesk_preview_file",
        json!({
            "case_dir": case_dir,
            "path": "DOCS/CASE.TXT",
            "partition_offset": 2048,
            "inode": case_inode,
            "encoding": "UTF-8",
            "mode": "both"
        }),
    );
    assert!(
        preview["text"]
            .as_str()
            .unwrap_or("")
            .contains("Case note inside a nested directory.")
    );
    assert!(
        preview["hex_lines"][0]
            .as_str()
            .unwrap_or("")
            .starts_with("00000000  43 61 73 65")
    );
    let preview_md = call_text(
        &server,
        "tracedesk_preview_file",
        json!({
            "case_dir": case_dir,
            "path": "DOCS/CASE.TXT",
            "partition_offset": 2048
        }),
    );
    assert!(preview_md.contains("## 文本内容"));
    assert!(preview_md.contains("## 十六进制"));

    // 10. tracedesk_search_content（JSON 与 Markdown 输出）
    let search_hex = call_json(
        &server,
        "tracedesk_search_content",
        json!({
            "case_dir": case_dir,
            "query": "6E 6F 74 65",
            "encoding": "HEX",
            "path": "DOCS/CASE.TXT",
            "partition_offset": 2048
        }),
    );
    assert_eq!(search_hex["total"].as_u64(), Some(1));
    assert_eq!(search_hex["items"][0]["file_byte"].as_u64(), Some(5));
    let search_md = call_text(
        &server,
        "tracedesk_search_content",
        json!({
            "case_dir": case_dir,
            "query": "Case note",
            "encoding": "UTF-8"
        }),
    );
    assert!(search_md.contains("# 内容搜索结果"));
    assert!(search_md.contains("DOCS/CASE.TXT"));

    // 11. tracedesk_export_file（导出单个文件）
    let exported = call_json(
        &server,
        "tracedesk_export_file",
        json!({
            "case_dir": case_dir,
            "path": "DOCS/CASE.TXT",
            "partition_offset": 2048
        }),
    );
    let exported_path = PathBuf::from(exported["exported_path"].as_str().expect("exported_path"));
    assert!(exported_path.is_file());
    if let Some(expected_sha) = manifest
        .get("DOCS/CASE.TXT")
        .and_then(|v| v.get("sha256"))
        .and_then(Value::as_str)
    {
        assert_eq!(exported["record"]["sha256"].as_str(), Some(expected_sha));
    }

    // 12. tracedesk_examine_file（与导出副本执行 FILE_COMPARE 比对）
    let compared = call_json(
        &server,
        "tracedesk_examine_file",
        json!({
            "case_dir": case_dir,
            "path": "DOCS/CASE.TXT",
            "partition_offset": 2048,
            "comparison_path": exported_path.to_string_lossy()
        }),
    );
    assert_eq!(compared["operation"].as_str(), Some("FILE_COMPARE"));
    assert_eq!(compared["result"].as_str(), Some("一致"));

    // 13. tracedesk_record_finding（记录取证发现笔记）
    let noted = call_json(
        &server,
        "tracedesk_record_finding",
        json!({
            "case_dir": case_dir,
            "path": "DOCS/CASE.TXT",
            "partition_offset": 2048,
            "note": "文件内偏移 5 处包含字节 6E 6F 74 65 (note)"
        }),
    );
    assert_eq!(noted["actor"].as_str(), Some("张取证"));
    assert_eq!(noted["origin"].as_str(), Some("mcp"));
    assert_eq!(
        noted["origin_label"].as_str(),
        Some("MCP · 本地 MCP 客户端")
    );
    assert_eq!(noted["mcp_client"].as_str(), Some(DEFAULT_MCP_CLIENT_LABEL));

    // 14. tracedesk_list_findings（JSON 与 Markdown 输出）
    let findings = call_json(
        &server,
        "tracedesk_list_findings",
        json!({
            "case_dir": case_dir,
            "keyword": "6E 6F 74 65"
        }),
    );
    assert_eq!(findings["total"].as_u64(), Some(1));
    assert_eq!(findings["items"][0]["path"].as_str(), Some("DOCS/CASE.TXT"));
    let recs = findings["items"][0]["records"].as_array().expect("records");
    assert_eq!(
        recs.last().unwrap()["origin_label"].as_str(),
        Some("MCP · 本地 MCP 客户端")
    );
    let findings_md = call_text(
        &server,
        "tracedesk_list_findings",
        json!({ "case_dir": case_dir }),
    );
    assert!(findings_md.contains("# 取证发现"));
    assert!(findings_md.contains("[MCP · 本地 MCP 客户端]"));

    // 15. tracedesk_export_findings（批量导出取证发现）
    let exported_findings = call_json(
        &server,
        "tracedesk_export_findings",
        json!({ "case_dir": case_dir }),
    );
    assert_eq!(exported_findings["exported_count"].as_u64(), Some(1));
    let summary_path = PathBuf::from(
        exported_findings["summary_path"]
            .as_str()
            .expect("summary_path"),
    );
    assert!(summary_path.is_file());

    // 16. tracedesk_query_timeline（JSON 与 Markdown 连续查询两次以覆盖 TimelineIndex 缓存）
    let timeline = call_json(
        &server,
        "tracedesk_query_timeline",
        json!({
            "case_dir": case_dir,
            "event": "M",
            "query": "CASE.TXT"
        }),
    );
    assert!(timeline["total"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(timeline["items"][0]["event"].as_str(), Some("M 内容修改"));
    assert!(
        timeline["available_filters"]["partition_offsets"]
            .as_array()
            .is_some()
    );
    let timeline_md = call_text(
        &server,
        "tracedesk_query_timeline",
        json!({
            "case_dir": case_dir,
            "event": "M",
            "sort_order": "desc"
        }),
    );
    assert!(timeline_md.contains("# MACB 时间线（UTC+8）"));

    // 通过 Case::open(..., AuditOrigin::Manual) 写入一条人工操作，验证严格的来源筛选
    // 以及磁盘文件在外部变更时只读缓存自动刷新机制。
    {
        let mut manual_case =
            Case::open(Path::new(&case_dir), None, AuditOrigin::Manual).expect("open manual case");
        manual_case
            .verify_integrity(None, None, None)
            .expect("manual verify");
        manual_case.close();
    }

    // 17. tracedesk_query_audit_log（校验 mcp / manual 来源筛选与 Markdown 输出）
    let audit_mcp = call_json(
        &server,
        "tracedesk_query_audit_log",
        json!({
            "case_dir": case_dir,
            "origin": "mcp",
            "sort_order": "desc"
        }),
    );
    assert_eq!(audit_mcp["audit_chain_valid"].as_bool(), Some(true));
    let mcp_total = audit_mcp["total"].as_u64().unwrap_or(0);
    assert!(mcp_total >= 5);
    for item in audit_mcp["items"].as_array().expect("items") {
        assert_eq!(item["origin"].as_str(), Some("mcp"));
        assert_eq!(
            item["origin_label"].as_str(),
            Some("MCP · 本地 MCP 客户端")
        );
        assert_eq!(item["mcp_client"].as_str(), Some(DEFAULT_MCP_CLIENT_LABEL));
    }
    assert_eq!(audit_mcp["origin_counts"]["manual"].as_u64(), Some(1));
    assert_eq!(audit_mcp["origin_counts"]["mcp"].as_u64(), Some(mcp_total));

    let audit_manual = call_json(
        &server,
        "tracedesk_query_audit_log",
        json!({
            "case_dir": case_dir,
            "origin": "manual"
        }),
    );
    assert_eq!(audit_manual["total"].as_u64(), Some(1));
    assert_eq!(audit_manual["items"][0]["origin"].as_str(), Some("manual"));
    assert_eq!(
        audit_manual["items"][0]["origin_label"].as_str(),
        Some("人工")
    );
    assert_eq!(
        audit_manual["items"][0]["action"].as_str(),
        Some("HASH_VERIFY")
    );

    let audit_md = call_text(
        &server,
        "tracedesk_query_audit_log",
        json!({ "case_dir": case_dir }),
    );
    assert!(audit_md.contains("| 序号 | 时间（UTC+8） | 来源 |"));
    assert!(audit_md.contains("| MCP · 本地 MCP 客户端 |"));
    assert!(audit_md.contains("| 人工 |"));

    // 18. tracedesk_generate_report（生成取证报告）
    let report = call_json(
        &server,
        "tracedesk_generate_report",
        json!({ "case_dir": case_dir }),
    );
    let report_path = PathBuf::from(report["report_path"].as_str().expect("report_path"));
    assert!(report_path.is_file());
    let report_text = fs::read_to_string(&report_path).expect("read report.md");
    assert!(report_text.contains("6E 6F 74 65"));
    assert!(report_text.contains("| 序号 | 时间 (UTC+8) | 来源 | 操作人员 | 操作 | 对象 | 结果 |"));
    assert!(report_text.contains("| 人工 |"));
    assert!(report_text.contains("| MCP · 本地 MCP 客户端 |"));

    // 19. tracedesk_build_review_bundle 与原生复核包验签
    let bundle = call_json(
        &server,
        "tracedesk_build_review_bundle",
        json!({ "case_dir": case_dir }),
    );
    let bundle_path = PathBuf::from(bundle["bundle_path"].as_str().expect("bundle_path"));
    assert!(bundle_path.is_file());
    let bundle_sha = bundle["sha256"].as_str().expect("bundle sha256");
    let verified_members =
        verify_bundle(&bundle_path, Some(bundle_sha)).expect("verify_bundle must pass");
    assert!(verified_members >= 6);

    // 在篡改审计链前，先预热 list_files 与 query_timeline 的只读视图缓存
    let warmed_files = call_json(
        &server,
        "tracedesk_list_files",
        json!({ "case_dir": case_dir }),
    );
    assert!(warmed_files["total"].as_u64().unwrap_or(0) > 0);
    let warmed_timeline = call_json(
        &server,
        "tracedesk_query_timeline",
        json!({ "case_dir": case_dir }),
    );
    assert!(warmed_timeline["total"].as_u64().unwrap_or(0) > 0);

    // 在 case.json 与清单缓存保持热态时篡改 audit.head -> list_files 与 query_timeline 必须拒绝访问
    let head_file = Path::new(&case_dir).join("audit.head");
    let orig_head = fs::read_to_string(&head_file).expect("read audit.head");
    fs::write(&head_file, "0".repeat(64)).expect("tamper audit.head");
    let head_err_files = call_text(
        &server,
        "tracedesk_list_files",
        json!({ "case_dir": case_dir }),
    );
    assert!(
        head_err_files.contains("锚点不匹配"),
        "expected audit.head tamper rejection in list_files, got: {head_err_files}"
    );
    let head_err_timeline = call_text(
        &server,
        "tracedesk_query_timeline",
        json!({ "case_dir": case_dir }),
    );
    assert!(
        head_err_timeline.contains("锚点不匹配"),
        "expected audit.head tamper rejection in query_timeline, got: {head_err_timeline}"
    );
    fs::write(&head_file, orig_head).expect("restore audit.head");

    // 篡改 audit.jsonl（伪造 "origin":"mcp" -> "origin":"manual"），验证即便只读缓存处于热态，
    // query_audit_log、list_files 与 query_timeline 仍能检出篡改
    let audit_file = Path::new(&case_dir).join("audit.jsonl");
    let raw_audit = fs::read_to_string(&audit_file).expect("read audit.jsonl");
    let tampered = raw_audit.replacen("\"origin\":\"mcp\"", "\"origin\":\"manual\"", 1);
    fs::write(&audit_file, tampered).expect("write tampered audit.jsonl");
    for tool in [
        "tracedesk_query_audit_log",
        "tracedesk_list_files",
        "tracedesk_query_timeline",
    ] {
        let tamper_err = call_text(&server, tool, json!({ "case_dir": case_dir }));
        assert!(
            tamper_err.contains("不完整或被修改"),
            "unexpected tamper_err from {tool}: {tamper_err}"
        );
    }
}

#[test]
fn test_boundaries_lock_contention_and_force_release() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    fs::create_dir_all(&cases_dir).expect("create cases_dir");
    let server = create_server(Some(cases_dir.clone()), None);

    let created = call_json(
        &server,
        "tracedesk_create_case",
        json!({
            "number": "MCP-LOCK",
            "examiner": "测试员",
            "target": "边界验证"
        }),
    );
    let case_dir = created["case_dir"].as_str().expect("case_dir").to_string();

    // 1. 必须拒绝未知额外字段（等价于 extra='forbid'）
    let unknown_field_err = call_text(
        &server,
        "tracedesk_get_case_summary",
        json!({
            "case_dir": case_dir,
            "unexpected_field": 123
        }),
    );
    assert!(unknown_field_err.starts_with("Error (ValueError):"));

    // 2. 必须拒绝位于 cases_dir 内部的源镜像文件
    let bad_image = cases_dir.join("inside.dd");
    fs::write(&bad_image, vec![0u8; 512]).expect("write bad_image");
    let err = call_text(
        &server,
        "tracedesk_load_image",
        json!({
            "case_dir": case_dir,
            "image_path": bad_image.to_string_lossy()
        }),
    );
    assert!(err.contains("Error (ValueError)"), "got: {err}");
    assert!(err.contains("案件库目录之外"), "got: {err}");

    // 3. 显式持续持有 case.lock 时，MCP 工具在短超时等待后应返回可操作的中文提示且不崩溃
    let mut opened =
        Case::open(Path::new(&case_dir), None, AuditOrigin::Manual).expect("open desktop case");
    let fast_timeout_server = McpServer::with_service(std::sync::Arc::new(
        tracedesk_mcp::CaseService::new(Some(cases_dir.clone()), None)
            .with_lock_timeout(std::time::Duration::from_millis(80)),
    ));
    let lock_err = call_text(
        &fast_timeout_server,
        "tracedesk_get_case_summary",
        json!({ "case_dir": case_dir }),
    );
    assert!(lock_err.contains("锁定"), "got: {lock_err}");
    assert!(lock_err.contains("桌面端"), "got: {lock_err}");

    // 桌面端仍在活跃持锁时调用 force_release_case_lock 也必须报告锁冲突
    let active_release_err = force_release_case_lock(Path::new(&case_dir)).unwrap_err();
    assert!(active_release_err.to_string().contains("锁定"));

    // 释放桌面端锁后 -> force_release_case_lock 可安全清理残留的 case.lock 文件
    opened.close();
    drop(opened);
    let released = force_release_case_lock(Path::new(&case_dir)).expect("release stale lock");
    assert!(released);
    assert!(!Path::new(&case_dir).join("case.lock").exists());

    // MCP 调用结束后立即释放锁，桌面端可立即重新打开该案件
    let summary = call_json(
        &server,
        "tracedesk_get_case_summary",
        json!({ "case_dir": case_dir }),
    );
    assert_eq!(summary["number"].as_str(), Some("MCP-LOCK"));
    let reopened =
        Case::open(Path::new(&case_dir), None, AuditOrigin::Manual).expect("reopen after MCP call");
    drop(reopened);

    // 4. 必须拒绝非回环监听地址
    let host_err = validate_loopback_host("0.0.0.0").unwrap_err();
    assert!(host_err.to_string().contains("回环"));
}

#[test]
fn test_multi_partition_disambiguation_deleted_files_and_resources() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    fs::create_dir_all(&cases_dir).expect("create cases_dir");
    let multi_image = tmp.path().join("evidence").join("multi.dd");
    create_multi_partition_test_image(&multi_image);

    let server = create_server(Some(cases_dir), None);
    let created = call_json(
        &server,
        "tracedesk_create_case",
        json!({
            "number": "MCP-MULTI",
            "examiner": "测试员",
            "target": "多分区与删除恢复"
        }),
    );
    let case_dir = created["case_dir"].as_str().expect("case_dir").to_string();

    call_json(
        &server,
        "tracedesk_load_image",
        json!({
            "case_dir": case_dir,
            "image_path": multi_image.to_string_lossy(),
            "scan_all": false
        }),
    );
    let scanned = call_json(
        &server,
        "tracedesk_scan_partitions",
        json!({ "case_dir": case_dir }),
    );
    assert_eq!(
        scanned["partition_scans"].as_array().map(Vec::len),
        Some(2)
    );

    // 未指定 partition_offset 时，跨分区同名的 README.TXT 应返回消歧提示
    let ambiguous = call_text(
        &server,
        "tracedesk_preview_file",
        json!({
            "case_dir": case_dir,
            "path": "README.TXT"
        }),
    );
    assert!(ambiguous.contains("歧义"), "got: {ambiguous}");
    assert!(ambiguous.contains("2048"), "got: {ambiguous}");
    assert!(ambiguous.contains("20480"), "got: {ambiguous}");

    // 指定 partition_offset=20480 时，准确读取第二分区的 README.TXT
    let p2 = call_json(
        &server,
        "tracedesk_preview_file",
        json!({
            "case_dir": case_dir,
            "path": "README.TXT",
            "partition_offset": 20480,
            "mode": "text"
        }),
    );
    assert!(
        p2["text"]
            .as_str()
            .unwrap_or("")
            .starts_with("SECOND FS")
    );

    // 筛选并预览第一分区（偏移 2048 扇区）中的已删除文件
    let deleted_list = call_json(
        &server,
        "tracedesk_list_files",
        json!({
            "case_dir": case_dir,
            "partition_offset": 2048,
            "status": "deleted",
            "files_only": true
        }),
    );
    assert!(deleted_list["total"].as_u64().unwrap_or(0) >= 1);
    let del_entry = &deleted_list["items"][0];
    let del_preview = call_json(
        &server,
        "tracedesk_preview_file",
        json!({
            "case_dir": case_dir,
            "path": del_entry["path"],
            "partition_offset": 2048,
            "inode": del_entry["inode"],
            "deleted": true,
            "mode": "text"
        }),
    );
    assert_eq!(del_preview["entry"]["deleted"].as_bool(), Some(true));

    // 读取全部 2 个 MCP 资源
    let guide_res = server
        .read_resource("tracedesk://guide/workflow")
        .expect("read workflow resource");
    assert!(guide_res.text.contains("tracedesk_load_image"));

    let cases_res = server
        .read_resource("tracedesk://cases")
        .expect("read cases resource");
    assert!(cases_res.text.contains("MCP-MULTI"));
}

#[test]
fn test_stdio_jsonrpc_and_subprocess_end_to_end() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    fs::create_dir_all(&cases_dir).expect("create cases_dir");
    let server = create_server(Some(cases_dir.clone()), None);

    call_json(
        &server,
        "tracedesk_create_case",
        json!({
            "number": "MCP-STDIO",
            "examiner": "测试员",
            "target": "STDIO 传输"
        }),
    );

    // 1. 内存 stdio 消息循环测试，覆盖所有必需的 JSON-RPC 2.0 方法
    let requests = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 4, "method": "resources/list"}),
        json!({"jsonrpc": "2.0", "id": 5, "method": "resources/read", "params": {"uri": "tracedesk://cases"}}),
        json!({"jsonrpc": "2.0", "id": 6, "method": "resources/templates/list"}),
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "tracedesk_list_cases", "arguments": {"response_format": "json"}}}),
    ];
    let mut input_bytes = Vec::new();
    for req in &requests {
        serde_json::to_writer(&mut input_bytes, req).unwrap();
        input_bytes.push(b'\n');
    }
    let mut output_bytes = Vec::new();
    run_stdio_loop(&server, Cursor::new(input_bytes), &mut output_bytes).expect("run_stdio_loop");

    let output_str = String::from_utf8(output_bytes).expect("utf8 output");
    let lines: Vec<Value> = output_str
        .lines()
        .map(|l| serde_json::from_str(l).expect("parse response line"))
        .collect();
    // 共发送 8 条消息，其中 1 条为通知 -> 应收到 7 条响应
    assert_eq!(lines.len(), 7);
    assert_eq!(
        lines[0]["result"]["serverInfo"]["name"].as_str(),
        Some("tracedesk_mcp")
    );
    assert_eq!(lines[1]["id"].as_u64(), Some(2)); // ping 响应
    assert_eq!(
        lines[2]["result"]["tools"].as_array().map(Vec::len),
        Some(19)
    );
    assert_eq!(
        lines[3]["result"]["resources"].as_array().map(Vec::len),
        Some(2)
    );
    assert!(
        lines[4]["result"]["contents"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("MCP-STDIO")
    );
    assert_eq!(
        lines[5]["result"]["resourceTemplates"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    let call_text_str = lines[6]["result"]["content"][0]["text"]
        .as_str()
        .expect("tool call text");
    let call_data: Value = serde_json::from_str(call_text_str).expect("parse call json");
    assert_eq!(call_data["total"].as_u64(), Some(1));
    assert_eq!(call_data["items"][0]["number"].as_str(), Some("MCP-STDIO"));

    // 2. 启动真实 `tracedesk-mcp.exe` 子进程并通过 stdio 进行端到端通信（将遥测日志隔离到临时目录）
    let exe = env!("CARGO_BIN_EXE_tracedesk-mcp");
    let logs_dir = tmp.path().join("logs");
    let mut child = Command::new(exe)
        .args([
            "--transport",
            "stdio",
            "--cases-dir",
            &cases_dir.to_string_lossy(),
        ])
        .env("TRACEDESK_LOGS_DIR", &logs_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tracedesk-mcp subprocess");

    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "tracedesk_list_cases", "arguments": {"response_format": "json"}}})
        )
        .unwrap();
        stdin.flush().unwrap();
    }
    // 关闭子进程 stdin，使其处理完请求后干净退出
    drop(child.stdin.take());

    let out = child.wait_with_output().expect("wait child");
    assert!(out.status.success());
    let resp_lines: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid json line"))
        .collect();
    assert_eq!(resp_lines.len(), 2);
    assert_eq!(resp_lines[0]["id"].as_u64(), Some(10));
    assert_eq!(resp_lines[1]["id"].as_u64(), Some(11));
}

fn send_raw_http_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect http server");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body_bytes = body.as_bytes();
    write!(stream, "{method} {path} HTTP/1.1\r\n").unwrap();
    for &(k, v) in headers {
        write!(stream, "{k}: {v}\r\n").unwrap();
    }
    write!(
        stream,
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    )
    .unwrap();
    stream.write_all(body_bytes).unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).expect("read status");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    let mut resp_body = String::new();
    reader.read_to_string(&mut resp_body).unwrap();
    (status_code, resp_body)
}

#[test]
fn test_streamable_http_and_dns_rebinding_protection_end_to_end() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    fs::create_dir_all(&cases_dir).expect("create cases_dir");
    let server = create_server(Some(cases_dir.clone()), None);
    let created = call_json(
        &server,
        "tracedesk_create_case",
        json!({
            "number": "MCP-HTTP",
            "examiner": "测试员",
            "target": "HTTP 传输与 DNS 重绑定防护"
        }),
    );

    let port = free_local_port();
    let isolated_sink = std::sync::Arc::new(FileActivitySink::new(
        tmp.path().join("logs").join(ACTIVITY_LOG_FILENAME),
    ));
    let manager = LocalHttpMcpManager::new(Some(cases_dir.clone()), None)
        .with_activity_sink(std::sync::Arc::clone(&isolated_sink) as _);
    let url = manager
        .start("127.0.0.1", port, "/mcp")
        .expect("start http server");
    assert_eq!(url, format!("http://127.0.0.1:{port}/mcp"));
    assert!(manager.running());

    let snap = manager.status(Some(port), Some("MCP-HTTP".to_string()));
    assert!(snap.running);
    assert_eq!(snap.port, port);
    assert_eq!(snap.tools.len(), 19);

    // 第二个管理器尝试绑定同一端口时必须返回端口占用错误
    let manager2 =
        LocalHttpMcpManager::new(Some(cases_dir), None).with_activity_sink(isolated_sink);
    let port_err = manager2.start("127.0.0.1", port, "/mcp").unwrap_err();
    assert!(
        port_err.to_string().contains("占用"),
        "expected port occupied error, got: {port_err}"
    );

    let host_hdr = format!("127.0.0.1:{port}");
    let origin_hdr = format!("http://127.0.0.1:{port}");

    // 1. 通过 Streamable HTTP 发送合法的 initialize 握手请求
    let (code, body) = send_raw_http_request(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Origin", &origin_hdr),
            ("Content-Type", "application/json"),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"}
        })
        .to_string(),
    );
    assert_eq!(code, 200);
    let init_resp: Value = serde_json::from_str(&body).expect("parse init resp");
    assert_eq!(
        init_resp["result"]["serverInfo"]["name"].as_str(),
        Some("tracedesk_mcp")
    );

    // 2. 通知类请求返回 HTTP 202 Accepted
    let (code_notif, _) = send_raw_http_request(
        port,
        "POST",
        "/mcp",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        .to_string(),
    );
    assert_eq!(code_notif, 202);

    // 3. 通过 Streamable HTTP 调用 tools/call
    let (code_call, body_call) = send_raw_http_request(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &format!("localhost:{port}")),
            ("Origin", &format!("http://localhost:{port}")),
            ("Content-Type", "application/json"),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_list_cases",
                "arguments": {
                    "params": {
                        "response_format": "json"
                    }
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_call, 200);
    let call_resp: Value = serde_json::from_str(&body_call).expect("parse call resp");
    let inner_text = call_resp["result"]["content"][0]["text"]
        .as_str()
        .expect("inner text");
    let listed_data: Value = serde_json::from_str(inner_text).expect("parse inner json");
    assert_eq!(listed_data["total"].as_u64(), Some(1));
    assert_eq!(
        listed_data["items"][0]["folder"].as_str(),
        created["case_dir"].as_str()
    );

    // 4. DNS Rebinding 攻击拦截：恶意 Host 请求头 -> HTTP 421
    let (code_bad_host, _) = send_raw_http_request(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", "evil.attacker.example:8765"),
            ("Content-Type", "application/json"),
        ],
        &json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}).to_string(),
    );
    assert_eq!(code_bad_host, 421);

    // 5. DNS Rebinding 攻击拦截：局域网 IP 的 Host 请求头 -> HTTP 421
    let (code_lan_host, _) = send_raw_http_request(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &format!("192.168.1.50:{port}")),
            ("Content-Type", "application/json"),
        ],
        &json!({"jsonrpc": "2.0", "id": 4, "method": "ping"}).to_string(),
    );
    assert_eq!(code_lan_host, 421);

    // 6. 跨站 CSRF / DNS Rebinding 攻击拦截：合法 Host 但恶意 Origin 请求头 -> HTTP 403
    let (code_bad_origin, _) = send_raw_http_request(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Origin", "http://malicious.site.invalid"),
            ("Content-Type", "application/json"),
        ],
        &json!({"jsonrpc": "2.0", "id": 5, "method": "ping"}).to_string(),
    );
    assert_eq!(code_bad_origin, 403);

    // 7. 根路径 "/" 必须返回 404 Not Found（绝不能被误路由到 "/mcp"）
    let (code_root, _) = send_raw_http_request(
        port,
        "POST",
        "/",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &json!({"jsonrpc": "2.0", "id": 6, "method": "ping"}).to_string(),
    );
    assert_eq!(code_root, 404);

    // 带尾部斜杠的 "/mcp/" 应匹配已配置的 "/mcp" 端点
    let (code_trailing, _) = send_raw_http_request(
        port,
        "POST",
        "/mcp/",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &json!({"jsonrpc": "2.0", "id": 7, "method": "ping"}).to_string(),
    );
    assert_eq!(code_trailing, 200);

    // 8. 超长 Content-Length（超过 MAX_HTTP_BODY_BYTES）-> HTTP 413 Payload Too Large
    {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect 413 test");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let oversized = MAX_HTTP_BODY_BYTES + 1;
        write!(
            stream,
            "POST /mcp HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Length: {oversized}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).expect("read 413 status");
        assert!(
            status_line.contains("413"),
            "expected HTTP 413 for oversized Content-Length, got: {status_line}"
        );
    }

    // 9. 超长 chunked Transfer-Encoding 请求体 -> HTTP 413 Payload Too Large
    {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect 413 chunked test");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let oversized_hex = format!("{:x}", MAX_HTTP_BODY_BYTES + 1);
        write!(
            stream,
            "POST /mcp HTTP/1.1\r\nHost: {host_hdr}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{oversized_hex}\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .expect("read 413 chunked status");
        assert!(
            status_line.contains("413"),
            "expected HTTP 413 for oversized chunked body, got: {status_line}"
        );
    }

    // 10. 停止服务并验证已干净关闭
    manager.stop();
    assert!(!manager.running());
}

/// 发送 HTTP 请求并返回 `(状态码, 小写键响应头映射, 响应体文本)`，便于验证 `Mcp-Session-Id` 等响应头。
fn send_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, HashMap<String, String>, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect local mcp http");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    for &(k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("Connection: close\r\n\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).unwrap();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut resp_headers = HashMap::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            resp_headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let resp_body = if let Some(cl) = resp_headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        let mut buf = vec![0u8; cl];
        if cl > 0 {
            reader.read_exact(&mut buf).unwrap();
        }
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        let mut s = String::new();
        reader.read_to_string(&mut s).unwrap();
        s
    };
    (status_code, resp_headers, resp_body)
}

#[test]
fn test_mcp_caller_identity_stdio_http_headers_and_actor_combination() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    fs::create_dir_all(&cases_dir).expect("create cases_dir");
    let (image_path, _) = prepare_demo_image(&tmp.path().join("evidence"));

    // 1. stdio 传输：在会话期间记住 initialize.clientInfo，并正确与工具参数 actor 合并。
    let stdio_server = McpServer::new(Some(cases_dir.clone()), None);
    let stdio_input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "clientInfo": { "name": "claude-code", "version": "2.1" }
            }
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_create_case",
                "arguments": {
                    "number": "WHO-STDIO-001",
                    "examiner": "张取证",
                    "target": "stdio调用方测试",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_load_image",
                "arguments": {
                    "case_dir": "WHO-STDIO-001_张取证_stdio调用方测试",
                    "image_path": image_path.to_string_lossy(),
                    "scan_all": true,
                    "actor": "张三",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    ]
    .join("\n")
        + "\n";
    let mut stdio_out = Vec::new();
    run_stdio_loop(
        &stdio_server,
        BufReader::new(Cursor::new(stdio_input.as_bytes())),
        &mut stdio_out,
    )
    .expect("stdio 循环执行成功");
    let out_lines: Vec<Value> = String::from_utf8(stdio_out)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("json 响应行"))
        .collect();
    assert_eq!(out_lines.len(), 3);
    let created_payload: Value = serde_json::from_str(
        out_lines[1]["result"]["content"][0]["text"]
            .as_str()
            .expect("create_case json"),
    )
    .expect("解析 create_case");
    let case_dir = created_payload["case_dir"]
        .as_str()
        .expect("case_dir")
        .to_string();
    assert_eq!(created_payload["mcp_client"].as_str(), Some("claude-code"));
    assert_eq!(
        created_payload["origin_label"].as_str(),
        Some("MCP · claude-code")
    );

    // 校验 stdio 会话中两条操作在 audit.jsonl 中的 mcp_client 标记（不再拼接末尾版本号数字）。
    let stdio_records = verify_audit_chain_at(Path::new(&case_dir)).expect("校验 stdio 审计链");
    assert_eq!(stdio_records[0].mcp_client.as_deref(), Some("claude-code"));
    assert!(
        stdio_records
            .iter()
            .any(|r| r.action == "IMAGE_LOAD" && r.mcp_client.as_deref() == Some("张三 / claude-code")),
        "携带 actor=张三 时应合并为 张三 / claude-code"
    );

    // 2. streamable-http 传输：验证 Mcp-Session-Id 隔离、无 session 回退、HTTP 头优先级与 --actor 合并。
    let port = free_local_port();
    let http_server = McpServer::new(Some(cases_dir.clone()), None).with_activity_sink(
        std::sync::Arc::new(FileActivitySink::new(
            tmp.path().join("logs").join(ACTIVITY_LOG_FILENAME),
        )),
    );
    let mut handle = McpHttpServerHandle::start(http_server, "127.0.0.1", port, "/mcp")
        .expect("启动本地 HTTP MCP 服务");
    let host_hdr = format!("127.0.0.1:{port}");

    // 2a. 客户端 A（Cursor 1.2）初始化，获取专属 Mcp-Session-Id。
    let (code_a, hdrs_a, _) = send_http(
        port,
        "POST",
        "/mcp",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "clientInfo": { "name": "Cursor", "version": "1.2" }
            }
        })
        .to_string(),
    );
    assert_eq!(code_a, 200);
    let sid_a = hdrs_a
        .get("mcp-session-id")
        .cloned()
        .expect("initialize 响应必须返回 Mcp-Session-Id");

    // 2b. 客户端 B（CherryStudio）初始化，获取另一个 Mcp-Session-Id（并成为最近一次 initialize 回退目标）。
    let (code_b, hdrs_b, _) = send_http(
        port,
        "POST",
        "/mcp",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "clientInfo": { "name": "CherryStudio" }
            }
        })
        .to_string(),
    );
    assert_eq!(code_b, 200);
    let sid_b = hdrs_b
        .get("mcp-session-id")
        .cloned()
        .expect("第二次 initialize 返回独立 Mcp-Session-Id");
    assert_ne!(sid_a, sid_b);

    // 2c. 客户端 A 携带自己的 Mcp-Session-Id 写入取证笔记 -> 应标记为 Cursor（不含末尾版本号 1.2，且不受客户端 B 影响）。
    let (code_note_a, _, body_note_a) = send_http(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Content-Type", "application/json"),
            ("Mcp-Session-Id", &sid_a),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "case_dir": case_dir,
                    "path": "DOCS/CASE.TXT",
                    "partition_offset": 2048,
                    "note": "来自会话 A 的笔记",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_note_a, 200);
    let note_a_rpc: Value = serde_json::from_str(&body_note_a).expect("parse note A");
    let note_a: Value = serde_json::from_str(
        note_a_rpc["result"]["content"][0]["text"]
            .as_str()
            .expect("note A text"),
    )
    .expect("note A json");
    assert_eq!(note_a["mcp_client"].as_str(), Some("Cursor"));
    assert_eq!(note_a["origin_label"].as_str(), Some("MCP · Cursor"));

    // 2d. 无 Mcp-Session-Id 请求 -> 回退到最近一次 initialize 的客户端 CherryStudio。
    let (code_no_sid, _, body_no_sid) = send_http(
        port,
        "POST",
        "/mcp",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "case_dir": case_dir,
                    "path": "DOCS/CASE.TXT",
                    "partition_offset": 2048,
                    "note": "无 session 头回退笔记",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_no_sid, 200);
    let no_sid_rpc: Value = serde_json::from_str(&body_no_sid).expect("parse no sid");
    let no_sid_note: Value = serde_json::from_str(
        no_sid_rpc["result"]["content"][0]["text"]
            .as_str()
            .expect("no sid text"),
    )
    .expect("no sid json");
    assert_eq!(no_sid_note["mcp_client"].as_str(), Some("CherryStudio"));
    assert_eq!(
        no_sid_note["origin_label"].as_str(),
        Some("MCP · CherryStudio")
    );

    // 2e. 显式 HTTP 头 X-MCP-User + X-MCP-Client 优先于会话 clientInfo。
    let (code_hdr, _, body_hdr) = send_http(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Content-Type", "application/json"),
            ("Mcp-Session-Id", &sid_a),
            ("X-MCP-User", "李四"),
            ("X-MCP-Client", "CustomAgent"),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "case_dir": case_dir,
                    "path": "DOCS/CASE.TXT",
                    "partition_offset": 2048,
                    "note": "显式 HTTP 头覆盖",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_hdr, 200);
    let hdr_rpc: Value = serde_json::from_str(&body_hdr).expect("parse hdr");
    let hdr_note: Value = serde_json::from_str(
        hdr_rpc["result"]["content"][0]["text"]
            .as_str()
            .expect("hdr text"),
    )
    .expect("hdr json");
    assert_eq!(hdr_note["mcp_client"].as_str(), Some("李四 / CustomAgent"));
    assert_eq!(
        hdr_note["origin_label"].as_str(),
        Some("MCP · 李四 / CustomAgent")
    );

    // 2f. 泛化 actor="MCP" 不应与客户端名拼接为 "MCP / Cursor"。
    let (code_gen, _, body_gen) = send_http(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Content-Type", "application/json"),
            ("Mcp-Session-Id", &sid_a),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 15,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "case_dir": case_dir,
                    "path": "DOCS/CASE.TXT",
                    "partition_offset": 2048,
                    "actor": "MCP",
                    "note": "泛化 actor 去重检查",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_gen, 200);
    let gen_rpc: Value = serde_json::from_str(&body_gen).expect("parse gen");
    let gen_note: Value = serde_json::from_str(
        gen_rpc["result"]["content"][0]["text"]
            .as_str()
            .expect("gen text"),
    )
    .expect("gen json");
    assert_eq!(gen_note["mcp_client"].as_str(), Some("Cursor"));

    handle.stop();

    // 3. 独立 HTTP 服务实例：校验非通用 User-Agent 回退、通用 curl UA 忽略以及 --actor 默认操作人合并。
    let port2 = free_local_port();
    let actor_server = McpServer::new(Some(cases_dir.clone()), Some("王五".to_string()))
        .with_activity_sink(std::sync::Arc::new(FileActivitySink::new(
            tmp.path().join("logs").join(ACTIVITY_LOG_FILENAME),
        )));
    let mut handle2 = McpHttpServerHandle::start(actor_server, "127.0.0.1", port2, "/mcp")
        .expect("启动带默认 actor 的 HTTP MCP 服务");
    let host_hdr2 = format!("127.0.0.1:{port2}");

    // 3a. 非通用 User-Agent 作为补充回退并去除末尾 "/3.0" 后与默认 --actor 合并为 "王五 / ForensicBot"。
    let (code_ua, _, body_ua) = send_http(
        port2,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr2),
            ("Content-Type", "application/json"),
            ("User-Agent", "ForensicBot/3.0"),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "case_dir": case_dir,
                    "path": "DOCS/CASE.TXT",
                    "partition_offset": 2048,
                    "note": "非通用 UA 与默认 actor 合并",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_ua, 200);
    let ua_rpc: Value = serde_json::from_str(&body_ua).expect("parse ua");
    let ua_note: Value = serde_json::from_str(
        ua_rpc["result"]["content"][0]["text"]
            .as_str()
            .expect("ua text"),
    )
    .expect("ua json");
    assert_eq!(
        ua_note["mcp_client"].as_str(),
        Some("王五 / ForensicBot")
    );

    // 3b. 通用 User-Agent (curl/8.5.0) 应被忽略，仅保留默认 --actor "王五"。
    let (code_curl, _, body_curl) = send_http(
        port2,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr2),
            ("Content-Type", "application/json"),
            ("User-Agent", "curl/8.5.0"),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_record_finding",
                "arguments": {
                    "case_dir": case_dir,
                    "path": "DOCS/CASE.TXT",
                    "partition_offset": 2048,
                    "note": "通用 curl UA 忽略测试",
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(code_curl, 200);
    let curl_rpc: Value = serde_json::from_str(&body_curl).expect("parse curl");
    let curl_note: Value = serde_json::from_str(
        curl_rpc["result"]["content"][0]["text"]
            .as_str()
            .expect("curl text"),
    )
    .expect("curl json");
    assert_eq!(curl_note["mcp_client"].as_str(), Some("王五"));

    handle2.stop();

    // 4. 校验 tracedesk_query_audit_log（JSON + Markdown 表格）与整案复核包验签。
    let query_server = create_server(Some(cases_dir), None);
    let audit_json = call_json(
        &query_server,
        "tracedesk_query_audit_log",
        json!({
            "case_dir": case_dir,
            "origin": "mcp",
            "limit": 50
        }),
    );
    assert_eq!(audit_json["audit_chain_valid"].as_bool(), Some(true));
    let items = audit_json["items"].as_array().expect("items");
    assert!(
        items
            .iter()
            .any(|it| it["mcp_client"].as_str() == Some("Cursor")
                && it["origin_label"].as_str() == Some("MCP · Cursor"))
    );
    assert!(
        items
            .iter()
            .any(|it| it["mcp_client"].as_str() == Some("李四 / CustomAgent")
                && it["origin_label"].as_str() == Some("MCP · 李四 / CustomAgent"))
    );

    let audit_md = call_text(
        &query_server,
        "tracedesk_query_audit_log",
        json!({
            "case_dir": case_dir,
            "limit": 50
        }),
    );
    assert!(audit_md.contains("| 序号 | 时间（UTC+8） | 来源 |"));
    assert!(audit_md.contains("| MCP · Cursor |"));
    assert!(audit_md.contains("| MCP · 李四 / CustomAgent |"));
    assert!(audit_md.contains("| MCP · 王五 / ForensicBot |"));

    let disk_records = verify_audit_chain_at(Path::new(&case_dir)).expect("全链校验通过");
    assert!(
        disk_records
            .iter()
            .all(|r| audit_mcp_user(r).is_some() && audit_origin_label(r).starts_with("MCP · "))
    );

    let bundle = call_json(
        &query_server,
        "tracedesk_build_review_bundle",
        json!({ "case_dir": case_dir }),
    );
    let bundle_path = PathBuf::from(bundle["bundle_path"].as_str().expect("bundle_path"));
    let bundle_sha = bundle["sha256"].as_str().expect("sha256");
    verify_bundle(&bundle_path, Some(bundle_sha)).expect("复核包验签通过");
}

#[test]
fn test_stdio_and_http_activity_telemetry_lifecycle_and_jsonl_tailing() {
    use std::sync::Arc;

    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    let logs_dir = tmp.path().join("logs");
    fs::create_dir_all(&cases_dir).expect("mkdir cases");
    fs::create_dir_all(&logs_dir).expect("mkdir logs");
    let log_path = logs_dir.join(ACTIVITY_LOG_FILENAME);

    let (image_path, _) = prepare_demo_image(&tmp.path().join("evidence"));

    // 1. 验证 stdio 传输产生完整的 started -> completed / failed 遥测事件（含 initialize、tools/call、resources/read）。
    let stdio_server = create_server(Some(cases_dir.clone()), None)
        .with_activity_sink(Arc::new(FileActivitySink::new(log_path.clone())));

    let stdio_input = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "clientInfo": { "name": "Antigravity", "version": "1.0" }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_create_case",
                "arguments": {
                    "number": "TELEM-01",
                    "examiner": "取证员甲",
                    "target": "测试磁盘",
                    "response_format": "json"
                }
            }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": { "uri": "tracedesk://guide/workflow" }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": { "uri": "tracedesk://unknown/resource" }
        }),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_get_case_summary",
                "arguments": { "case_dir": "NON_EXISTENT_DIR" }
            }
        }),
    ]
    .iter()
    .map(|v| serde_json::to_string(v).expect("serialize request"))
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";

    let mut out_buf = Vec::new();
    run_stdio_loop(&stdio_server, Cursor::new(stdio_input.as_bytes()), &mut out_buf)
        .expect("run_stdio_loop");

    let out_text = String::from_utf8(out_buf).expect("utf8 stdio output");
    let out_lines: Vec<Value> = out_text
        .lines()
        .map(|l| serde_json::from_str(l).expect("parse stdio resp"))
        .collect();
    assert_eq!(out_lines.len(), 5);
    let created_json: Value = serde_json::from_str(
        out_lines[1]["result"]["content"][0]["text"]
            .as_str()
            .expect("create_case text"),
    )
    .expect("create_case json");
    let created_case_dir = created_json["case_dir"]
        .as_str()
        .expect("created case_dir")
        .to_string();

    // 使用 ActivityLogTailer 读取 JSONL，验证每条调用均有成对的 started 与 completed/failed，且共享 callId。
    let mut tailer = ActivityLogTailer::new(log_path.clone(), 0);
    let raw_events = tailer.poll_new_records();
    assert_eq!(raw_events.len(), 10, "5 次调用应产生 10 条开始/结束事件");

    // 校验每对事件共享 callId 但事件 id 唯一。
    for pair in raw_events.as_chunks::<2>().0 {
        assert_eq!(pair[0].phase, "started");
        assert!(matches!(pair[1].phase.as_str(), "completed" | "failed"));
        assert_eq!(pair[0].call_id, pair[1].call_id);
        assert_ne!(pair[0].id, pair[1].id);
        assert_eq!(pair[0].transport, "stdio");
        assert_eq!(pair[1].transport, "stdio");
        assert_eq!(pair[1].client, "Antigravity");
        assert!(pair[0].timestamp.ends_with("+08:00"));
        assert!(pair[1].duration_ms.is_some());
    }

    // 校验 initialize、create_case、resources/read 成功与失败语义字段。
    assert_eq!(raw_events[1].method, "initialize");
    assert_eq!(raw_events[1].tool_title, "客户端握手初始化");
    assert_eq!(raw_events[1].category, "协议会话");
    assert!(raw_events[1].read_only);

    assert_eq!(raw_events[3].tool_name.as_deref(), Some("tracedesk_create_case"));
    assert_eq!(raw_events[3].tool_title, "新建案件");
    assert!(!raw_events[3].read_only);
    assert_eq!(raw_events[3].case_number.as_deref(), Some("TELEM-01"));
    assert!(raw_events[3].case_dir.is_some());

    assert_eq!(raw_events[5].method, "resources/read");
    assert_eq!(raw_events[5].tool_name.as_deref(), Some("tracedesk://guide/workflow"));
    assert_eq!(raw_events[5].tool_title, "读取 MCP 资源");
    assert_eq!(raw_events[5].phase, "completed");

    assert_eq!(raw_events[7].method, "resources/read");
    assert_eq!(raw_events[7].phase, "failed");
    assert!(raw_events[7].error.as_deref().is_some_and(|e| e.contains("未知的 MCP 资源")));

    assert_eq!(raw_events[9].tool_name.as_deref(), Some("tracedesk_get_case_summary"));
    assert_eq!(raw_events[9].phase, "failed");
    assert!(raw_events[9].error.is_some());

    // 2. 验证独立 streamable-http 传输写入 transport="streamable-http" 遥测记录。
    let port = free_local_port();
    let http_server = create_server(Some(cases_dir.clone()), None)
        .with_activity_sink(Arc::new(FileActivitySink::new(log_path.clone())));
    let mut http_handle =
        McpHttpServerHandle::start(http_server, "127.0.0.1", port, "/mcp").expect("start http");
    let host_hdr = format!("127.0.0.1:{port}");
    let (status, _, _) = send_http(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Content-Type", "application/json"),
            ("X-MCP-Client", "Cursor"),
        ],
        &json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "tracedesk_load_image",
                "arguments": {
                    "case_dir": created_case_dir,
                    "image_path": image_path.to_string_lossy(),
                    "scan_all": false,
                    "response_format": "json"
                }
            }
        })
        .to_string(),
    );
    assert_eq!(status, 200);
    http_handle.stop();

    // 增量尾随读取应仅拿到新增的 2 条 streamable-http 事件。
    let delta_events = tailer.poll_new_records();
    assert_eq!(delta_events.len(), 2);
    assert_eq!(delta_events[0].phase, "started");
    assert_eq!(delta_events[1].phase, "completed");
    assert_eq!(delta_events[1].transport, "streamable-http");
    assert_eq!(delta_events[1].client, "Cursor");
    assert_eq!(delta_events[1].tool_name.as_deref(), Some("tracedesk_load_image"));
    assert_eq!(delta_events[1].case_number.as_deref(), Some("TELEM-01"));

    // 3. 验证外部真实 tracedesk-mcp 子进程在 stdio 模式下默认通过 TRACEDESK_LOGS_DIR 写入 mcp-activity.jsonl。
    let exe_path = PathBuf::from(env!("CARGO_BIN_EXE_tracedesk-mcp"));
    let mut child = Command::new(&exe_path)
        .args(["--transport", "stdio", "--cases-dir"])
        .arg(&cases_dir)
        .env("TRACEDESK_LOGS_DIR", &logs_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tracedesk-mcp");
    {
        let mut child_in = child.stdin.take().expect("child stdin");
        let reqs = format!(
            "{}\n{}\n",
            json!({
                "jsonrpc": "2.0",
                "id": 101,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "clientInfo": { "name": "ExternalCli", "version": "2.0" }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 102,
                "method": "tools/call",
                "params": {
                    "name": "tracedesk_list_cases",
                    "arguments": { "limit": 5, "response_format": "json" }
                }
            })
        );
        child_in.write_all(reqs.as_bytes()).expect("write child stdin");
    }
    let output = child.wait_with_output().expect("wait child");
    assert!(output.status.success(), "child stderr: {}", String::from_utf8_lossy(&output.stderr));

    let subproc_events = tailer.poll_new_records();
    assert_eq!(subproc_events.len(), 4);
    assert_eq!(subproc_events[3].transport, "stdio");
    assert_eq!(subproc_events[3].client, "ExternalCli");
    assert_eq!(subproc_events[3].tool_name.as_deref(), Some("tracedesk_list_cases"));
    assert_eq!(subproc_events[3].phase, "completed");

    // 3b. 模拟历史已落盘到 mcp-activity.jsonl 的含版本号记录（workbuddy 1.0 与 WorkBuddy HTTP / workbuddy-http-forensics 1.0），
    //     读取后应自动去除末尾版本号数字且不污染 active_clients。
    let legacy_rec_1 = McpActivityRecord {
        id: "legacy-wb-1".to_string(),
        call_id: "legacy-call-wb-1".to_string(),
        client: "workbuddy 1.0".to_string(),
        ..subproc_events[3].clone()
    };
    let legacy_rec_2 = McpActivityRecord {
        id: "legacy-wb-2".to_string(),
        call_id: "legacy-call-wb-2".to_string(),
        client: "WorkBuddy HTTP / workbuddy-http-forensics 1.0".to_string(),
        ..subproc_events[3].clone()
    };
    tracedesk_mcp::append_activity_record(&log_path, &legacy_rec_1).expect("append legacy 1");
    tracedesk_mcp::append_activity_record(&log_path, &legacy_rec_2).expect("append legacy 2");
    let legacy_polled = tailer.poll_new_records();
    assert_eq!(legacy_polled.len(), 2);
    assert_eq!(legacy_polled[0].client, "workbuddy");
    assert_eq!(
        legacy_polled[1].client,
        "WorkBuddy HTTP / workbuddy-http-forensics"
    );

    // 4. 将全部记录加载进 McpActivityStore，校验按 callId 合并后的统计与最新倒序。
    let mut store = McpActivityStore::new(500);
    let loaded_bytes = store.load_from_file(&log_path);
    assert!(loaded_bytes > 0);
    let snapshot = store.snapshot(None, None, None, None, None);
    assert_eq!(snapshot.activities.len(), 10);
    assert_eq!(snapshot.stats.total_calls, 10);
    assert_eq!(snapshot.stats.running_calls, 0);
    assert_eq!(snapshot.stats.succeeded_calls, 8);
    assert_eq!(snapshot.stats.failed_calls, 2);
    assert_eq!(
        snapshot.activities[0].client,
        "WorkBuddy HTTP / workbuddy-http-forensics"
    );
    assert_eq!(snapshot.activities[1].client, "workbuddy");
    assert_eq!(snapshot.activities[2].client, "ExternalCli");
    assert!(
        snapshot
            .stats
            .active_clients
            .contains(&"workbuddy".to_string())
    );
    assert!(
        snapshot
            .stats
            .active_clients
            .contains(&"WorkBuddy HTTP / workbuddy-http-forensics".to_string())
    );
    assert!(
        !snapshot
            .stats
            .active_clients
            .iter()
            .any(|c| c.contains("1.0") || c.contains("2.0"))
    );
    // 校验所有记录均为合法 McpActivityRecord 并按 camelCase 序列化。
    let _: McpActivityRecord = snapshot.activities[0].clone();
}

#[test]
fn test_http_hardening_client_registry_and_input_validation_regressions() {
    use std::sync::Arc;
    use tracedesk_mcp::{HttpParseError, parse_http_request, sanitize_session_id};

    // 1. `sanitize_session_id` 必须拦截含控制字符/空白或超长的会话 ID，防止响应头注入。
    let clean_sid = sanitize_session_id(Some("valid-session_123"));
    assert_eq!(clean_sid, "valid-session_123");
    let injected_sid = sanitize_session_id(Some("abc\rX-Evil: 1"));
    assert_ne!(injected_sid, "abc\rX-Evil: 1");
    assert!(!injected_sid.contains('\r') && !injected_sid.contains('\n'));
    let too_long = "a".repeat(200);
    let sanitized_long = sanitize_session_id(Some(&too_long));
    assert!(sanitized_long.len() <= 128);

    // 2. HTTP 解析器安全加固：重复关键头、冲突分帧头、裸 CR、单缓冲超长行、非法 chunk 终止符均须返回 400。
    let dup_host = b"POST /mcp HTTP/1.1\r\nHost: evil.com\r\nHost: 127.0.0.1:8765\r\nContent-Length: 2\r\n\r\n{}";
    assert!(matches!(
        parse_http_request(&mut BufReader::new(Cursor::new(dup_host.as_slice()))),
        Err(HttpParseError::BadRequest(_))
    ));

    let dup_origin = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nOrigin: https://evil.com\r\nOrigin: http://127.0.0.1:8765\r\nContent-Length: 2\r\n\r\n{}";
    assert!(matches!(
        parse_http_request(&mut BufReader::new(Cursor::new(dup_origin.as_slice()))),
        Err(HttpParseError::BadRequest(_))
    ));

    let te_and_cl = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n0\r\n\r\n";
    assert!(matches!(
        parse_http_request(&mut BufReader::new(Cursor::new(te_and_cl.as_slice()))),
        Err(HttpParseError::BadRequest(_))
    ));

    let bare_cr = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nMcp-Session-Id: a\rX-Injected: 1\r\nContent-Length: 2\r\n\r\n{}";
    assert!(matches!(
        parse_http_request(&mut BufReader::new(Cursor::new(bare_cr.as_slice()))),
        Err(HttpParseError::BadRequest(_))
    ));

    let bad_chunk_term = b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}GARBAGE\r\n0\r\n\r\n";
    assert!(matches!(
        parse_http_request(&mut BufReader::new(Cursor::new(bad_chunk_term.as_slice()))),
        Err(HttpParseError::BadRequest(_))
    ));

    let overlong_chunk_size = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8765\r\nTransfer-Encoding: chunked\r\n\r\n0;{}\r\n\r\n",
        "x".repeat(1200)
    );
    assert!(matches!(
        parse_http_request(&mut BufReader::new(Cursor::new(overlong_chunk_size.as_bytes()))),
        Err(HttpParseError::BadRequest(_))
    ));

    // 3. JSON-RPC 2.0 缺少 `method` 与 `id` 的非法对象 `{}` 应返回 `-32600`（而非静默吞掉）。
    let tmp = tempfile::tempdir().expect("tempdir");
    let cases_dir = tmp.path().join("cases");
    let log_path = tmp.path().join("logs").join(ACTIVITY_LOG_FILENAME);
    let server = McpServer::new(Some(cases_dir.clone()), None)
        .with_activity_sink(Arc::new(FileActivitySink::new(log_path.clone())));
    let invalid_resp = server
        .handle_jsonrpc_value(json!({}))
        .expect("empty object must yield -32600");
    assert_eq!(invalid_resp["error"]["code"].as_i64(), Some(-32600));

    // 4. `ClientRegistry` 回归：非通用 User-Agent 优先于其他会话的 `last_initialized`，
    //    且会话 `DELETE` 移除后清理该会话设置的 `last_initialized`，防止跨会话误归因。
    let port = free_local_port();
    let http_server = McpServer::new(Some(cases_dir.clone()), None)
        .with_activity_sink(Arc::new(FileActivitySink::new(log_path)));
    let mut handle = McpHttpServerHandle::start(http_server, "127.0.0.1", port, "/mcp")
        .expect("start isolated http server");
    let host_hdr = format!("127.0.0.1:{port}");

    // 4a. 会话 A 初始化为 "Cursor"
    let init_body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2025-03-26", "clientInfo": { "name": "Cursor", "version": "1.0" } }
    }))
    .unwrap();
    let (code_init, hdrs_init, _) = send_http(
        port,
        "POST",
        "/mcp",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &init_body,
    );
    assert_eq!(code_init, 200);
    let sid_a = hdrs_init
        .get("mcp-session-id")
        .cloned()
        .expect("session id A");

    // 4b. 未初始化客户端 B 携带非通用 User-Agent `AuditBot/2.0` 建案 -> 审计来源必须归因为 `AuditBot` 而非 `Cursor`。
    let create_b = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "tracedesk_create_case",
            "arguments": {
                "number": "UA-PRIO-01",
                "examiner": "测试员",
                "target": "UA 优先级测试",
                "response_format": "json"
            }
        }
    }))
    .unwrap();
    let (code_b, _, body_b) = send_http(
        port,
        "POST",
        "/mcp",
        &[
            ("Host", &host_hdr),
            ("Content-Type", "application/json"),
            ("User-Agent", "AuditBot/2.0"),
        ],
        &create_b,
    );
    assert_eq!(code_b, 200);
    let rpc_b: Value = serde_json::from_str(&body_b).unwrap();
    let res_b: Value = serde_json::from_str(rpc_b["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(res_b["mcp_client"].as_str(), Some("AuditBot"));

    // 4c. 结束会话 A（DELETE）后，无标识客户端 C 不得继承已销毁的 `Cursor` 身份，应回退为默认标签。
    let (code_del, _, _) = send_http(
        port,
        "DELETE",
        "/mcp",
        &[("Host", &host_hdr), ("Mcp-Session-Id", &sid_a)],
        "",
    );
    assert_eq!(code_del, 200);
    let create_c = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "tracedesk_create_case",
            "arguments": {
                "number": "NO-STALE-01",
                "examiner": "测试员",
                "target": "会话清理防串号",
                "response_format": "json"
            }
        }
    }))
    .unwrap();
    let (code_c, _, body_c) = send_http(
        port,
        "POST",
        "/mcp",
        &[("Host", &host_hdr), ("Content-Type", "application/json")],
        &create_c,
    );
    assert_eq!(code_c, 200);
    let rpc_c: Value = serde_json::from_str(&body_c).unwrap();
    let res_c: Value = serde_json::from_str(rpc_c["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(res_c["mcp_client"].as_str(), Some(DEFAULT_MCP_CLIENT_LABEL));
    handle.stop();

    // 5. `search_content` 保留文本检索首尾空格 + `preview_file` 只读缓存快路径 + `build_review_bundle` 拒绝 0 序号。
    let (img_path, _) = prepare_demo_image(&tmp.path().join("evidence"));
    let created = call_json(
        &server,
        "tracedesk_create_case",
        json!({"number": "VAL-01", "examiner": "测试员", "target": "校验回归"}),
    );
    let case_dir = created["case_dir"].as_str().unwrap().to_string();
    call_json(
        &server,
        "tracedesk_load_image",
        json!({"case_dir": case_dir, "image_path": img_path.to_string_lossy(), "scan_all": true}),
    );

    // 含首尾空格的 UTF-8 检索词 `" forensic "` 在 `README.TXT`（"TraceDesk forensic demonstration."）中应精确命中且不丢失空格。
    let space_search = call_json(
        &server,
        "tracedesk_search_content",
        json!({
            "case_dir": case_dir,
            "query": " forensic ",
            "encoding": "UTF-8"
        }),
    );
    assert_eq!(space_search["query"].as_str(), Some(" forensic "));
    assert_eq!(space_search["total"].as_u64(), Some(1));

    // `preview_file` 只读缓存快路径连续读取内容正确。
    let preview = call_json(
        &server,
        "tracedesk_preview_file",
        json!({
            "case_dir": case_dir,
            "path": "README.TXT",
            "page": 0,
            "page_bytes": 64,
            "encoding": "UTF-8",
            "mode": "text"
        }),
    );
    assert!(
        preview["text"]
            .as_str()
            .unwrap_or("")
            .contains("TraceDesk forensic demonstration")
    );

    // `build_review_bundle` 拒绝从 0 开始的非法导出/搜索序号。
    let bad_bundle = server.call_tool(
        "tracedesk_build_review_bundle",
        json!({
            "case_dir": case_dir,
            "selected_export_indices": [0]
        }),
    );
    assert!(bad_bundle.is_error);
    assert!(bad_bundle.text().contains("从 1 开始"));
}
