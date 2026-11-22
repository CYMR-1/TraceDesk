//! 10 节 Markdown 取证报告渲染器（对应 `core-contract.md` §2.4，
//! 逐节逐列与 `forensic/core/reporting.py` 保持一致）。

use std::collections::HashMap;

use serde_json::Value;

use crate::case::CaseData;
use crate::coverage::{SOURCE_FIELDS, coverage_text, source_status};
use crate::findings::{
    AuditOrigin, AuditRecord, action_title, audit_origin, audit_origin_label, group_findings,
    operation_title,
};
use crate::formatting::{
    deleted_export_summary, display_iso_time, display_timestamp, entry_status, format_commas,
    format_size, now,
};

fn cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn value_as_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn value_is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_i64() != Some(0) && n.as_u64() != Some(0),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// 渲染完整的 10 节 Markdown 取证报告（`reports/report_<12hex>.md`）。
pub fn render_report(data: &CaseData, records: &[AuditRecord], conclusion: &str) -> String {
    let evidence = data
        .evidence
        .as_ref()
        .expect("render_report requires loaded evidence");
    let inventory = &data.inventory;
    let exports = &data.exports;
    let groups = group_findings(records);
    let searches: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| r.action == "CONTENT_SEARCH")
        .collect();

    let active_files = inventory
        .iter()
        .filter(|row| !row.deleted && !row.directory)
        .count() as u64;
    let deleted_items = inventory.iter().filter(|row| row.deleted).count() as u64;
    let directories = inventory.iter().filter(|row| row.directory).count() as u64;

    let mut lines: Vec<String> = vec![
        "# 电子数据取证报告".to_string(),
        String::new(),
        format!(
            "> 生成时间（UTC+8）：{} · 工作模式：应用层只读",
            display_iso_time(&now(), true)
        ),
        String::new(),
        "## 案件信息".to_string(),
        String::new(),
        "| 项目 | 内容 |".to_string(),
        "| --- | --- |".to_string(),
        format!("| 案件编号 | {} |", cell(&data.number)),
        format!("| 取证人员 | {} |", cell(&data.examiner)),
        format!("| 取证对象 | {} |", cell(&data.target)),
        format!(
            "| 案件建立时间（UTC+8） | {} |",
            display_iso_time(&data.created, false)
        ),
        format!(
            "| 核心统计 | {} 个分区 · 清单 {} 项 · 内容搜索 {} 次 · 导出副本 {} 个 · 取证发现 {} 个文件 · 审计记录 {} 条 |",
            evidence.partitions.len(),
            format_commas(inventory.len() as u64),
            searches.len(),
            exports.len(),
            groups.len(),
            records.len()
        ),
        String::new(),
        "## 原始证据与完整性".to_string(),
        String::new(),
        format!("> **完整性校验结论**：{}", cell(conclusion)),
        String::new(),
        "| 校验与来源项 | 内容 |".to_string(),
        "| --- | --- |".to_string(),
        format!("| 镜像路径 | `{}` |", cell(&evidence.path)),
        format!("| 镜像格式 | {} |", cell(evidence.format_label())),
        format!("| 逻辑介质大小 | {} |", format_size(evidence.size)),
    ];

    if evidence.is_ewf()
        && let Some(ref segs) = evidence.segments
        && !segs.is_empty()
    {
        let encap_size: u64 = segs.iter().map(|s| s.size).sum();
        lines.push(format!(
            "| EWF 分段封装 | 共 {} 段 · 封装总大小 {} |",
            segs.len(),
            format_size(encap_size)
        ));
    }

    let actual_label = if evidence.is_ewf() {
        "已核验分段对应的逻辑摘要（本次未重新解码）"
    } else {
        "当前复算 SHA-256"
    };
    let initial_sha = evidence
        .sha256
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("待固定");
    let verification = data.verification.as_ref();
    let actual_sha = verification
        .and_then(|v| v.actual.as_deref())
        .filter(|s| !s.is_empty())
        .unwrap_or("无法确认");
    let verify_time = verification
        .map(|v| display_iso_time(&v.time, false))
        .unwrap_or_default();
    let verify_method = verification
        .map(|v| v.method.as_str())
        .unwrap_or("复算 RAW SHA-256");

    lines.push(format!("| 初始逻辑介质 SHA-256 | `{initial_sha}` |"));
    lines.push(format!("| {actual_label} | `{actual_sha}` |"));
    lines.push(format!("| 完整读取时间（UTC+8） | {verify_time} |"));
    lines.push(format!("| 校验方式 | {} |", cell(verify_method)));
    lines.push(format!(
        "| 声明范围判定 | {} |",
        cell(&coverage_text(evidence.coverage.as_ref()))
    ));
    lines.push(format!(
        "| 交付方摘要比对 | {} |",
        cell(source_status(evidence))
    ));

    for &(key, label) in &SOURCE_FIELDS {
        let val = evidence
            .provenance
            .as_ref()
            .map(|p| p.get_field(key))
            .filter(|s| !s.is_empty())
            .unwrap_or("未登记");
        lines.push(format!("| {label} | {} |", cell(val)));
    }

    // 第 4 节：文件清单摘要
    lines.push(String::new());
    lines.push("## 文件清单摘要".to_string());
    lines.push(String::new());
    lines.push(format!(
        "已识别 **{}** 个分区，当前清单共 **{}** 项（现存文件 {} 项 · 已删除记录 {} 项 · 目录 {} 项；下方最多展示前 200 项）。",
        evidence.partitions.len(),
        format_commas(inventory.len() as u64),
        format_commas(active_files),
        format_commas(deleted_items),
        format_commas(directories)
    ));

    if let Some(ref idx_ver) = data.index_verification
        && !idx_ver.is_empty()
    {
        lines.push(String::new());
        lines.push(format!("- 建立清单时的完整性状态：{}", cell(idx_ver)));
    }

    let scans_map: HashMap<u64, _> = data
        .partition_scans
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| (s.offset, s))
        .collect();

    lines.push(String::new());
    lines.push("### 分区概览".to_string());
    lines.push(String::new());
    lines.push("| 分区偏移（扇区） | 分区说明 | 扫描状态 |".to_string());
    lines.push("| ---: | --- | --- |".to_string());
    for part in &evidence.partitions {
        let state = match scans_map.get(&part.offset) {
            Some(scan) if scan.status == "ready" => {
                format!("已读取 {} 项", format_commas(scan.count as u64))
            }
            Some(scan) => format!("无法读取：{}", scan.error.as_deref().unwrap_or("")),
            None => "未完成全部分区读取".to_string(),
        };
        lines.push(format!(
            "| {} | {} | {} |",
            part.offset,
            cell(&part.description),
            cell(&state)
        ));
    }

    if !inventory.is_empty() {
        lines.push(String::new());
        lines.push("### 文件清单抽样（前 200 项）".to_string());
        lines.push(String::new());
        lines.push(
            "| 分区偏移 | 路径 | 状态 | inode | 字节数 | M (UTC+8) | A (UTC+8) | C (UTC+8) | B (UTC+8) |"
                .to_string(),
        );
        lines.push("| ---: | --- | --- | --- | ---: | --- | --- | --- | --- |".to_string());
        for row in inventory.iter().take(200) {
            let fields = [
                row.offset.to_string(),
                row.path.clone(),
                entry_status(row).to_string(),
                row.inode.clone(),
                row.size.to_string(),
                display_timestamp(row.mtime, true),
                display_timestamp(row.atime, true),
                display_timestamp(row.ctime, true),
                display_timestamp(row.crtime, true),
            ];
            let cells: Vec<String> = fields.iter().map(|s| cell(s)).collect();
            lines.push(format!("| {} |", cells.join(" | ")));
        }
    } else {
        lines.push(String::new());
        lines.push("尚未建立完整文件清单。".to_string());
    }

    // 第 5 节：导出副本
    lines.push(String::new());
    lines.push("## 导出副本".to_string());
    lines.push(String::new());
    if !exports.is_empty() {
        lines.push("| 序号 | 分区偏移 | 镜像内路径 | 导出路径 | 字节数 | SHA-256 | 说明 |".to_string());
        lines.push("| ---: | ---: | --- | --- | ---: | --- | --- |".to_string());
        for (idx, row) in exports.iter().enumerate() {
            let mut notes: Vec<String> = Vec::new();
            if let Some(ref sv) = row.source_verification
                && !sv.is_empty()
            {
                notes.push(format!("完整性状态：{sv}"));
            }
            if row.deleted == Some(true) {
                notes.push(deleted_export_summary(row));
            }
            let note_str = if notes.is_empty() {
                "正常导出".to_string()
            } else {
                notes.join("；")
            };
            lines.push(format!(
                "| {} | {} | {} | {} | {} | `{}` | {} |",
                idx + 1,
                row.offset,
                cell(&row.source),
                cell(&row.path),
                cell(&format_commas(row.size)),
                row.sha256,
                cell(&note_str)
            ));
        }
    } else {
        lines.push("本案件尚未导出文件副本。".to_string());
    }

    // 第 6 节：内容搜索记录（可选，仅在存在搜索记录时输出）
    if !searches.is_empty() {
        lines.push(String::new());
        lines.push("## 内容搜索记录".to_string());
        lines.push(String::new());
        lines.push(
            "| 序号 | 时间 (UTC+8) | 搜索内容 | 编码 | 状态 | 已处理/总数 | 命中数 | 失败数 | 详情清单 |"
                .to_string(),
        );
        lines.push("| ---: | --- | --- | --- | --- | --- | ---: | ---: | --- |".to_string());
        for (idx, row) in searches.iter().enumerate() {
            let d = &row.details;
            let visited = d.get("visited").and_then(Value::as_u64).unwrap_or(0);
            let eligible = d.get("eligible").and_then(Value::as_u64).unwrap_or(0);
            let query = d.get("query").and_then(Value::as_str).unwrap_or("");
            let encoding = d.get("encoding").and_then(Value::as_str).unwrap_or("");
            let hits = d.get("hits").and_then(Value::as_u64).unwrap_or(0);
            let failed = d.get("failed").and_then(Value::as_u64).unwrap_or(0);
            let fields = [
                (idx + 1).to_string(),
                display_iso_time(&row.timestamp, true),
                query.to_string(),
                encoding.to_string(),
                row.result.clone(),
                format!("{}/{}", format_commas(visited), format_commas(eligible)),
                hits.to_string(),
                failed.to_string(),
                format!("reports/{}", row.subject),
            ];
            let cells: Vec<String> = fields.iter().map(|s| cell(s)).collect();
            lines.push(format!("| {} |", cells.join(" | ")));
        }
    }

    // 第 7 节：文件取证发现（可选，仅在存在取证发现时输出）
    if !groups.is_empty() {
        lines.push(String::new());
        lines.push("## 文件取证发现".to_string());
        lines.push(String::new());
        lines.push(format!(
            "共涉及 **{}** 个文件，均来自已通过哈希链校验的操作记录。",
            groups.len()
        ));
        lines.push(String::new());
        lines.push("| 序号 | 镜像内路径 | 状态 | 分区偏移 | inode | 记录数 | 最近记录 (UTC+8) |".to_string());
        lines.push("| ---: | --- | --- | ---: | --- | ---: | --- |".to_string());
        for (idx, group) in groups.iter().enumerate() {
            let status = if group.key.deleted { "已删除" } else { "现存" };
            let latest = group
                .records
                .last()
                .map(|r| display_iso_time(&r.timestamp, true))
                .unwrap_or_default();
            let fields = [
                (idx + 1).to_string(),
                group.key.subject.clone(),
                status.to_string(),
                group.key.offset.to_string(),
                group.key.inode.clone(),
                group.records.len().to_string(),
                latest,
            ];
            let cells: Vec<String> = fields.iter().map(|s| cell(s)).collect();
            lines.push(format!("| {} |", cells.join(" | ")));
        }

        for (idx, group) in groups.iter().enumerate() {
            let status = if group.key.deleted { "已删除" } else { "现存" };
            let image_hash = group
                .key
                .image_sha256
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("记录时待固定");
            lines.push(String::new());
            lines.push(format!("### {}. {}", idx + 1, cell(&group.key.subject)));
            lines.push(String::new());
            lines.push(format!(
                "- **文件定位**：分区偏移 {} 扇区 · inode `{}` · 状态：{status}",
                group.key.offset,
                cell(&group.key.inode)
            ));
            lines.push(format!("- **来源镜像 SHA-256**：`{image_hash}`"));
            for r in &group.records {
                let d = &r.details;
                let op = operation_title(&r.action).unwrap_or(&r.action);
                lines.push(format!(
                    "- **`#{}` {}** · [{}] · {} · {} · **{}**",
                    r.seq,
                    display_iso_time(&r.timestamp, true),
                    cell(&audit_origin_label(r)),
                    cell(&r.actor),
                    op,
                    cell(&r.result)
                ));
                if let Some(size) = d.get("size").and_then(Value::as_u64) {
                    let recorded = d
                        .get("recorded_size")
                        .and_then(Value::as_u64)
                        .unwrap_or(size);
                    lines.push(format!(
                        "  - 读取长度：{} / {} 字节",
                        format_commas(size),
                        format_commas(recorded)
                    ));
                }
                if let Some(fb) = d.get("file_byte").and_then(Value::as_u64) {
                    lines.push(format!("  - 命中字节偏移：`{fb}`（`0x{fb:X}`）"));
                }
                for &(key, label) in &[
                    ("note", "笔记"),
                    ("sha256", "读取内容 SHA-256"),
                    ("comparison", "对照文件"),
                    ("comparison_sha256", "对照 SHA-256"),
                    ("before", "前文 HEX"),
                    ("after", "后文 HEX"),
                    ("search_record", "关联搜索记录"),
                    ("source_note", "来源状态"),
                    ("source_verification", "操作时的完整性状态"),
                    ("read_note", "读取说明"),
                    ("error", "错误"),
                ] {
                    if let Some(v) = d.get(key)
                        && value_is_truthy(v)
                    {
                        let disp = value_as_display(v);
                        let formatted = if matches!(
                            key,
                            "sha256" | "comparison_sha256" | "before" | "after"
                        ) {
                            format!("`{}`", cell(&disp))
                        } else {
                            cell(&disp)
                        };
                        lines.push(format!("  - {label}：{formatted}"));
                    }
                }
            }
        }
    }

    // 第 8 节：审计日志摘要（最近 100 条）
    let shown_start = records.len().saturating_sub(100);
    let shown_audit = &records[shown_start..];
    let mcp_count = records
        .iter()
        .filter(|r| audit_origin(r) == AuditOrigin::Mcp)
        .count();
    let manual_count = records.len() - mcp_count;
    let tail_hash = records.last().map(|r| r.hash.as_str()).unwrap_or("");
    let trunc_note = if records.len() > shown_audit.len() {
        format!("（下方展示最近 {} 条）", shown_audit.len())
    } else {
        String::new()
    };

    lines.push(String::new());
    lines.push("## 审计日志摘要".to_string());
    lines.push(String::new());
    lines.push(format!(
        "审计链验证通过；共 **{}** 条记录（人工 {manual_count} 条 · MCP {mcp_count} 条）{trunc_note}；尾部哈希锚点：`{tail_hash}`。",
        records.len()
    ));
    lines.push(String::new());
    lines.push("| 序号 | 时间 (UTC+8) | 来源 | 操作人员 | 操作 | 对象 | 结果 |".to_string());
    lines.push("| ---: | --- | --- | --- | --- | --- | --- |".to_string());
    for row in shown_audit {
        let fields = [
            row.seq.to_string(),
            display_iso_time(&row.timestamp, false),
            audit_origin_label(row),
            row.actor.clone(),
            action_title(&row.action).to_string(),
            row.subject.clone(),
            row.result.clone(),
        ];
        let cells: Vec<String> = fields.iter().map(|s| cell(s)).collect();
        lines.push(format!("| {} |", cells.join(" | ")));
    }

    // 第 9 节：取证人员确认
    lines.push(String::new());
    lines.push("## 取证人员确认".to_string());
    lines.push(String::new());
    lines.push("| 角色 | 签名 | 日期 |".to_string());
    lines.push("| --- | --- | --- |".to_string());
    lines.push("| 取证人员 | ________________ | ________________ |".to_string());
    lines.push("| 复核人员 | ________________ | ________________ |".to_string());

    // 第 10 节：适用边界
    lines.push(String::new());
    lines.push("## 适用边界".to_string());
    lines.push(String::new());
    lines.push(
        "- 本工具为教学原型，实施应用层只读约束，不替代硬件写保护器或法定资质认证。".to_string(),
    );
    lines.push(
        "- MACB 时间来自文件系统元数据，可能被修改；C 表示元数据变更时间，并非通用的创建时间。"
            .to_string(),
    );
    lines.push(
        "- 日志哈希链和本地锚点可发现意外修改或单独截断，不能抵抗同时重写全部案件数据的攻击者。"
            .to_string(),
    );
    lines.push(
        "- 案件库与镜像位于独立目录；若要求不同物理介质，需由操作人员另行安排。".to_string(),
    );
    lines.push(String::new());

    lines.join("\n")
}
