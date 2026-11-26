//! 10 节 Markdown 取证报告与离线自包含单文件 HTML 取证报告渲染器
//! （对应 `core-contract.md` §2.4，兼容既有 Markdown 报告结构并增强抽样、EWF 分段明细与人工/MCP 协同统计）。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracedesk_engines::{InventoryEntry, TskCli};

use crate::case::{Case, CaseData, EvidenceInfo, PartitionScan};
use crate::coverage::{SOURCE_FIELDS, coverage_text, source_status};
use crate::error::CoreResult;
use crate::findings::{
    AuditOrigin, AuditRecord, FindingGroup, action_title, audit_mcp_user, audit_origin,
    audit_origin_label, group_findings, operation_title,
};
use crate::formatting::{
    deleted_export_summary, display_iso_time, display_timestamp, entry_status, format_commas,
    format_size, now,
};

/// 文件清单抽样上限。
const INVENTORY_SAMPLE_LIMIT: usize = 200;
/// 审计日志摘要完整展示阈值；超过该数量时采用“首 20 条基线 + 末 80 条”。
const AUDIT_SUMMARY_LIMIT: usize = 100;
const AUDIT_HEAD_COUNT: usize = 20;
const AUDIT_TAIL_COUNT: usize = 80;

/// 生成离线单文件 HTML 取证报告的返回结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HtmlReportResult {
    /// 写入磁盘后的 HTML 报告绝对路径（`reports/report_<timestamp>_<6hex>.html`）。
    pub path: PathBuf,
    /// HTML 文件原始 UTF-8 字节的 64 位小写十六进制 SHA-256 摘要。
    pub sha256: String,
    /// HTML 文件字节数。
    pub bytes: u64,
    /// 报告生成时间（UTC+8 ISO-8601）。
    pub generated_at: String,
}

/// 单个操作员或 MCP 调用方的协同取证统计明细。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollabCallerStat {
    /// 归一化后的操作员或 MCP 调用方标识。
    pub name: String,
    /// 该调用方触发的审计操作总次数。
    pub audit_ops: usize,
    /// 该调用方记录的取证发现次数（`FILE_NOTE` / `FILE_HASH` / `FILE_COMPARE`）。
    pub finding_ops: usize,
}

/// 人工与 MCP 协同取证统计概览（Markdown 与 HTML 报告同源使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollaborationStats {
    /// 审计记录总数。
    pub total_audit_ops: usize,
    /// 人工审计操作次数。
    pub manual_audit_ops: usize,
    /// MCP 审计操作次数。
    pub mcp_audit_ops: usize,
    /// 人工产生的取证发现记录条数。
    pub manual_finding_ops: usize,
    /// MCP 产生的取证发现记录条数。
    pub mcp_finding_ops: usize,
    /// 人工涉及的去重取证发现文件数。
    pub manual_finding_files: usize,
    /// MCP 涉及的去重取证发现文件数。
    pub mcp_finding_files: usize,
    /// 人工活跃操作员明细（按操作数降序、名称升序排列）。
    pub manual_actors: Vec<CollabCallerStat>,
    /// MCP 活跃调用方明细（按操作数降序、名称升序排列）。
    pub mcp_callers: Vec<CollabCallerStat>,
}

/// 抽样后的单条文件清单记录及其优先级标注。
struct SampledInventoryItem<'a> {
    entry: &'a InventoryEntry,
    tags: Vec<&'static str>,
}

/// 审计日志摘要抽样视图（全部或“首 20 条基线 + 中间省略 + 末 80 条”）。
struct AuditSampleView<'a> {
    head: &'a [AuditRecord],
    tail: &'a [AuditRecord],
    omitted: usize,
}

/// Markdown 与 HTML 报告共用的同源结构化案件数据模型。
struct ReportModel<'a> {
    data: &'a CaseData,
    evidence: &'a EvidenceInfo,
    records: &'a [AuditRecord],
    conclusion: &'a str,
    generated_at: String,
    groups: Vec<FindingGroup>,
    searches: Vec<&'a AuditRecord>,
    active_files: u64,
    deleted_items: u64,
    directories: u64,
    scans_map: HashMap<u64, &'a PartitionScan>,
    sampled_inventory: Vec<SampledInventoryItem<'a>>,
    priority_sampled_count: usize,
    collab: CollaborationStats,
    audit_view: AuditSampleView<'a>,
    tail_hash: &'a str,
}

fn cell(value: &str) -> String {
    value
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// 对 HTML 文本和属性值执行严格转义，防止注入与 XSS。
pub fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
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

fn fallback_evidence() -> EvidenceInfo {
    EvidenceInfo {
        path: String::new(),
        size: 0,
        sha256: None,
        fixed_at: None,
        partitions: Vec::new(),
        layout: String::new(),
        format: None,
        large_image: None,
        opened_at: None,
        source_stamp: None,
        segments: None,
        provenance: None,
        coverage: None,
    }
}

/// 统计人工与 MCP 协同取证操作次数、活跃调用方与取证发现数。
pub fn compute_collaboration_stats(records: &[AuditRecord]) -> CollaborationStats {
    let mut manual_audit_ops = 0usize;
    let mut mcp_audit_ops = 0usize;
    let mut manual_finding_ops = 0usize;
    let mut mcp_finding_ops = 0usize;

    let mut manual_files: HashSet<(String, u64, String, bool)> = HashSet::new();
    let mut mcp_files: HashSet<(String, u64, String, bool)> = HashSet::new();

    let mut manual_map: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut mcp_map: BTreeMap<String, (usize, usize)> = BTreeMap::new();

    for rec in records {
        let is_finding = operation_title(&rec.action).is_some();
        let finding_key = if is_finding {
            let offset = rec.details.get("offset").and_then(Value::as_u64).unwrap_or(0);
            let inode = rec
                .details
                .get("inode")
                .map(value_as_display)
                .unwrap_or_default();
            let deleted = rec
                .details
                .get("deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Some((rec.subject.clone(), offset, inode, deleted))
        } else {
            None
        };

        match audit_origin(rec) {
            AuditOrigin::Manual => {
                manual_audit_ops += 1;
                let actor_name = if rec.actor.trim().is_empty() {
                    "未署名操作员".to_string()
                } else {
                    rec.actor.trim().to_string()
                };
                let entry = manual_map.entry(actor_name).or_insert((0, 0));
                entry.0 += 1;
                if let Some(key) = finding_key {
                    manual_finding_ops += 1;
                    entry.1 += 1;
                    manual_files.insert(key);
                }
            }
            AuditOrigin::Mcp => {
                mcp_audit_ops += 1;
                let caller_name = audit_mcp_user(rec).unwrap_or_else(|| {
                    let trimmed = rec.actor.trim();
                    if trimmed.is_empty() {
                        "MCP 客户端".to_string()
                    } else {
                        trimmed.to_string()
                    }
                });
                let entry = mcp_map.entry(caller_name).or_insert((0, 0));
                entry.0 += 1;
                if let Some(key) = finding_key {
                    mcp_finding_ops += 1;
                    entry.1 += 1;
                    mcp_files.insert(key);
                }
            }
        }
    }

    let to_sorted_vec = |map: BTreeMap<String, (usize, usize)>| -> Vec<CollabCallerStat> {
        let mut list: Vec<CollabCallerStat> = map
            .into_iter()
            .map(|(name, (audit_ops, finding_ops))| CollabCallerStat {
                name,
                audit_ops,
                finding_ops,
            })
            .collect();
        list.sort_by(|a, b| b.audit_ops.cmp(&a.audit_ops).then_with(|| a.name.cmp(&b.name)));
        list
    };

    CollaborationStats {
        total_audit_ops: records.len(),
        manual_audit_ops,
        mcp_audit_ops,
        manual_finding_ops,
        mcp_finding_ops,
        manual_finding_files: manual_files.len(),
        mcp_finding_files: mcp_files.len(),
        manual_actors: to_sorted_vec(manual_map),
        mcp_callers: to_sorted_vec(mcp_map),
    }
}

/// 按取证相关性对文件清单抽样（最多 200 项）：
/// 优先纳入“有取证发现 / 已导出 / 已删除”条目，再按清单顺序补足常规文件与其他条目。
fn sample_inventory<'a>(
    inventory: &'a [InventoryEntry],
    exports: &[crate::case::ExportRecord],
    groups: &[FindingGroup],
) -> (Vec<SampledInventoryItem<'a>>, usize) {
    if inventory.is_empty() {
        return (Vec::new(), 0);
    }

    let finding_keys: HashSet<(&str, u64, &str, bool)> = groups
        .iter()
        .map(|g| {
            (
                g.key.subject.as_str(),
                g.key.offset,
                g.key.inode.as_str(),
                g.key.deleted,
            )
        })
        .collect();
    let export_keys: HashSet<(&str, u64, &str)> = exports
        .iter()
        .map(|e| (e.source.as_str(), e.offset, e.inode.as_str()))
        .collect();

    let mut tier_finding: Vec<SampledInventoryItem<'a>> = Vec::new();
    let mut tier_exported: Vec<SampledInventoryItem<'a>> = Vec::new();
    let mut tier_deleted: Vec<SampledInventoryItem<'a>> = Vec::new();
    let mut tier_regular_file: Vec<SampledInventoryItem<'a>> = Vec::new();
    let mut tier_other: Vec<SampledInventoryItem<'a>> = Vec::new();

    for row in inventory {
        let is_finding =
            finding_keys.contains(&(row.path.as_str(), row.offset, row.inode.as_str(), row.deleted));
        let is_exported =
            export_keys.contains(&(row.path.as_str(), row.offset, row.inode.as_str()));
        let is_deleted = row.deleted;

        let mut tags = Vec::new();
        if is_finding {
            tags.push("取证发现");
        }
        if is_exported {
            tags.push("已导出");
        }
        if is_deleted {
            tags.push("已删除");
        }

        let item = SampledInventoryItem { entry: row, tags };
        if is_finding {
            tier_finding.push(item);
        } else if is_exported {
            tier_exported.push(item);
        } else if is_deleted {
            tier_deleted.push(item);
        } else if !row.directory && !row.mode.starts_with("v/") && !row.mode.starts_with("V/") {
            tier_regular_file.push(item);
        } else {
            tier_other.push(item);
        }
    }

    let mut result = Vec::with_capacity(inventory.len().min(INVENTORY_SAMPLE_LIMIT));
    let mut priority_count = 0usize;

    for item in tier_finding
        .into_iter()
        .chain(tier_exported)
        .chain(tier_deleted)
    {
        if result.len() >= INVENTORY_SAMPLE_LIMIT {
            break;
        }
        priority_count += 1;
        result.push(item);
    }

    for item in tier_regular_file.into_iter().chain(tier_other) {
        if result.len() >= INVENTORY_SAMPLE_LIMIT {
            break;
        }
        result.push(item);
    }

    (result, priority_count)
}

/// 构造审计日志摘要视图：不超过 100 条时全量展示，超过 100 条时展示“首 20 条基线 + 末 80 条”。
fn build_audit_view(records: &[AuditRecord]) -> AuditSampleView<'_> {
    if records.len() <= AUDIT_SUMMARY_LIMIT {
        AuditSampleView {
            head: records,
            tail: &[],
            omitted: 0,
        }
    } else {
        let omitted = records.len() - (AUDIT_HEAD_COUNT + AUDIT_TAIL_COUNT);
        AuditSampleView {
            head: &records[..AUDIT_HEAD_COUNT],
            tail: &records[records.len() - AUDIT_TAIL_COUNT..],
            omitted,
        }
    }
}

fn build_report_model<'a>(
    data: &'a CaseData,
    evidence: &'a EvidenceInfo,
    records: &'a [AuditRecord],
    conclusion: &'a str,
    generated_at: String,
) -> ReportModel<'a> {
    let groups = group_findings(records);
    let searches: Vec<&AuditRecord> = records
        .iter()
        .filter(|r| r.action == "CONTENT_SEARCH")
        .collect();
    let active_files = data
        .inventory
        .iter()
        .filter(|row| !row.deleted && !row.directory)
        .count() as u64;
    let deleted_items = data.inventory.iter().filter(|row| row.deleted).count() as u64;
    let directories = data.inventory.iter().filter(|row| row.directory).count() as u64;
    let scans_map: HashMap<u64, &PartitionScan> = data
        .partition_scans
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|s| (s.offset, s))
        .collect();
    let (sampled_inventory, priority_sampled_count) =
        sample_inventory(&data.inventory, &data.exports, &groups);
    let collab = compute_collaboration_stats(records);
    let audit_view = build_audit_view(records);
    let tail_hash = records.last().map(|r| r.hash.as_str()).unwrap_or("");

    ReportModel {
        data,
        evidence,
        records,
        conclusion,
        generated_at,
        groups,
        searches,
        active_files,
        deleted_items,
        directories,
        scans_map,
        sampled_inventory,
        priority_sampled_count,
        collab,
        audit_view,
        tail_hash,
    }
}

fn format_percent(part: usize, total: usize) -> String {
    if total == 0 {
        "0.0%".to_string()
    } else {
        format!("{:.1}%", (part as f64) * 100.0 / (total as f64))
    }
}

fn format_callers_summary(callers: &[CollabCallerStat]) -> String {
    if callers.is_empty() {
        "无".to_string()
    } else {
        callers
            .iter()
            .map(|c| {
                if c.finding_ops > 0 {
                    format!("{}（{} 次操作 / {} 条发现）", c.name, c.audit_ops, c.finding_ops)
                } else {
                    format!("{}（{} 次操作）", c.name, c.audit_ops)
                }
            })
            .collect::<Vec<_>>()
            .join("、")
    }
}

/// 渲染完整的 10 节 Markdown 取证报告（`reports/report_<12hex>.md`）。
pub fn render_report(data: &CaseData, records: &[AuditRecord], conclusion: &str) -> String {
    let fallback = fallback_evidence();
    let evidence = data.evidence.as_ref().unwrap_or(&fallback);
    let model = build_report_model(data, evidence, records, conclusion, now());
    render_markdown_from_model(&model)
}

/// 渲染离线自包含单文件 HTML 取证报告（使用当前 UTC+8 时间戳）。
pub fn render_html_report(data: &CaseData, records: &[AuditRecord], conclusion: &str) -> String {
    render_html_report_with_time(data, records, conclusion, &now())
}

/// 渲染离线自包含单文件 HTML 取证报告（允许指定生成时间，便于案件持久化与单测校验）。
pub fn render_html_report_with_time(
    data: &CaseData,
    records: &[AuditRecord],
    conclusion: &str,
    generated_at: &str,
) -> String {
    let fallback = fallback_evidence();
    let evidence = data.evidence.as_ref().unwrap_or(&fallback);
    let model = build_report_model(data, evidence, records, conclusion, generated_at.to_string());
    render_html_from_model(&model)
}

/// 便捷自由函数入口：委托 [`Case::generate_html_report`] 校验完整性并写出离线 HTML 报告。
pub fn generate_html_report(case: &mut Case, tsk: Option<&TskCli>) -> CoreResult<HtmlReportResult> {
    case.generate_html_report(tsk)
}

fn render_markdown_from_model(m: &ReportModel<'_>) -> String {
    let data = m.data;
    let evidence = m.evidence;
    let inventory = &data.inventory;
    let exports = &data.exports;
    let groups = &m.groups;
    let searches = &m.searches;
    let records = m.records;

    let mut lines: Vec<String> = vec![
        "# 电子数据取证报告".to_string(),
        String::new(),
        format!(
            "> 生成时间（UTC+8）：{} · 工作模式：应用层只读",
            display_iso_time(&m.generated_at, true)
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
    ];

    // 人工 vs MCP 协同取证统计概览
    lines.push(String::new());
    lines.push("### 人工与 MCP 协同取证统计".to_string());
    lines.push(String::new());
    lines.push("| 协同来源 | 审计操作数 | 占比 | 取证发现记录 | 涉及发现文件 | 活跃操作员 / 调用方 |".to_string());
    lines.push("| --- | ---: | ---: | ---: | ---: | --- |".to_string());
    lines.push(format!(
        "| 人工 | {} | {} | {} | {} | {} |",
        m.collab.manual_audit_ops,
        format_percent(m.collab.manual_audit_ops, m.collab.total_audit_ops),
        m.collab.manual_finding_ops,
        m.collab.manual_finding_files,
        cell(&format_callers_summary(&m.collab.manual_actors))
    ));
    lines.push(format!(
        "| MCP | {} | {} | {} | {} | {} |",
        m.collab.mcp_audit_ops,
        format_percent(m.collab.mcp_audit_ops, m.collab.total_audit_ops),
        m.collab.mcp_finding_ops,
        m.collab.mcp_finding_files,
        cell(&format_callers_summary(&m.collab.mcp_callers))
    ));

    lines.push(String::new());
    lines.push("## 原始证据与完整性".to_string());
    lines.push(String::new());
    lines.push(format!("> **完整性校验结论**：{}", cell(m.conclusion)));
    lines.push(String::new());
    lines.push("| 校验与来源项 | 内容 |".to_string());
    lines.push("| --- | --- |".to_string());
    lines.push(format!("| 镜像路径 | `{}` |", cell(&evidence.path)));
    lines.push(format!("| 镜像格式 | {} |", cell(evidence.format_label())));
    lines.push(format!("| 逻辑介质大小 | {} |", format_size(evidence.size)));

    if let Some(ref segs) = evidence.segments
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

    // EWF 逐段 SHA-256 明细表（只要 evidence.segments 非空即输出）
    if let Some(ref segs) = evidence.segments
        && !segs.is_empty()
    {
        lines.push(String::new());
        lines.push("### EWF 分段 SHA-256 明细".to_string());
        lines.push(String::new());
        lines.push("| 段序 | 分段文件名 | 分段大小 | 分段 SHA-256 |".to_string());
        lines.push("| ---: | --- | ---: | --- |".to_string());
        for (idx, seg) in segs.iter().enumerate() {
            let seg_sha = if seg.sha256.trim().is_empty() {
                "待计算"
            } else {
                seg.sha256.as_str()
            };
            lines.push(format!(
                "| {} | {} | {} | `{}` |",
                idx + 1,
                cell(&seg.name),
                cell(&format_size(seg.size)),
                cell(seg_sha)
            ));
        }
    }

    // 第 4 节：文件清单摘要
    lines.push(String::new());
    lines.push("## 文件清单摘要".to_string());
    lines.push(String::new());
    lines.push(format!(
        "已识别 **{}** 个分区，当前清单共 **{}** 项（现存文件 {} 项 · 已删除记录 {} 项 · 目录 {} 项；下方抽样展示 {} 项，优先纳入取证发现/已导出/已删除条目 {} 项）。",
        evidence.partitions.len(),
        format_commas(inventory.len() as u64),
        format_commas(m.active_files),
        format_commas(m.deleted_items),
        format_commas(m.directories),
        m.sampled_inventory.len(),
        m.priority_sampled_count
    ));

    if let Some(ref idx_ver) = data.index_verification
        && !idx_ver.is_empty()
    {
        lines.push(String::new());
        lines.push(format!("- 建立清单时的完整性状态：{}", cell(idx_ver)));
    }

    lines.push(String::new());
    lines.push("### 分区概览".to_string());
    lines.push(String::new());
    lines.push("| 分区偏移（扇区） | 分区说明 | 扫描状态 |".to_string());
    lines.push("| ---: | --- | --- |".to_string());
    for part in &evidence.partitions {
        let state = match m.scans_map.get(&part.offset) {
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

    if !m.sampled_inventory.is_empty() {
        lines.push(String::new());
        // 保持既有标题字面量，兼容跨语言及既有集成测试断言。
        lines.push("### 文件清单抽样（前 200 项）".to_string());
        lines.push(String::new());
        lines.push(
            "> 抽样策略：优先纳入存在取证发现、已导出副本及已删除状态的条目，再按清单顺序补足至最多 200 项。".to_string(),
        );
        lines.push(String::new());
        lines.push(
            "| 分区偏移 | 路径 | 状态 | 关注标签 | inode | 字节数 | M (UTC+8) | A (UTC+8) | C (UTC+8) | B (UTC+8) |"
                .to_string(),
        );
        lines.push("| ---: | --- | --- | --- | --- | ---: | --- | --- | --- | --- |".to_string());
        for item in &m.sampled_inventory {
            let row = item.entry;
            let tag_text = if item.tags.is_empty() {
                "—".to_string()
            } else {
                item.tags.join(" · ")
            };
            let fields = [
                row.offset.to_string(),
                row.path.clone(),
                entry_status(row).to_string(),
                tag_text,
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

    // 第 8 节：审计日志摘要（超过 100 条采用“首 20 条基线 + 末 80 条”）
    let trunc_note = if m.audit_view.omitted > 0 {
        format!(
            "（下方展示首 {} 条基线与末 {} 条记录，中间省略 {} 条）",
            m.audit_view.head.len(),
            m.audit_view.tail.len(),
            m.audit_view.omitted
        )
    } else {
        String::new()
    };

    lines.push(String::new());
    lines.push("## 审计日志摘要".to_string());
    lines.push(String::new());
    lines.push(format!(
        "审计链验证通过；共 **{}** 条记录（人工 {} 条 · MCP {} 条）{trunc_note}；尾部哈希锚点：`{}`。",
        records.len(),
        m.collab.manual_audit_ops,
        m.collab.mcp_audit_ops,
        m.tail_hash
    ));
    lines.push(String::new());
    lines.push("| 序号 | 时间 (UTC+8) | 来源 | 操作人员 | 操作 | 对象 | 结果 |".to_string());
    lines.push("| ---: | --- | --- | --- | --- | --- | --- |".to_string());

    let push_audit_row = |lines: &mut Vec<String>, row: &AuditRecord| {
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
    };

    for row in m.audit_view.head {
        push_audit_row(&mut lines, row);
    }
    if m.audit_view.omitted > 0 {
        let omitted_start = m.audit_view.head.last().map(|r| r.seq + 1).unwrap_or(21);
        let omitted_end = m
            .audit_view
            .tail
            .first()
            .map(|r| r.seq.saturating_sub(1))
            .unwrap_or(omitted_start + m.audit_view.omitted as u64 - 1);
        lines.push(format!(
            "| … | — | — | — | 已省略中间 {} 条记录 | 第 #{} 至 #{} 条（完整明细见 audit.jsonl） | 省略 |",
            m.audit_view.omitted, omitted_start, omitted_end
        ));
        for row in m.audit_view.tail {
            push_audit_row(&mut lines, row);
        }
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

/// 根据完整性校验结论推断语义徽章样式类与简短标签。
fn integrity_badge(conclusion: &str, ok_hint: Option<bool>) -> (&'static str, &'static str) {
    if conclusion.contains("不通过") || conclusion.contains("不一致") || ok_hint == Some(false) {
        ("badge-danger", "完整性异常")
    } else if conclusion.contains("通过") || ok_hint == Some(true) {
        ("badge-ok", "完整性通过")
    } else {
        ("badge-warn", "待复核确认")
    }
}

/// 根据卷声明覆盖范围评估结果推断语义徽章样式类与简短标签。
fn coverage_badge(evidence: &EvidenceInfo) -> (&'static str, &'static str) {
    let Some(ref cov) = evidence.coverage else {
        return ("badge-warn", "覆盖范围未评估");
    };
    if cov.volumes.is_empty() {
        return ("badge-warn", "无分区卷信息");
    }
    if cov
        .volumes
        .iter()
        .any(|v| v.status.contains("超出") || v.missing_bytes > 0)
    {
        ("badge-danger", "声明范围超出镜像")
    } else if cov.volumes.iter().all(|v| v.status == "声明范围已覆盖") {
        ("badge-ok", "卷声明范围已覆盖")
    } else {
        ("badge-warn", "部分卷范围待判定")
    }
}

/// 根据交付方摘要比对状态推断语义徽章样式类。
fn source_badge(status: &str) -> &'static str {
    if status.contains("不一致") || status.contains("警告") {
        "badge-danger"
    } else if status.contains("一致") {
        "badge-ok"
    } else {
        "badge-warn"
    }
}

/// 离线自包含单文件 HTML 报告样式（明净瓷白与晴空蓝：#FFFFFF / #F7FAFD / #EFF4F9 / #2674C4）。
const HTML_REPORT_CSS: &str = r#"
:root {
  --bg-page: #F7FAFD;
  --bg-card: #FFFFFF;
  --bg-subtle: #EFF4F9;
  --accent: #2674C4;
  --accent-deep: #1B5A9C;
  --accent-soft: #E8F2FC;
  --border: #DCE6F2;
  --border-strong: #C5D6E8;
  --text-main: #182635;
  --text-muted: #52677D;
  --ok-bg: #E8F7EE;
  --ok-fg: #157347;
  --ok-bd: #B7E4C7;
  --warn-bg: #FFF6E5;
  --warn-fg: #9A5B00;
  --warn-bd: #F5D693;
  --danger-bg: #FDECEC;
  --danger-fg: #B42318;
  --danger-bd: #F5C2C0;
  --mono: "Cascadia Code", "JetBrains Mono", Consolas, "SFMono-Regular", Menlo, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.65;
  color: var(--text-main);
  background: var(--bg-page);
}
.layout {
  max-width: 1440px;
  margin: 0 auto;
  padding: 20px 24px 48px;
  display: grid;
  grid-template-columns: 248px minmax(0, 1fr);
  gap: 24px;
  align-items: start;
}
.sidebar {
  position: sticky;
  top: 20px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 18px 16px;
  box-shadow: 0 4px 16px rgba(24, 38, 53, 0.05);
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding-bottom: 14px;
  margin-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.brand-mark {
  width: 34px;
  height: 34px;
  border-radius: 9px;
  background: var(--accent);
  color: #FFFFFF;
  font-weight: 700;
  font-size: 15px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.brand-title { font-weight: 700; font-size: 15px; color: var(--text-main); }
.brand-sub { font-size: 12px; color: var(--text-muted); }
.toc-label {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  text-transform: uppercase;
  margin: 0 0 8px 6px;
}
.toc { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 3px; }
.toc a {
  display: block;
  padding: 7px 10px;
  border-radius: 8px;
  color: var(--text-main);
  text-decoration: none;
  font-size: 13px;
  transition: background 0.15s ease, color 0.15s ease;
}
.toc a:hover, .toc a.active {
  background: var(--accent-soft);
  color: var(--accent-deep);
  font-weight: 600;
}
.sidebar-actions {
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.btn {
  appearance: none;
  border: 1px solid var(--border-strong);
  background: var(--bg-subtle);
  color: var(--text-main);
  border-radius: 8px;
  padding: 7px 12px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  text-align: center;
}
.btn:hover { background: var(--accent-soft); border-color: var(--accent); color: var(--accent-deep); }
.btn-primary { background: var(--accent); border-color: var(--accent); color: #FFFFFF; }
.btn-primary:hover { background: var(--accent-deep); color: #FFFFFF; }
.content { display: flex; flex-direction: column; gap: 20px; min-width: 0; }
.hero {
  background: linear-gradient(135deg, #FFFFFF 0%, #EFF4F9 100%);
  border: 1px solid var(--border);
  border-top: 4px solid var(--accent);
  border-radius: 14px;
  padding: 24px 28px;
  box-shadow: 0 4px 18px rgba(38, 116, 196, 0.06);
}
.hero h1 { margin: 0 0 8px; font-size: 24px; color: var(--text-main); }
.hero-meta { color: var(--text-muted); font-size: 13px; display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 14px; }
.badge-row { display: flex; flex-wrap: wrap; gap: 8px; }
.badge {
  display: inline-flex;
  align-items: center;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid var(--border);
  background: var(--bg-subtle);
  color: var(--text-main);
  white-space: nowrap;
}
.badge-ok { background: var(--ok-bg); color: var(--ok-fg); border-color: var(--ok-bd); }
.badge-warn { background: var(--warn-bg); color: var(--warn-fg); border-color: var(--warn-bd); }
.badge-danger { background: var(--danger-bg); color: var(--danger-fg); border-color: var(--danger-bd); }
.badge-accent { background: var(--accent-soft); color: var(--accent-deep); border-color: #B9D7F5; }
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 22px 24px;
  box-shadow: 0 2px 10px rgba(24, 38, 53, 0.035);
}
.card h2 {
  margin: 0 0 14px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
  font-size: 18px;
  color: var(--text-main);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.card h3 { margin: 18px 0 10px; font-size: 15px; color: var(--accent-deep); }
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin: 14px 0 18px;
}
.kpi {
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 12px 14px;
}
.kpi-label { font-size: 12px; color: var(--text-muted); }
.kpi-value { font-size: 22px; font-weight: 700; color: var(--text-main); margin-top: 2px; }
.collab-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 14px;
  margin-top: 12px;
}
.collab-card {
  background: var(--bg-page);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
}
.collab-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.collab-title { font-weight: 700; font-size: 15px; }
.collab-bar {
  height: 8px;
  background: var(--bg-subtle);
  border-radius: 999px;
  overflow: hidden;
  display: flex;
  margin: 12px 0;
  border: 1px solid var(--border);
}
.collab-bar-manual { background: #4B79A8; height: 100%; }
.collab-bar-mcp { background: var(--accent); height: 100%; }
.callout {
  padding: 12px 16px;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--bg-subtle);
  margin-bottom: 14px;
}
.callout.badge-ok { background: var(--ok-bg); border-color: var(--ok-bd); color: var(--ok-fg); }
.callout.badge-warn { background: var(--warn-bg); border-color: var(--warn-bd); color: var(--warn-fg); }
.callout.badge-danger { background: var(--danger-bg); border-color: var(--danger-bd); color: var(--danger-fg); }
.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; background: var(--bg-card); }
thead th {
  background: var(--bg-subtle);
  color: var(--text-main);
  font-weight: 600;
  text-align: left;
  padding: 9px 11px;
  border-bottom: 1px solid var(--border-strong);
  white-space: nowrap;
}
tbody td {
  padding: 8px 11px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-word;
}
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #F7FAFD; }
.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.omit-row td {
  background: var(--accent-soft);
  color: var(--accent-deep);
  font-weight: 600;
  text-align: center;
}
code, .mono {
  font-family: var(--mono);
  font-size: 12px;
  background: var(--bg-subtle);
  padding: 1px 5px;
  border-radius: 4px;
  word-break: break-all;
}
details {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--bg-page);
  margin-top: 12px;
}
details > summary {
  cursor: pointer;
  padding: 11px 14px;
  font-weight: 600;
  color: var(--accent-deep);
  list-style: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: "▸";
  display: inline-block;
  margin-right: 6px;
  transition: transform 0.15s ease;
}
details[open] > summary::before { transform: rotate(90deg); }
.details-body { padding: 0 14px 14px; }
.finding-entry {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  margin-top: 8px;
}
.finding-meta { list-style: none; margin: 6px 0 0; padding: 0; font-size: 13px; color: var(--text-muted); }
.finding-meta li { margin: 3px 0; }
.scope-list { margin: 0; padding-left: 20px; color: var(--text-muted); }
.scope-list li { margin: 6px 0; }
.sign-cell { min-width: 140px; color: var(--text-muted); }
.muted { color: var(--text-muted); }
@media (max-width: 960px) {
  .layout { grid-template-columns: 1fr; padding: 14px; }
  .sidebar { position: static; }
}
@media print {
  body { background: #FFFFFF; font-size: 12px; }
  .layout { display: block; padding: 0; max-width: none; }
  .sidebar, .sidebar-actions { display: none !important; }
  .hero, .card { box-shadow: none; border-color: #CBD5E1; break-inside: avoid-page; margin-bottom: 14px; }
  .table-wrap { overflow: visible; }
  thead { display: table-header-group; }
  tr, .finding-entry, .collab-card { break-inside: avoid; }
  details { border: none; background: #FFFFFF; }
  details > summary { padding: 6px 0; }
}
"#;

/// 极简离线内联脚本：仅负责打印与一键展开/折叠全部明细（无任何外部依赖）。
const HTML_REPORT_JS: &str = r#"
(function () {
  var btn = document.getElementById('toggle-details-btn');
  if (btn) {
    btn.addEventListener('click', function () {
      var list = document.querySelectorAll('details');
      var anyClosed = false;
      for (var i = 0; i < list.length; i++) {
        if (!list[i].open) { anyClosed = true; break; }
      }
      for (var j = 0; j < list.length; j++) {
        list[j].open = anyClosed;
      }
      btn.textContent = anyClosed ? '折叠全部明细' : '展开全部明细';
    });
  }
  var printBtn = document.getElementById('print-report-btn');
  if (printBtn) {
    printBtn.addEventListener('click', function () {
      var list = document.querySelectorAll('details');
      for (var i = 0; i < list.length; i++) { list[i].open = true; }
      window.print();
    });
  }
})();
"#;

fn render_html_from_model(m: &ReportModel<'_>) -> String {
    let data = m.data;
    let evidence = m.evidence;
    let verification = data.verification.as_ref();
    let (int_cls, int_label) = integrity_badge(m.conclusion, verification.map(|v| v.ok));
    let (cov_cls, cov_label) = coverage_badge(evidence);
    let src_status = source_status(evidence);
    let src_cls = source_badge(src_status);
    let has_segments = evidence.segments.as_ref().is_some_and(|s| !s.is_empty());

    let mut html = String::with_capacity(32 * 1024);
    let _ = writeln!(html, "<!DOCTYPE html>");
    let _ = writeln!(html, "<html lang=\"zh-CN\">");
    let _ = writeln!(html, "<head>");
    let _ = writeln!(html, "<meta charset=\"UTF-8\">");
    let _ = writeln!(
        html,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
    );
    let _ = writeln!(
        html,
        "<title>电子数据取证报告 · {}</title>",
        escape_html(&data.number)
    );
    let _ = writeln!(html, "<style>{HTML_REPORT_CSS}</style>");
    let _ = writeln!(html, "</head>");
    let _ = writeln!(html, "<body>");
    let _ = writeln!(html, "<div class=\"layout\">");

    // 左侧吸顶目录导航
    let _ = writeln!(html, "<aside class=\"sidebar\" aria-label=\"报告目录\">");
    let _ = writeln!(
        html,
        "<div class=\"brand\"><div class=\"brand-mark\">TD</div><div><div class=\"brand-title\">TraceDesk 取证报告</div><div class=\"brand-sub\">离线单文件 · 应用层只读</div></div></div>"
    );
    let _ = writeln!(html, "<div class=\"toc-label\">报告目录</div>");
    let _ = writeln!(html, "<ul class=\"toc\">");
    let _ = writeln!(html, "<li><a href=\"#sec-case\">1. 案件信息与协同概览</a></li>");
    let _ = writeln!(html, "<li><a href=\"#sec-evidence\">2. 原始证据与完整性</a></li>");
    if has_segments {
        let _ = writeln!(html, "<li><a href=\"#sec-ewf\">3. EWF 分段校验明细</a></li>");
    }
    let _ = writeln!(html, "<li><a href=\"#sec-inventory\">文件清单与分区摘要</a></li>");
    let _ = writeln!(html, "<li><a href=\"#sec-exports\">导出副本清单</a></li>");
    if !m.searches.is_empty() {
        let _ = writeln!(html, "<li><a href=\"#sec-searches\">内容搜索记录</a></li>");
    }
    if !m.groups.is_empty() {
        let _ = writeln!(html, "<li><a href=\"#sec-findings\">文件取证发现</a></li>");
    }
    let _ = writeln!(html, "<li><a href=\"#sec-audit\">审计日志与哈希链</a></li>");
    let _ = writeln!(html, "<li><a href=\"#sec-signoff\">取证人员确认</a></li>");
    let _ = writeln!(html, "<li><a href=\"#sec-scope\">适用边界声明</a></li>");
    let _ = writeln!(html, "</ul>");
    let _ = writeln!(html, "<div class=\"sidebar-actions\">");
    let _ = writeln!(
        html,
        "<button type=\"button\" class=\"btn btn-primary\" id=\"print-report-btn\">打印 / 导出 PDF</button>"
    );
    let _ = writeln!(
        html,
        "<button type=\"button\" class=\"btn\" id=\"toggle-details-btn\">折叠全部明细</button>"
    );
    let _ = writeln!(html, "</div>");
    let _ = writeln!(html, "</aside>");

    // 主体内容
    let _ = writeln!(html, "<main class=\"content\">");

    // 顶部概览横幅
    let _ = writeln!(html, "<header class=\"hero\">");
    let _ = writeln!(
        html,
        "<h1>电子数据取证报告 · {}</h1>",
        escape_html(&data.number)
    );
    let _ = writeln!(html, "<div class=\"hero-meta\">");
    let _ = writeln!(
        html,
        "<span>生成时间（UTC+8）：{}</span>",
        escape_html(&display_iso_time(&m.generated_at, true))
    );
    let _ = writeln!(html, "<span>取证人员：{}</span>", escape_html(&data.examiner));
    let _ = writeln!(html, "<span>取证对象：{}</span>", escape_html(&data.target));
    let _ = writeln!(html, "<span>工作模式：应用层只读</span>");
    let _ = writeln!(html, "</div>");
    let _ = writeln!(html, "<div class=\"badge-row\">");
    let _ = writeln!(html, "<span class=\"badge {int_cls}\">{int_label}</span>");
    let _ = writeln!(html, "<span class=\"badge {cov_cls}\">{cov_label}</span>");
    let _ = writeln!(
        html,
        "<span class=\"badge {src_cls}\">{}</span>",
        escape_html(src_status)
    );
    let _ = writeln!(
        html,
        "<span class=\"badge badge-accent\">审计链通过 · {} 条</span>",
        m.records.len()
    );
    let _ = writeln!(
        html,
        "<span class=\"badge\">人工 {} · MCP {}</span>",
        m.collab.manual_audit_ops, m.collab.mcp_audit_ops
    );
    let _ = writeln!(html, "</div>");
    let _ = writeln!(html, "</header>");

    // 第 1 节：案件信息与人工/MCP 协同概览
    let _ = writeln!(html, "<section class=\"card\" id=\"sec-case\">");
    let _ = writeln!(html, "<h2><span>案件信息与协同概览</span></h2>");
    let _ = writeln!(html, "<div class=\"kpi-grid\">");
    for (label, value) in [
        ("识别分区", evidence.partitions.len().to_string()),
        ("文件清单项", format_commas(data.inventory.len() as u64)),
        ("已删除记录", format_commas(m.deleted_items)),
        ("导出副本", data.exports.len().to_string()),
        ("内容搜索", m.searches.len().to_string()),
        ("取证发现文件", m.groups.len().to_string()),
        ("审计记录", m.records.len().to_string()),
    ] {
        let _ = writeln!(
            html,
            "<div class=\"kpi\"><div class=\"kpi-label\">{label}</div><div class=\"kpi-value\">{}</div></div>",
            escape_html(&value)
        );
    }
    let _ = writeln!(html, "</div>");

    let _ = writeln!(html, "<div class=\"table-wrap\"><table><tbody>");
    for (k, v) in [
        ("案件编号", data.number.as_str()),
        ("取证人员", data.examiner.as_str()),
        ("取证对象", data.target.as_str()),
    ] {
        let _ = writeln!(
            html,
            "<tr><th style=\"width:220px;background:var(--bg-subtle);\">{k}</th><td>{}</td></tr>",
            escape_html(v)
        );
    }
    let _ = writeln!(
        html,
        "<tr><th style=\"width:220px;background:var(--bg-subtle);\">案件建立时间（UTC+8）</th><td>{}</td></tr>",
        escape_html(&display_iso_time(&data.created, false))
    );
    let _ = writeln!(html, "</tbody></table></div>");

    // 人工 vs MCP 协同统计卡片
    let total_ops = m.collab.total_audit_ops.max(1);
    let manual_pct = (m.collab.manual_audit_ops as f64) * 100.0 / (total_ops as f64);
    let mcp_pct = if m.collab.total_audit_ops == 0 {
        0.0
    } else {
        100.0 - manual_pct
    };
    let _ = writeln!(html, "<h3>人工与 MCP 协同取证统计</h3>");
    let _ = writeln!(
        html,
        "<div class=\"collab-bar\" title=\"人工 {:.1}% / MCP {:.1}%\"><div class=\"collab-bar-manual\" style=\"width:{:.2}%\"></div><div class=\"collab-bar-mcp\" style=\"width:{:.2}%\"></div></div>",
        manual_pct, mcp_pct, manual_pct, mcp_pct
    );
    let _ = writeln!(html, "<div class=\"collab-grid\">");
    let _ = writeln!(html, "<div class=\"collab-card\">");
    let _ = writeln!(
        html,
        "<div class=\"collab-head\"><span class=\"collab-title\">人工桌面取证</span><span class=\"badge\">{} 次操作（{}）</span></div>",
        m.collab.manual_audit_ops,
        format_percent(m.collab.manual_audit_ops, m.collab.total_audit_ops)
    );
    let _ = writeln!(
        html,
        "<div class=\"muted\">取证发现：<strong>{}</strong> 条记录 · 涉及 <strong>{}</strong> 个文件</div>",
        m.collab.manual_finding_ops, m.collab.manual_finding_files
    );
    let _ = writeln!(
        html,
        "<div style=\"margin-top:8px;\">活跃操作员：{}</div>",
        escape_html(&format_callers_summary(&m.collab.manual_actors))
    );
    let _ = writeln!(html, "</div>");

    let _ = writeln!(html, "<div class=\"collab-card\">");
    let _ = writeln!(
        html,
        "<div class=\"collab-head\"><span class=\"collab-title\">MCP 智能体协同</span><span class=\"badge badge-accent\">{} 次操作（{}）</span></div>",
        m.collab.mcp_audit_ops,
        format_percent(m.collab.mcp_audit_ops, m.collab.total_audit_ops)
    );
    let _ = writeln!(
        html,
        "<div class=\"muted\">取证发现：<strong>{}</strong> 条记录 · 涉及 <strong>{}</strong> 个文件</div>",
        m.collab.mcp_finding_ops, m.collab.mcp_finding_files
    );
    let _ = writeln!(
        html,
        "<div style=\"margin-top:8px;\">活跃调用方：{}</div>",
        escape_html(&format_callers_summary(&m.collab.mcp_callers))
    );
    let _ = writeln!(html, "</div>");
    let _ = writeln!(html, "</div>");
    let _ = writeln!(html, "</section>");

    // 第 2 节：原始证据与完整性
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

    let _ = writeln!(html, "<section class=\"card\" id=\"sec-evidence\">");
    let _ = writeln!(
        html,
        "<h2><span>原始证据与完整性</span><span class=\"badge {int_cls}\">{int_label}</span></h2>"
    );
    let _ = writeln!(
        html,
        "<div class=\"callout {int_cls}\"><strong>完整性校验结论：</strong>{}</div>",
        escape_html(m.conclusion)
    );
    let _ = writeln!(html, "<div class=\"table-wrap\"><table><tbody>");
    let _ = writeln!(
        html,
        "<tr><th style=\"width:260px;background:var(--bg-subtle);\">镜像路径</th><td><code>{}</code></td></tr>",
        escape_html(&evidence.path)
    );
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">镜像格式</th><td>{}</td></tr>",
        escape_html(evidence.format_label())
    );
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">逻辑介质大小</th><td>{}</td></tr>",
        escape_html(&format_size(evidence.size))
    );
    if let Some(ref segs) = evidence.segments
        && !segs.is_empty()
    {
        let encap_size: u64 = segs.iter().map(|s| s.size).sum();
        let _ = writeln!(
            html,
            "<tr><th style=\"background:var(--bg-subtle);\">EWF 分段封装</th><td>共 {} 段 · 封装总大小 {}</td></tr>",
            segs.len(),
            escape_html(&format_size(encap_size))
        );
    }
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">初始逻辑介质 SHA-256</th><td><code>{}</code></td></tr>",
        escape_html(initial_sha)
    );
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">{}</th><td><code>{}</code></td></tr>",
        escape_html(actual_label),
        escape_html(actual_sha)
    );
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">完整读取时间（UTC+8）</th><td>{}</td></tr>",
        escape_html(&verify_time)
    );
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">校验方式</th><td>{}</td></tr>",
        escape_html(verify_method)
    );
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">声明范围判定</th><td><span class=\"badge {cov_cls}\" style=\"margin-right:8px;\">{cov_label}</span>{}</td></tr>",
        escape_html(&coverage_text(evidence.coverage.as_ref()))
    );
    let _ = writeln!(
        html,
        "<tr><th style=\"background:var(--bg-subtle);\">交付方摘要比对</th><td><span class=\"badge {src_cls}\">{}</span></td></tr>",
        escape_html(src_status)
    );
    for &(key, label) in &SOURCE_FIELDS {
        let val = evidence
            .provenance
            .as_ref()
            .map(|p| p.get_field(key))
            .filter(|s| !s.is_empty())
            .unwrap_or("未登记");
        let _ = writeln!(
            html,
            "<tr><th style=\"background:var(--bg-subtle);\">{label}</th><td>{}</td></tr>",
            escape_html(val)
        );
    }
    let _ = writeln!(html, "</tbody></table></div>");
    let _ = writeln!(html, "</section>");

    // EWF 逐段 SHA-256 明细
    if let Some(ref segs) = evidence.segments
        && !segs.is_empty()
    {
        let _ = writeln!(html, "<section class=\"card\" id=\"sec-ewf\">");
        let _ = writeln!(
            html,
            "<h2><span>EWF 分段 SHA-256 明细</span><span class=\"badge badge-accent\">共 {} 段</span></h2>",
            segs.len()
        );
        let _ = writeln!(
            html,
            "<details open><summary>展开 / 折叠 {} 个物理分段摘要表</summary><div class=\"details-body\"><div class=\"table-wrap\"><table><thead><tr><th class=\"num\">段序</th><th>分段文件名</th><th class=\"num\">分段大小</th><th>分段 SHA-256</th></tr></thead><tbody>",
            segs.len()
        );
        for (idx, seg) in segs.iter().enumerate() {
            let seg_sha = if seg.sha256.trim().is_empty() {
                "待计算"
            } else {
                seg.sha256.as_str()
            };
            let _ = writeln!(
                html,
                "<tr><td class=\"num\">{}</td><td>{}</td><td class=\"num\">{}</td><td><code>{}</code></td></tr>",
                idx + 1,
                escape_html(&seg.name),
                escape_html(&format_size(seg.size)),
                escape_html(seg_sha)
            );
        }
        let _ = writeln!(html, "</tbody></table></div></div></details>");
        let _ = writeln!(html, "</section>");
    }

    // 文件清单与分区摘要
    let _ = writeln!(html, "<section class=\"card\" id=\"sec-inventory\">");
    let _ = writeln!(html, "<h2><span>文件清单与分区摘要</span></h2>");
    let _ = writeln!(
        html,
        "<p>已识别 <strong>{}</strong> 个分区，当前清单共 <strong>{}</strong> 项（现存文件 {} 项 · 已删除记录 {} 项 · 目录 {} 项；抽样展示 {} 项，其中优先纳入的取证发现/已导出/已删除条目 {} 项）。</p>",
        evidence.partitions.len(),
        format_commas(data.inventory.len() as u64),
        format_commas(m.active_files),
        format_commas(m.deleted_items),
        format_commas(m.directories),
        m.sampled_inventory.len(),
        m.priority_sampled_count
    );
    if let Some(ref idx_ver) = data.index_verification
        && !idx_ver.is_empty()
    {
        let _ = writeln!(
            html,
            "<div class=\"callout\">建立清单时的完整性状态：{}</div>",
            escape_html(idx_ver)
        );
    }

    let _ = writeln!(html, "<h3>分区概览</h3>");
    let _ = writeln!(
        html,
        "<div class=\"table-wrap\"><table><thead><tr><th class=\"num\">分区偏移（扇区）</th><th>分区说明</th><th>扫描状态</th></tr></thead><tbody>"
    );
    for part in &evidence.partitions {
        let state = match m.scans_map.get(&part.offset) {
            Some(scan) if scan.status == "ready" => {
                format!("已读取 {} 项", format_commas(scan.count as u64))
            }
            Some(scan) => format!("无法读取：{}", scan.error.as_deref().unwrap_or("")),
            None => "未完成全部分区读取".to_string(),
        };
        let _ = writeln!(
            html,
            "<tr><td class=\"num\">{}</td><td>{}</td><td>{}</td></tr>",
            part.offset,
            escape_html(&part.description),
            escape_html(&state)
        );
    }
    let _ = writeln!(html, "</tbody></table></div>");

    if !m.sampled_inventory.is_empty() {
        let _ = writeln!(
            html,
            "<details open><summary>文件清单智能抽样明细（共展示 {} 项，优先纳入 {} 项重点条目）</summary><div class=\"details-body\">",
            m.sampled_inventory.len(),
            m.priority_sampled_count
        );
        let _ = writeln!(
            html,
            "<div class=\"table-wrap\"><table><thead><tr><th class=\"num\">分区偏移</th><th>路径</th><th>状态</th><th>关注标签</th><th>inode</th><th class=\"num\">字节数</th><th>M (UTC+8)</th><th>A (UTC+8)</th><th>C (UTC+8)</th><th>B (UTC+8)</th></tr></thead><tbody>"
        );
        for item in &m.sampled_inventory {
            let row = item.entry;
            let status = entry_status(row);
            let status_cls = if row.deleted { "badge-warn" } else { "badge-ok" };
            let tags_html = if item.tags.is_empty() {
                "<span class=\"muted\">—</span>".to_string()
            } else {
                item.tags
                    .iter()
                    .map(|t| {
                        let cls = match *t {
                            "取证发现" => "badge-accent",
                            "已导出" => "badge-ok",
                            _ => "badge-warn",
                        };
                        format!("<span class=\"badge {cls}\">{t}</span>")
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let _ = writeln!(
                html,
                "<tr><td class=\"num\">{}</td><td><code>{}</code></td><td><span class=\"badge {status_cls}\">{}</span></td><td>{tags_html}</td><td><code>{}</code></td><td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                row.offset,
                escape_html(&row.path),
                escape_html(status),
                escape_html(&row.inode),
                format_commas(row.size),
                escape_html(&display_timestamp(row.mtime, true)),
                escape_html(&display_timestamp(row.atime, true)),
                escape_html(&display_timestamp(row.ctime, true)),
                escape_html(&display_timestamp(row.crtime, true))
            );
        }
        let _ = writeln!(html, "</tbody></table></div></div></details>");
    } else {
        let _ = writeln!(html, "<p class=\"muted\">尚未建立完整文件清单。</p>");
    }
    let _ = writeln!(html, "</section>");

    // 导出副本
    let _ = writeln!(html, "<section class=\"card\" id=\"sec-exports\">");
    let _ = writeln!(
        html,
        "<h2><span>导出副本清单</span><span class=\"badge\">{} 项</span></h2>",
        data.exports.len()
    );
    if !data.exports.is_empty() {
        let _ = writeln!(
            html,
            "<div class=\"table-wrap\"><table><thead><tr><th class=\"num\">序号</th><th class=\"num\">分区偏移</th><th>镜像内路径</th><th>导出路径</th><th class=\"num\">字节数</th><th>SHA-256</th><th>说明</th></tr></thead><tbody>"
        );
        for (idx, row) in data.exports.iter().enumerate() {
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
            let _ = writeln!(
                html,
                "<tr><td class=\"num\">{}</td><td class=\"num\">{}</td><td><code>{}</code></td><td><code>{}</code></td><td class=\"num\">{}</td><td><code>{}</code></td><td>{}</td></tr>",
                idx + 1,
                row.offset,
                escape_html(&row.source),
                escape_html(&row.path),
                format_commas(row.size),
                escape_html(&row.sha256),
                escape_html(&note_str)
            );
        }
        let _ = writeln!(html, "</tbody></table></div>");
    } else {
        let _ = writeln!(html, "<p class=\"muted\">本案件尚未导出文件副本。</p>");
    }
    let _ = writeln!(html, "</section>");

    // 内容搜索记录（可选）
    if !m.searches.is_empty() {
        let _ = writeln!(html, "<section class=\"card\" id=\"sec-searches\">");
        let _ = writeln!(
            html,
            "<h2><span>内容搜索记录</span><span class=\"badge badge-accent\">{} 次</span></h2>",
            m.searches.len()
        );
        let _ = writeln!(
            html,
            "<div class=\"table-wrap\"><table><thead><tr><th class=\"num\">序号</th><th>时间 (UTC+8)</th><th>搜索内容</th><th>编码</th><th>状态</th><th>已处理/总数</th><th class=\"num\">命中数</th><th class=\"num\">失败数</th><th>详情清单</th></tr></thead><tbody>"
        );
        for (idx, row) in m.searches.iter().enumerate() {
            let d = &row.details;
            let visited = d.get("visited").and_then(Value::as_u64).unwrap_or(0);
            let eligible = d.get("eligible").and_then(Value::as_u64).unwrap_or(0);
            let query = d.get("query").and_then(Value::as_str).unwrap_or("");
            let encoding = d.get("encoding").and_then(Value::as_str).unwrap_or("");
            let hits = d.get("hits").and_then(Value::as_u64).unwrap_or(0);
            let failed = d.get("failed").and_then(Value::as_u64).unwrap_or(0);
            let _ = writeln!(
                html,
                "<tr><td class=\"num\">{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}/{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td><code>reports/{}</code></td></tr>",
                idx + 1,
                escape_html(&display_iso_time(&row.timestamp, true)),
                escape_html(query),
                escape_html(encoding),
                escape_html(&row.result),
                format_commas(visited),
                format_commas(eligible),
                hits,
                failed,
                escape_html(&row.subject)
            );
        }
        let _ = writeln!(html, "</tbody></table></div>");
        let _ = writeln!(html, "</section>");
    }

    // 文件取证发现（可选）
    if !m.groups.is_empty() {
        let _ = writeln!(html, "<section class=\"card\" id=\"sec-findings\">");
        let _ = writeln!(
            html,
            "<h2><span>文件取证发现</span><span class=\"badge badge-accent\">{} 个文件</span></h2>",
            m.groups.len()
        );
        let _ = writeln!(
            html,
            "<p>共涉及 <strong>{}</strong> 个文件，全部取证发现记录均来自已通过 SHA-256 哈希链校验的审计日志。</p>",
            m.groups.len()
        );
        for (idx, group) in m.groups.iter().enumerate() {
            let status = if group.key.deleted { "已删除" } else { "现存" };
            let status_cls = if group.key.deleted {
                "badge-warn"
            } else {
                "badge-ok"
            };
            let image_hash = group
                .key
                .image_sha256
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("记录时待固定");
            let _ = writeln!(
                html,
                "<details open><summary><span>{}. <code>{}</code></span><span><span class=\"badge {status_cls}\">{status}</span> <span class=\"badge\">{} 条记录</span></span></summary><div class=\"details-body\">",
                idx + 1,
                escape_html(&group.key.subject),
                group.records.len()
            );
            let _ = writeln!(
                html,
                "<div class=\"muted\" style=\"margin-bottom:6px;\">分区偏移 {} 扇区 · inode <code>{}</code> · 来源镜像 SHA-256：<code>{}</code></div>",
                group.key.offset,
                escape_html(&group.key.inode),
                escape_html(image_hash)
            );
            for r in &group.records {
                let d = &r.details;
                let op = operation_title(&r.action).unwrap_or(&r.action);
                let origin_cls = if audit_origin(r) == AuditOrigin::Mcp {
                    "badge-accent"
                } else {
                    ""
                };
                let _ = writeln!(html, "<div class=\"finding-entry\">");
                let _ = writeln!(
                    html,
                    "<div><code>#{}</code> {} · <span class=\"badge {origin_cls}\">{}</span> · {} · <strong>{}</strong> · <span class=\"badge badge-ok\">{}</span></div>",
                    r.seq,
                    escape_html(&display_iso_time(&r.timestamp, true)),
                    escape_html(&audit_origin_label(r)),
                    escape_html(&r.actor),
                    escape_html(op),
                    escape_html(&r.result)
                );
                let _ = writeln!(html, "<ul class=\"finding-meta\">");
                if let Some(size) = d.get("size").and_then(Value::as_u64) {
                    let recorded = d
                        .get("recorded_size")
                        .and_then(Value::as_u64)
                        .unwrap_or(size);
                    let _ = writeln!(
                        html,
                        "<li>读取长度：{} / {} 字节</li>",
                        format_commas(size),
                        format_commas(recorded)
                    );
                }
                if let Some(fb) = d.get("file_byte").and_then(Value::as_u64) {
                    let _ = writeln!(
                        html,
                        "<li>命中字节偏移：<code>{fb}</code>（<code>0x{fb:X}</code>）</li>"
                    );
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
                        if matches!(key, "sha256" | "comparison_sha256" | "before" | "after") {
                            let _ = writeln!(
                                html,
                                "<li>{label}：<code>{}</code></li>",
                                escape_html(&disp)
                            );
                        } else {
                            let _ = writeln!(html, "<li>{label}：{}</li>", escape_html(&disp));
                        }
                    }
                }
                let _ = writeln!(html, "</ul></div>");
            }
            let _ = writeln!(html, "</div></details>");
        }
        let _ = writeln!(html, "</section>");
    }

    // 审计日志摘要（首 20 条基线 + 末 80 条）
    let _ = writeln!(html, "<section class=\"card\" id=\"sec-audit\">");
    let _ = writeln!(
        html,
        "<h2><span>审计日志与哈希链</span><span class=\"badge badge-ok\">验链通过 · {} 条</span></h2>",
        m.records.len()
    );
    let audit_desc = if m.audit_view.omitted > 0 {
        format!(
            "共 {} 条记录（人工 {} 条 · MCP {} 条），下方展示首 {} 条基线与末 {} 条记录，中间省略 {} 条。",
            m.records.len(),
            m.collab.manual_audit_ops,
            m.collab.mcp_audit_ops,
            m.audit_view.head.len(),
            m.audit_view.tail.len(),
            m.audit_view.omitted
        )
    } else {
        format!(
            "共 {} 条记录（人工 {} 条 · MCP {} 条），全部记录均已通过 SHA-256 哈希链验证。",
            m.records.len(),
            m.collab.manual_audit_ops,
            m.collab.mcp_audit_ops
        )
    };
    let _ = writeln!(html, "<p>{}</p>", escape_html(&audit_desc));
    let _ = writeln!(
        html,
        "<div class=\"callout\">尾部哈希锚点（<code>audit.head</code>）：<code>{}</code></div>",
        escape_html(m.tail_hash)
    );
    let _ = writeln!(
        html,
        "<details open><summary>展开 / 折叠审计日志摘要表</summary><div class=\"details-body\"><div class=\"table-wrap\"><table><thead><tr><th class=\"num\">序号</th><th>时间 (UTC+8)</th><th>来源</th><th>操作人员</th><th>操作</th><th>对象</th><th>结果</th></tr></thead><tbody>"
    );

    let write_html_audit_row = |html: &mut String, row: &AuditRecord| {
        let origin_cls = if audit_origin(row) == AuditOrigin::Mcp {
            "badge-accent"
        } else {
            ""
        };
        let _ = writeln!(
            html,
            "<tr><td class=\"num\">{}</td><td>{}</td><td><span class=\"badge {origin_cls}\">{}</span></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
            row.seq,
            escape_html(&display_iso_time(&row.timestamp, false)),
            escape_html(&audit_origin_label(row)),
            escape_html(&row.actor),
            escape_html(action_title(&row.action)),
            escape_html(&row.subject),
            escape_html(&row.result)
        );
    };

    for row in m.audit_view.head {
        write_html_audit_row(&mut html, row);
    }
    if m.audit_view.omitted > 0 {
        let omitted_start = m.audit_view.head.last().map(|r| r.seq + 1).unwrap_or(21);
        let omitted_end = m
            .audit_view
            .tail
            .first()
            .map(|r| r.seq.saturating_sub(1))
            .unwrap_or(omitted_start + m.audit_view.omitted as u64 - 1);
        let _ = writeln!(
            html,
            "<tr class=\"omit-row\"><td colspan=\"7\">… 已省略中间 {} 条审计记录（#{} 至 #{}），完整记录请查阅案件 audit.jsonl …</td></tr>",
            m.audit_view.omitted, omitted_start, omitted_end
        );
        for row in m.audit_view.tail {
            write_html_audit_row(&mut html, row);
        }
    }
    let _ = writeln!(html, "</tbody></table></div></div></details>");
    let _ = writeln!(html, "</section>");

    // 取证人员确认
    let _ = writeln!(html, "<section class=\"card\" id=\"sec-signoff\">");
    let _ = writeln!(html, "<h2><span>取证人员确认</span></h2>");
    let _ = writeln!(
        html,
        "<div class=\"table-wrap\"><table><thead><tr><th>角色</th><th>签名</th><th>日期</th></tr></thead><tbody><tr><td>取证人员</td><td class=\"sign-cell\">________________</td><td class=\"sign-cell\">________________</td></tr><tr><td>复核人员</td><td class=\"sign-cell\">________________</td><td class=\"sign-cell\">________________</td></tr></tbody></table></div>"
    );
    let _ = writeln!(html, "</section>");

    // 适用边界
    let _ = writeln!(html, "<section class=\"card\" id=\"sec-scope\">");
    let _ = writeln!(html, "<h2><span>适用边界声明</span></h2>");
    let _ = writeln!(html, "<ul class=\"scope-list\">");
    let _ = writeln!(
        html,
        "<li>本工具为教学原型，实施应用层只读约束，不替代硬件写保护器或法定资质认证。</li>"
    );
    let _ = writeln!(
        html,
        "<li>MACB 时间来自文件系统元数据，可能被修改；C 表示元数据变更时间，并非通用的创建时间。</li>"
    );
    let _ = writeln!(
        html,
        "<li>日志哈希链和本地锚点可发现意外修改或单独截断，不能抵抗同时重写全部案件数据的攻击者。</li>"
    );
    let _ = writeln!(
        html,
        "<li>案件库与镜像位于独立目录；若要求不同物理介质，需由操作人员另行安排。</li>"
    );
    let _ = writeln!(html, "</ul>");
    let _ = writeln!(html, "</section>");

    let _ = writeln!(html, "</main>");
    let _ = writeln!(html, "</div>");
    let _ = writeln!(html, "<script>{HTML_REPORT_JS}</script>");
    let _ = writeln!(html, "</body>");
    let _ = writeln!(html, "</html>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::{ExportRecord, VerificationInfo};
    use crate::coverage::Provenance;
    use serde_json::Map;
    use tracedesk_engines::{PartitionInfo, SegmentDigest};

    fn make_entry(path: &str, inode: &str, deleted: bool, directory: bool) -> InventoryEntry {
        InventoryEntry {
            path: path.to_string(),
            inode: inode.to_string(),
            mode: if directory {
                "d/drwxr-xr-x".to_string()
            } else if deleted {
                "-/r--------".to_string()
            } else {
                "r/rrw-r--r--".to_string()
            },
            size: if directory { 0 } else { 512 },
            deleted,
            reallocated: false,
            atime: 1_700_000_000,
            mtime: 1_700_000_000,
            ctime: 1_700_000_000,
            crtime: 1_700_000_000,
            directory,
            offset: 2048,
            filesystem: "FAT32".to_string(),
            start_cluster_allocated: None,
            extents: None,
        }
    }

    fn make_record(
        seq: u64,
        origin: &str,
        actor: &str,
        mcp_client: Option<&str>,
        action: &str,
        subject: &str,
        details: Map<String, Value>,
    ) -> AuditRecord {
        AuditRecord {
            seq,
            timestamp: "2026-11-26T10:00:00+08:00".to_string(),
            actor: actor.to_string(),
            origin: Some(origin.to_string()),
            mcp_client: mcp_client.map(str::to_string),
            action: action.to_string(),
            subject: subject.to_string(),
            result: "成功".to_string(),
            details,
            previous: format!("{:064x}", seq.saturating_sub(1)),
            hash: format!("{:064x}", seq),
        }
    }

    fn make_sample_case_data() -> CaseData {
        CaseData {
            id: "case-test-001".to_string(),
            number: "TD-2026-<XSS>&\"01\"".to_string(),
            examiner: "张取证<script>alert(1)</script>".to_string(),
            target: "测试盘 & '证据'".to_string(),
            created: "2026-11-26T09:00:00+08:00".to_string(),
            evidence: Some(EvidenceInfo {
                path: r"D:\evidence\case.E01".to_string(),
                size: 16 * 1024 * 1024,
                sha256: Some("a".repeat(64)),
                fixed_at: Some("2026-11-26T09:01:00+08:00".to_string()),
                partitions: vec![PartitionInfo {
                    offset: 2048,
                    description: "NTFS / exFAT".to_string(),
                }],
                layout: String::new(),
                format: Some("EWF".to_string()),
                large_image: Some(false),
                opened_at: Some("2026-11-26T09:00:30+08:00".to_string()),
                source_stamp: None,
                segments: Some(vec![
                    SegmentDigest {
                        name: "case.E01".to_string(),
                        size: 4_194_304,
                        sha256: "1".repeat(64),
                    },
                    SegmentDigest {
                        name: "case.E02".to_string(),
                        size: 3_145_728,
                        sha256: "2".repeat(64),
                    },
                ]),
                provenance: Some(Provenance {
                    evidence_id: "EV-01".to_string(),
                    source: "现场固定".to_string(),
                    acquired: "2026-11-25 14:00:00 +08:00".to_string(),
                    tool: "FTK Imager".to_string(),
                    expected_sha256: "a".repeat(64),
                }),
                coverage: None,
            }),
            inventory: Vec::new(),
            exports: Vec::new(),
            partition_scans: None,
            offset: None,
            fsstat: None,
            index_verification: None,
            verification: Some(VerificationInfo {
                time: "2026-11-26T09:30:00+08:00".to_string(),
                actual: Some("a".repeat(64)),
                ok: true,
                method: "复算 EWF 分段 SHA-256".to_string(),
            }),
        }
    }

    #[test]
    fn html_and_markdown_cover_xss_ewf_collab_and_priority_sampling() {
        let mut data = make_sample_case_data();

        // 构造 240 个普通系统目录在前，确保常规截断会漏掉末尾的关键文件
        for i in 0..240 {
            data.inventory.push(make_entry(
                &format!("WINDOWS/SYSDIR_{i:03}"),
                &format!("10{i}"),
                false,
                true,
            ));
        }
        // 在清单末尾放入 3 类高优先级条目：已删除、已导出、有取证发现
        data.inventory
            .push(make_entry("SECRET/DELETED.TXT", "9001", true, false));
        data.inventory
            .push(make_entry("SECRET/EXPORTED.TXT", "9002", false, false));
        data.inventory.push(make_entry(
            "SECRET/FINDING_<img onerror=alert(1)>.TXT",
            "9003",
            false,
            false,
        ));

        data.exports.push(ExportRecord {
            path: r"C:\cases\exports\EXPORTED.TXT".to_string(),
            source: "SECRET/EXPORTED.TXT".to_string(),
            inode: "9002".to_string(),
            offset: 2048,
            sha256: "b".repeat(64),
            size: 512,
            time: "2026-11-26T09:40:00+08:00".to_string(),
            source_verification: None,
            image_sha256: None,
            deleted: None,
            recorded_size: None,
            read_note: None,
            reallocated: None,
            start_cluster_allocated: None,
        });

        let mut note_details = Map::new();
        note_details.insert("offset".to_string(), Value::from(2048u64));
        note_details.insert("inode".to_string(), Value::String("9003".to_string()));
        note_details.insert("deleted".to_string(), Value::Bool(false));
        note_details.insert(
            "note".to_string(),
            Value::String("发现恶意载荷 <script>evil()</script>".to_string()),
        );

        let records = vec![
            make_record(1, "manual", "张取证", None, "CASE_CREATE", "案件", Map::new()),
            make_record(2, "manual", "张取证", None, "IMAGE_LOAD", "case.E01", Map::new()),
            make_record(
                3,
                "mcp",
                "MCP 助手",
                Some("张三 / Cursor 1.2"),
                "FILE_NOTE",
                "SECRET/FINDING_<img onerror=alert(1)>.TXT",
                note_details,
            ),
            make_record(
                4,
                "mcp",
                "MCP 助手",
                Some("张三 / Cursor 1.2"),
                "FILE_FILTER",
                ".txt",
                Map::new(),
            ),
        ];

        // 1. 校验人工 vs MCP 协同统计
        let stats = compute_collaboration_stats(&records);
        assert_eq!(stats.total_audit_ops, 4);
        assert_eq!(stats.manual_audit_ops, 2);
        assert_eq!(stats.mcp_audit_ops, 2);
        assert_eq!(stats.manual_finding_ops, 0);
        assert_eq!(stats.mcp_finding_ops, 1);
        assert_eq!(stats.mcp_finding_files, 1);
        assert_eq!(stats.mcp_callers.len(), 1);
        assert_eq!(stats.mcp_callers[0].name, "张三 / Cursor");

        // 2. 校验 Markdown 报告包含 EWF 分段明细表、协同统计与高优清单抽样
        let md = render_report(&data, &records, "通过：EWF 全部物理分段摘要一致");
        assert!(md.contains("### 人工与 MCP 协同取证统计"));
        assert!(md.contains("### EWF 分段 SHA-256 明细"));
        assert!(md.contains("case.E01"));
        assert!(md.contains("case.E02"));
        assert!(md.contains("SECRET/DELETED.TXT"));
        assert!(md.contains("SECRET/EXPORTED.TXT"));
        assert!(md.contains("SECRET/FINDING_"));

        // 3. 校验离线单文件 HTML 报告：XSS 转义、明净瓷白配色、无外链 CDN、含目录导航与折叠明细
        let html = render_html_report(&data, &records, "通过：EWF 全部物理分段摘要一致");
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("#2674C4"));
        assert!(html.contains("#F7FAFD"));
        assert!(html.contains("#EFF4F9"));
        assert!(html.contains("@media print"));
        assert!(html.contains("<details"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        // 严格防 XSS：用户输入中的 <script> 与 <img onerror=...> 必须被转义
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(!html.contains("<script>evil()</script>"));
        assert!(!html.contains("<img onerror=alert(1)>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;script&gt;evil()&lt;/script&gt;"));
        assert!(html.contains("&lt;img onerror=alert(1)&gt;"));
        assert!(html.contains("case.E02"));
        assert!(html.contains("张三 / Cursor"));
    }

    #[test]
    fn audit_sampling_uses_head_20_and_tail_80_when_over_100() {
        let data = make_sample_case_data();
        let records: Vec<AuditRecord> = (1..=135)
            .map(|seq| {
                let action = if seq == 1 {
                    "CASE_CREATE"
                } else if seq == 2 {
                    "IMAGE_LOAD"
                } else {
                    "FILE_FILTER"
                };
                make_record(
                    seq,
                    if seq % 3 == 0 { "mcp" } else { "manual" },
                    "张取证",
                    (seq % 3 == 0).then_some("Bot 2.0"),
                    action,
                    &format!("ITEM_{seq:03}"),
                    Map::new(),
                )
            })
            .collect();

        let md = render_report(&data, &records, "通过：测试校验");
        assert!(md.contains("中间省略 35 条"));
        assert!(md.contains("ITEM_001"));
        assert!(md.contains("ITEM_020"));
        assert!(!md.contains("ITEM_021"));
        assert!(!md.contains("ITEM_055"));
        assert!(md.contains("ITEM_056"));
        assert!(md.contains("ITEM_135"));

        let html = render_html_report(&data, &records, "通过：测试校验");
        assert!(html.contains("已省略中间 35 条审计记录（#21 至 #55）"));
        assert!(html.contains("ITEM_001"));
        assert!(html.contains("ITEM_020"));
        assert!(!html.contains("ITEM_021"));
        assert!(html.contains("ITEM_056"));
        assert!(html.contains("ITEM_135"));
    }
}
