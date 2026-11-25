//! 取证发现分组、审计操作标题、审计来源解析与一键导出取证发现
//! （对应 `core-contract.md` §3.3，与 `forensic/core/findings.py` 保持一致）。

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::case::Case;
pub use crate::case::strip_trailing_version;
use crate::error::{CoreError, CoreResult};
use crate::formatting::{can_export, display_iso_time, now, sha256_hex};

/// 归类为取证发现的审计操作类型。
pub const OPERATIONS: [(&str, &str); 3] = [
    ("FILE_NOTE", "取证笔记"),
    ("FILE_HASH", "计算摘要"),
    ("FILE_COMPARE", "比对副本"),
];

/// 合法的审计来源标识符及其中文展示标签。
pub const AUDIT_ORIGINS: [(&str, &str); 2] = [("manual", "人工"), ("mcp", "MCP")];

/// 全部审计操作代码到中文标题的完整映射（对应 `core-contract.md` §3.3）。
pub const ACTION_TITLES: [(&str, &str); 20] = [
    ("CONTENT_SEARCH", "搜索文件内容"),
    ("SOURCE_REGISTER", "登记证据来源"),
    ("REVIEW_EXPORT", "生成复核包"),
    ("CASE_CREATE", "新建案件"),
    ("CASE_OPEN", "打开案件"),
    ("IMAGE_LOAD_BEGIN", "开始载入镜像"),
    ("IMAGE_LOAD", "载入镜像"),
    ("HASH_FIXED", "固定镜像摘要"),
    ("HASH_VERIFY", "校验镜像完整性"),
    ("FILE_BROWSE", "读取分区文件"),
    ("PARTITIONS_SCAN", "扫描所有分区"),
    ("FILE_FILTER", "筛选文件"),
    ("FILE_EXPORT", "导出文件"),
    ("TIMELINE", "生成时间线"),
    ("REPORT_GENERATE", "生成报告"),
    ("FILE_NOTE", "记录取证发现"),
    ("FILE_COMPARE", "比对文件副本"),
    ("FILE_HASH", "计算文件摘要"),
    ("FINDINGS_EXPORT", "导出取证发现"),
    ("FSSTAT_EXPORT", "导出文件系统详情"),
];

/// 若 `action` 属于 [`OPERATIONS`]，则返回对应的中文取证发现操作名。
pub fn operation_title(action: &str) -> Option<&'static str> {
    OPERATIONS
        .iter()
        .find_map(|&(code, label)| (code == action).then_some(label))
}

/// 查找审计操作 `action` 对应的中文展示标题，未匹配时回退为 `action` 本身。
pub fn action_title(action: &str) -> &str {
    ACTION_TITLES
        .iter()
        .find_map(|&(code, title)| (code == action).then_some(title))
        .unwrap_or(action)
}

/// 标准化的审计来源枚举（`"manual"` 与 `"mcp"`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOrigin {
    Manual,
    Mcp,
}

impl AuditOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Mcp => "mcp",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Manual => "人工",
            Self::Mcp => "MCP",
        }
    }

    pub fn parse(raw: &str) -> CoreResult<Self> {
        match raw {
            "manual" => Ok(Self::Manual),
            "mcp" => Ok(Self::Mcp),
            other => Err(CoreError::InvalidInput(format!("未知审计来源：{other}"))),
        }
    }
}

/// `audit.jsonl` 中的单条审计记录（`core-contract.md` §1.2）。
///
/// `origin` 与 `mcp_client` 均为可选字段，以 100% 兼容不包含这两个字段的历史案件记录；
/// 新写入记录始终显式填充 `origin`，且仅当来源为 MCP 并存在使用者/客户端标识时才写入 `mcp_client`
/// （人工操作不写此键，保持与历史人工记录完全一致）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub timestamp: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// MCP 使用者/客户端标识（人工操作为 `None` 且序列化时省略该键）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_client: Option<String>,
    pub action: String,
    pub subject: String,
    pub result: String,
    #[serde(default)]
    pub details: Map<String, Value>,
    pub previous: String,
    pub hash: String,
}

/// 从旧版 `actor` 字段中剥离 `(MCP)` / `（MCP）` 标记（大小写不敏感），并规范化空白字符。
fn strip_mcp_marker(raw: &str) -> String {
    let mut current = raw.trim().to_string();
    loop {
        let lower = current.to_lowercase();
        let found = lower
            .find("(mcp)")
            .map(|pos| (pos, "(mcp)".len()))
            .or_else(|| lower.find("（mcp）").map(|pos| (pos, "（mcp）".len())));
        let Some((pos, len)) = found else {
            break;
        };
        if current.len() == lower.len()
            && current.is_char_boundary(pos)
            && current.is_char_boundary(pos + len)
        {
            current.replace_range(pos..pos + len, " ");
        } else {
            let replaced = current
                .replace("(MCP)", " ")
                .replace("(mcp)", " ")
                .replace("(Mcp)", " ")
                .replace("（MCP）", " ")
                .replace("（mcp）", " ")
                .replace("（Mcp）", " ");
            if replaced == current {
                break;
            }
            current = replaced;
        }
    }
    current.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 解析 [`AuditRecord`] 的有效审计来源（[`AuditOrigin`]），兼容无显式 `origin` 字段的历史记录。
pub fn audit_origin(record: &AuditRecord) -> AuditOrigin {
    match record.origin.as_deref() {
        Some("manual") => return AuditOrigin::Manual,
        Some("mcp") => return AuditOrigin::Mcp,
        _ => {}
    }
    let upper = record.actor.trim().to_ascii_uppercase();
    if upper.contains("(MCP)") || upper == "MCP" {
        AuditOrigin::Mcp
    } else {
        AuditOrigin::Manual
    }
}

/// 提取审计记录对应的 MCP 使用者/客户端展示名称（自动去除各段末尾的版本号数字，不修改磁盘原文）。
///
/// - 人工操作固定返回 `None`；
/// - MCP 操作优先取非空 `mcp_client`（经 [`strip_trailing_version`] 归一化并排除泛化 `"MCP"`）；
/// - 兼容旧版无 `mcp_client` 记录：从 `actor` 去除 `(MCP)` 并经 [`strip_trailing_version`] 归一化后，
///   若非空且不等于 `"MCP"` 则取该名称。
pub fn audit_mcp_user(record: &AuditRecord) -> Option<String> {
    if audit_origin(record) != AuditOrigin::Mcp {
        return None;
    }
    if let Some(raw_client) = record.mcp_client.as_deref() {
        let cleaned = strip_trailing_version(raw_client);
        if !cleaned.is_empty() && !cleaned.eq_ignore_ascii_case("MCP") {
            return Some(cleaned);
        }
    }
    let legacy = strip_trailing_version(&strip_mcp_marker(&record.actor));
    if !legacy.is_empty() && !legacy.eq_ignore_ascii_case("MCP") {
        Some(legacy)
    } else {
        None
    }
}

/// 返回审计记录来源的中文展示标签：
/// - `manual` → `"人工"`
/// - `mcp` → 若能解析出具体使用者/客户端 `<who>` 则返回 `"MCP · <who>"`，否则返回 `"MCP"`。
pub fn audit_origin_label(record: &AuditRecord) -> String {
    match audit_origin(record) {
        AuditOrigin::Manual => AuditOrigin::Manual.label().to_string(),
        AuditOrigin::Mcp => match audit_mcp_user(record) {
            Some(who) => format!("MCP · {who}"),
            None => AuditOrigin::Mcp.label().to_string(),
        },
    }
}

/// 取证发现分组键（`(subject, offset, inode, deleted, image_sha256)`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingGroupKey {
    pub subject: String,
    pub offset: u64,
    pub inode: String,
    pub deleted: bool,
    pub image_sha256: Option<String>,
}

/// 归属于同一目标文件的取证发现记录分组。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingGroup {
    pub key: FindingGroupKey,
    pub records: Vec<AuditRecord>,
}

fn value_as_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn value_is_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_i64() != Some(0) && n.as_u64() != Some(0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

fn value_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// 按 `(subject, offset, inode, deleted, image_sha256)` 对取证发现记录分组，
/// 并保持首次出现的插入顺序（对应 `core-contract.md` §3.3）。
pub fn group_findings(records: &[AuditRecord]) -> Vec<FindingGroup> {
    let mut index_by_key: HashMap<FindingGroupKey, usize> = HashMap::new();
    let mut groups: Vec<FindingGroup> = Vec::new();

    for record in records {
        if operation_title(&record.action).is_none() {
            continue;
        }
        let d = &record.details;
        let offset = d.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let inode = value_as_string(d.get("inode"));
        let deleted = d.get("deleted").and_then(Value::as_bool).unwrap_or(false);
        let image_sha256 = d
            .get("image_sha256")
            .and_then(Value::as_str)
            .map(str::to_string);

        let key = FindingGroupKey {
            subject: record.subject.clone(),
            offset,
            inode,
            deleted,
            image_sha256,
        };
        if let Some(&idx) = index_by_key.get(&key) {
            groups[idx].records.push(record.clone());
        } else {
            let idx = groups.len();
            index_by_key.insert(key.clone(), idx);
            groups.push(FindingGroup {
                key,
                records: vec![record.clone()],
            });
        }
    }

    groups
}

/// 以纯文本明细格式渲染取证发现，与 `forensic/core/findings.py::findings_text` 保持一致。
pub fn findings_text(records: &[AuditRecord]) -> String {
    let groups = group_findings(records);
    let mut sections = Vec::with_capacity(groups.len());

    for group in groups {
        let k = &group.key;
        let status = if k.deleted { "已删除" } else { "现存" };
        let image_hash = k
            .image_sha256
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("记录时待固定");
        let mut lines = vec![
            format!(
                "{}  ·  分区偏移 {} 扇区  ·  inode {}  ·  {}",
                k.subject, k.offset, k.inode, status
            ),
            format!("来源镜像 SHA-256：{image_hash}"),
        ];
        for r in &group.records {
            let d = &r.details;
            let op = operation_title(&r.action).unwrap_or(&r.action);
            lines.push(format!(
                "#{}  {}  [{}]  {}  {}  {}",
                r.seq,
                display_iso_time(&r.timestamp, true),
                audit_origin_label(r),
                r.actor,
                op,
                r.result
            ));
            if let Some(size) = d.get("size").and_then(Value::as_u64) {
                let recorded = d
                    .get("recorded_size")
                    .and_then(Value::as_u64)
                    .unwrap_or(size);
                lines.push(format!("  读取 {size} / {recorded} 字节"));
            }
            for &(key, label) in &[
                ("note", "笔记"),
                ("sha256", "读取内容 SHA-256"),
                ("comparison", "对照文件"),
                ("comparison_sha256", "对照 SHA-256"),
                ("source_note", "来源状态"),
                ("source_verification", "操作时的完整性状态"),
                ("read_note", "读取说明"),
                ("error", "错误"),
            ] {
                if let Some(val) = d.get(key)
                    && value_is_truthy(Some(val))
                {
                    lines.push(format!("  {label}：{}", value_display(val)));
                }
            }
        }
        sections.push(lines.join("\n"));
    }

    sections.join("\n\n")
}

/// [`export_findings`] 的输出摘要。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportFindingsResult {
    pub summary_path: PathBuf,
    pub exported_count: usize,
    pub failed: Vec<(String, String)>,
}

/// 批量导出 `groups` 引用的证据文件，生成 `exports/取证发现汇总_<8hex>.md`
/// 并追加 `FINDINGS_EXPORT` 审计记录（对应 `core-contract.md` §3.3）。
pub fn export_findings(case: &mut Case, groups: &[FindingGroup]) -> CoreResult<ExportFindingsResult> {
    if groups.is_empty() {
        return Err(CoreError::InvalidInput(
            "当前没有可导出的取证发现。".to_string(),
        ));
    }
    if case.data().evidence.is_none() {
        return Err(CoreError::InvalidInput("当前案件尚未加载镜像。".to_string()));
    }

    // 仅收集待导出取证发现涉及的目标键，避免克隆整个大清单的几十万条记录。
    let mut needed_keys: std::collections::HashSet<(&str, u64, &str, bool)> =
        std::collections::HashSet::with_capacity(groups.len());
    for group in groups {
        needed_keys.insert((
            group.key.subject.as_str(),
            group.key.offset,
            group.key.inode.as_str(),
            group.key.deleted,
        ));
    }

    let mut entry_map = HashMap::with_capacity(needed_keys.len());
    for entry in case.displayed_entries() {
        let probe = (
            entry.path.as_str(),
            entry.offset,
            entry.inode.as_str(),
            entry.deleted,
        );
        if needed_keys.contains(&probe) {
            let key = (
                entry.path.clone(),
                entry.offset,
                entry.inode.clone(),
                entry.deleted,
            );
            entry_map.entry(key).or_insert_with(|| entry.clone());
            if entry_map.len() == needed_keys.len() {
                break;
            }
        }
    }

    let mut results: Vec<(&FindingGroup, Option<PathBuf>, Option<String>)> =
        Vec::with_capacity(groups.len());
    let mut exported_count = 0usize;
    let mut failed: Vec<(String, String)> = Vec::new();

    for group in groups {
        let key = (
            group.key.subject.clone(),
            group.key.offset,
            group.key.inode.clone(),
            group.key.deleted,
        );
        let entry_opt = entry_map.get(&key);
        match entry_opt {
            Some(entry) if can_export(entry) => match case.export(entry, None) {
                Ok(dest) => {
                    exported_count += 1;
                    results.push((group, Some(dest), None));
                }
                Err(err) => {
                    let reason = err.to_string();
                    failed.push((group.key.subject.clone(), reason.clone()));
                    results.push((group, None, Some(reason)));
                }
            },
            _ => {
                let reason =
                    "当前文件清单中未找到对应条目（大镜像请先建立完整文件索引或进入所在目录）"
                        .to_string();
                failed.push((group.key.subject.clone(), reason.clone()));
                results.push((group, None, Some(reason)));
            }
        }
    }

    let uuid_hex = Uuid::new_v4().simple().to_string();
    let summary_name = format!("取证发现汇总_{}.md", &uuid_hex[..8]);
    let summary_path = case.folder().join("exports").join(&summary_name);
    let data = case.data();

    let mut lines: Vec<String> = vec![
        format!("# 取证发现一键导出汇总 · {}", data.number),
        String::new(),
        format!("- 导出时间（UTC+8）：{}", display_iso_time(&now(), true)),
        format!("- 取证人员：{} · 对象：{}", data.examiner, data.target),
        format!(
            "- 发现文件数：{} · 成功导出文件：{} · 跳过/失败：{}",
            groups.len(),
            exported_count,
            failed.len()
        ),
        String::new(),
        "## 导出清单".to_string(),
        String::new(),
        "| 序号 | 镜像内路径 | 状态 | 分区偏移 | inode | 导出结果 |".to_string(),
        "| --- | --- | --- | --- | --- | --- |".to_string(),
    ];

    for (idx, (group, dest, err)) in results.iter().enumerate() {
        let number = idx + 1;
        let status = if group.key.deleted { "已删除" } else { "现存" };
        let outcome = match dest {
            Some(p) => p
                .strip_prefix(case.folder())
                .unwrap_or(p)
                .to_string_lossy()
                .into_owned(),
            None => format!("未导出：{}", err.as_deref().unwrap_or("")),
        };
        let safe_path = group.key.subject.replace('|', "\\|");
        let safe_out = outcome.replace('|', "\\|");
        lines.push(format!(
            "| {number} | `{safe_path}` | {status} | {} | `{}` | {safe_out} |",
            group.key.offset, group.key.inode
        ));
    }

    lines.push(String::new());
    lines.push("## 取证记录明细".to_string());
    lines.push(String::new());

    for (idx, (group, dest, err)) in results.iter().enumerate() {
        let number = idx + 1;
        let status = if group.key.deleted { "已删除" } else { "现存" };
        let image_hash = group
            .key
            .image_sha256
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("记录时待固定");
        lines.push(format!("### {number}. {}", group.key.subject));
        lines.push(format!(
            "- 状态：{status} · 分区偏移：{} 扇区 · inode：`{}`",
            group.key.offset, group.key.inode
        ));
        lines.push(format!("- 来源镜像 SHA-256：`{image_hash}`"));
        if let Some(p) = dest {
            lines.push(format!("- 导出副本：`{}`", p.display()));
        } else if let Some(msg) = err {
            lines.push(format!("- 导出说明：{msg}"));
        }
        for r in &group.records {
            let op = operation_title(&r.action).unwrap_or(&r.action);
            lines.push(format!(
                "  - `#{}` {} · [{}] · {} · {} · {}",
                r.seq,
                display_iso_time(&r.timestamp, true),
                audit_origin_label(r),
                r.actor,
                op,
                r.result
            ));
            for &(field, title) in &[
                ("note", "笔记"),
                ("file_byte", "文件内字节偏移"),
                ("sha256", "SHA-256"),
                ("comparison", "对照文件"),
                ("comparison_sha256", "对照 SHA-256"),
                ("source_note", "来源状态"),
                ("source_verification", "完整性状态"),
                ("read_note", "读取说明"),
                ("error", "错误"),
            ] {
                if let Some(v) = r.details.get(field) {
                    let s = value_display(v);
                    if !s.is_empty() {
                        lines.push(format!("    - {title}：{s}"));
                    }
                }
            }
        }
        lines.push(String::new());
    }

    let raw = lines.join("\n").into_bytes();
    fs::write(&summary_path, &raw)?;
    let digest = sha256_hex(&raw);

    let mut details = Map::new();
    details.insert("total".to_string(), Value::from(groups.len() as u64));
    details.insert("exported".to_string(), Value::from(exported_count as u64));
    details.insert("failed".to_string(), Value::from(failed.len() as u64));
    details.insert("sha256".to_string(), Value::String(digest));
    case.log(
        "FINDINGS_EXPORT",
        &summary_name,
        if failed.is_empty() { "成功" } else { "部分导出" },
        details,
    )?;

    Ok(ExportFindingsResult {
        summary_path,
        exported_count,
        failed,
    })
}
