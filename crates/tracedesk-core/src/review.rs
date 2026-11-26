//! 可核验复核包构建器（`reports/report_<12hex>.zip` + `.zip.sha256`）
//! 与原生 Rust 复核包校验器（`verify_bundle` / `verify_bundle_detailed`），
//! 与内嵌 `verify_bundle.py` 保持 100% 兼容（对应 `core-contract.md` §2.5）。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tracedesk_engines::{TskCli, sha256_file};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::case::{Case, ExportRecord, GENESIS_HASH};
use crate::coverage::source_status;
use crate::error::{CoreError, CoreResult};
use crate::findings::operation_title;
use crate::formatting::{canonical_json_value, format_commas, hex_lower, sha256_hex};
use crate::paths::{is_within, resolve_clean, strip_verbatim_prefix};

/// 编译期嵌入的独立校验脚本 `verify_bundle.py` 原始字节。
pub const EMBEDDED_VERIFY_BUNDLE_PY: &[u8] = include_bytes!("../resources/verify_bundle.py");

/// 构建复核包前检查得到的单条历史导出记录状态。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleExportRow {
    pub index: usize,
    pub item: ExportRecord,
    pub path: PathBuf,
    pub relative: String,
    pub display_path: String,
    pub source: String,
    pub offset: u64,
    pub inode: String,
    pub size: u64,
    pub sha256: String,
    pub time: String,
    pub exists: bool,
    pub missing_reason: String,
}

/// 构建复核包前检查得到的单条历史内容搜索记录状态（`reports/search_*.json`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleSearchRow {
    pub index: usize,
    pub seq: u64,
    pub name: String,
    pub path: PathBuf,
    pub display_path: String,
    pub query: String,
    pub encoding: String,
    pub hits: u64,
    pub result: String,
    pub sha256: String,
    pub time: String,
    pub exists: bool,
    pub missing_reason: String,
}

/// 调用 [`build_bundle`] 时控制按需纳入材料的选项。
#[derive(Debug, Clone, Default)]
pub struct BuildBundleOptions {
    /// 要纳入的从 1 开始的导出记录序号列表；为 `None` 时全选所有导出记录。
    pub selected_export_indices: Option<Vec<usize>>,
    /// 要纳入的从 1 开始的搜索记录序号列表；为 `None` 时全选所有搜索记录。
    pub selected_search_indices: Option<Vec<usize>>,
    /// 若为 `true`，缺失的已选导出/搜索项记为省略而不报错中止。
    pub skip_missing: bool,
}

/// [`build_bundle`] 的返回结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildBundleResult {
    pub bundle_path: PathBuf,
    pub sha256_path: PathBuf,
    pub sha256: String,
    pub included_exports: usize,
    pub omitted_exports: usize,
    pub missing_exports: usize,
    pub included_searches: usize,
    pub omitted_searches: usize,
    pub missing_searches: usize,
}

/// 复核包单个成员的核验明细（供桌面端可视化核验面板展示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleMemberCheck {
    /// ZIP 内成员路径（如 `report.md`、`report.html`、`exports/1/CASE.TXT`）。
    pub path: String,
    /// 成员类别：`report` / `export` / `search` / `audit` / `manifest` / `script` / `doc` / `other`。
    pub category: String,
    /// 校验状态：`ok` / `mismatch` / `missing` / `extra`。
    pub status: String,
    /// `SHA256SUMS.json` 中记录的期望 SHA-256（多余成员时为 `None`）。
    pub expected_sha256: Option<String>,
    /// 实际解压计算得到的 SHA-256（缺失或不可读时为 `None`）。
    pub actual_sha256: Option<String>,
    /// 实际解压字节数（缺失或不可读时为 `None`）。
    pub size: Option<u64>,
    /// 面向用户的中文校验说明。
    pub message: String,
}

/// 复核包跨文件审计链交叉核对单项结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleCrossCheck {
    /// 交叉校验项名称。
    pub name: String,
    /// 校验状态：`ok` / `mismatch` / `skipped`。
    pub status: String,
    /// 面向用户的中文校验说明。
    pub message: String,
}

/// 面向桌面端可视化核验面板的完整复核包校验结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleVerificationDetail {
    /// 整体验签是否通过（所有外部摘要、成员摘要、审计链、清单与交叉校验均无错误）。
    pub ok: bool,
    /// 被核验的复核包路径。
    pub bundle_path: String,
    /// 复核包 ZIP 整体 SHA-256。
    pub bundle_sha256: String,
    /// 参与比对的期望外部 SHA-256（手动输入或自动读取伴随 `.sha256` 文件）。
    pub expected_sha256: Option<String>,
    /// 期望外部 SHA-256 来源：`"manual"` / `"sidecar"` / `"none"`。
    pub sha256_source: String,
    /// 外部 SHA-256 比对是否一致（当 `sha256_source == "none"` 时为 `None`）。
    pub sha256_matched: Option<bool>,
    /// `audit.jsonl` 哈希链及 `audit.head` 尾部锚点是否全部通过。
    pub audit_valid: bool,
    /// `audit.jsonl` 解析到的记录总数。
    pub audit_count: usize,
    /// `audit.jsonl` 计算得到的最终链尾哈希。
    pub audit_head: String,
    /// 审计链失败时的精确错误说明（正常时为 `None`）。
    pub audit_error: Option<String>,
    /// `manifest.json` 结构、链尾锚点及导出/发现一致性校验是否通过。
    pub manifest_valid: bool,
    /// 复核包内各成员的逐项哈希与结构核验明细。
    pub members: Vec<BundleMemberCheck>,
    /// 跨文件审计链交叉核对明细。
    pub cross_checks: Vec<BundleCrossCheck>,
    /// 汇总后的全部错误列表（`ok == true` 时为空）。
    pub errors: Vec<String>,
}

/// 判断 `REPORT_GENERATE` 审计记录是否对应 HTML 格式报告。
fn is_html_report_audit_record(subject: &str, details: &Map<String, Value>) -> bool {
    if let Some(fmt) = details.get("format").and_then(Value::as_str)
        && fmt.trim().eq_ignore_ascii_case("html")
    {
        return true;
    }
    subject.trim().to_ascii_lowercase().ends_with(".html")
}

/// 解析导出记录在 `<case_dir>/exports/` 下的本地文件路径，即使案件目录曾被整体移动仍可定位。
///
/// - 新版导出（含同名序号后缀，如 `NOTES(1).TXT`）均直接位于 `<case_dir>/exports/` 下；
/// - 保留对历史案件中 `同名副本-*` 子目录导出记录的向后兼容解析。
pub fn resolve_export_path(case: &Case, item: &ExportRecord) -> CoreResult<(PathBuf, PathBuf)> {
    let original = Path::new(&item.path);
    let file_name = original
        .file_name()
        .ok_or_else(|| CoreError::InvalidInput("导出记录文件名无效".to_string()))?;
    // 兼容历史案件中的 `exports/同名副本-*/<filename>` 目录结构；新版序号命名直接按文件名定位。
    let relative = if let Some(parent_name) = original
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        && parent_name.starts_with("同名副本-")
    {
        PathBuf::from(parent_name).join(file_name)
    } else {
        PathBuf::from(file_name)
    };
    let exports_root = resolve_clean(&case.folder().join("exports"));
    let resolved = resolve_clean(&exports_root.join(&relative));
    if !is_within(&resolved, &exports_root) {
        return Err(CoreError::InvalidInput(
            "导出副本不在案件目录内".to_string(),
        ));
    }
    Ok((resolved, relative))
}

/// 检查 `case.data().exports` 中所有历史导出副本的本地存在状态。
pub fn inspect_bundle_exports(case: &Case) -> CoreResult<Vec<BundleExportRow>> {
    let mut rows = Vec::with_capacity(case.data().exports.len());
    for (idx, item) in case.data().exports.iter().enumerate() {
        let index = idx + 1;
        let (path, relative) = resolve_export_path(case, item)?;
        let exists = path.is_file();
        let rel_str = relative.to_string_lossy().into_owned();
        let display_path = format!("exports\\{rel_str}");
        let missing_reason = if exists {
            String::new()
        } else {
            format!("本地副本缺失（{display_path}）")
        };
        rows.push(BundleExportRow {
            index,
            item: item.clone(),
            path,
            relative: rel_str,
            display_path,
            source: item.source.clone(),
            offset: item.offset,
            inode: item.inode.clone(),
            size: item.size,
            sha256: item.sha256.clone(),
            time: item.time.clone(),
            exists,
            missing_reason,
        });
    }
    Ok(rows)
}

/// 检查案件审计链中所有 `CONTENT_SEARCH` 记录对应的本地 JSON 文件存在状态。
pub fn inspect_bundle_searches(case: &mut Case) -> CoreResult<Vec<BundleSearchRow>> {
    let records = case.check_audit()?;
    let reports_root = resolve_clean(&case.folder().join("reports"));
    let mut rows = Vec::new();
    let mut index = 0usize;

    for record in records {
        if record.action != "CONTENT_SEARCH" {
            continue;
        }
        index += 1;
        let name = record.subject.clone();
        let name_path = Path::new(&name);
        if name_path.file_name().and_then(|s| s.to_str()) != Some(name.as_str()) {
            return Err(CoreError::InvalidInput("搜索记录名称无效".to_string()));
        }
        let path = resolve_clean(&reports_root.join(&name));
        if !is_within(&path, &reports_root) {
            return Err(CoreError::InvalidInput(
                "搜索记录不在案件目录内".to_string(),
            ));
        }
        let exists = path.is_file();
        let display_path = format!("reports\\{name}");
        let missing_reason = if exists {
            String::new()
        } else {
            format!("本地搜索记录缺失（{display_path}）")
        };
        let d = &record.details;
        rows.push(BundleSearchRow {
            index,
            seq: record.seq,
            name,
            path,
            display_path,
            query: d
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            encoding: d
                .get("encoding")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            hits: d.get("hits").and_then(Value::as_u64).unwrap_or(0),
            result: record.result,
            sha256: d
                .get("sha256")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            time: record.timestamp,
            exists,
            missing_reason,
        });
    }
    Ok(rows)
}

/// 将缺失的导出副本与搜索记录格式化为可读的中文清单。
pub fn format_missing_materials(
    missing_exports: &[BundleExportRow],
    missing_searches: &[BundleSearchRow],
) -> String {
    let mut sections: Vec<String> = Vec::new();
    if !missing_exports.is_empty() {
        let mut lines = vec![format!(
            "以下 {} 条历史导出记录在本地 exports 目录中缺失（可能已被删除或被安全软件隔离）：",
            missing_exports.len()
        )];
        for row in missing_exports {
            lines.push(format!(
                "- 导出 #{} {}（镜像内路径：{}，{} 字节）",
                row.index,
                row.display_path,
                row.source,
                format_commas(row.size)
            ));
        }
        sections.push(lines.join("\n"));
    }
    if !missing_searches.is_empty() {
        let mut lines = vec![format!(
            "以下 {} 条历史内容搜索记录在本地 reports 目录中缺失（可能已被清理或移动）：",
            missing_searches.len()
        )];
        for row in missing_searches {
            lines.push(format!(
                "- 搜索 #{}（审计 #{}）{}（关键词：{}，编码：{}，命中 {} 条）",
                row.index, row.seq, row.display_path, row.query, row.encoding, row.hits
            ));
        }
        sections.push(lines.join("\n"));
    }
    sections.join("\n\n")
}

/// 构建可核验 ZIP64 复核包（`reports/report_<12hex>.zip`）及配套 `.zip.sha256` 摘要文件，
/// 并追加 `REVIEW_EXPORT` 审计记录（对应 `core-contract.md` §2.5）。
///
/// 构建期间仅执行一次完整性前置校验，并同步生成配套的最新 Markdown（`report.md`）与
/// 离线单文件 HTML 报告（`report.html`），确保两份报告内容同源且均纳入 `audit.jsonl`、
/// `SHA256SUMS.json` 与 `manifest.json.html_report` 交叉核验保护。
pub fn build_bundle(
    case: &mut Case,
    options: &BuildBundleOptions,
    tsk: Option<&TskCli>,
) -> CoreResult<BuildBundleResult> {
    let export_rows = inspect_bundle_exports(case)?;
    let search_rows = inspect_bundle_searches(case)?;

    let chosen_exports: HashSet<usize> = match options.selected_export_indices {
        Some(ref selected) => {
            let valid: HashSet<usize> = export_rows.iter().map(|r| r.index).collect();
            let chosen: HashSet<usize> = selected.iter().copied().collect();
            let mut invalid: Vec<usize> = chosen.difference(&valid).copied().collect();
            invalid.sort_unstable();
            if !invalid.is_empty() {
                let s = invalid
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(CoreError::InvalidInput(format!("指定的导出序号无效：{s}")));
            }
            chosen
        }
        None => export_rows.iter().map(|r| r.index).collect(),
    };

    let chosen_searches: HashSet<usize> = match options.selected_search_indices {
        Some(ref selected) => {
            let valid: HashSet<usize> = search_rows.iter().map(|r| r.index).collect();
            let chosen: HashSet<usize> = selected.iter().copied().collect();
            let mut invalid: Vec<usize> = chosen.difference(&valid).copied().collect();
            invalid.sort_unstable();
            if !invalid.is_empty() {
                let s = invalid
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(CoreError::InvalidInput(format!(
                    "指定的搜索记录序号无效：{s}"
                )));
            }
            chosen
        }
        None => search_rows.iter().map(|r| r.index).collect(),
    };

    let missing_selected: Vec<BundleExportRow> = export_rows
        .iter()
        .filter(|r| chosen_exports.contains(&r.index) && !r.exists)
        .cloned()
        .collect();
    let missing_selected_searches: Vec<BundleSearchRow> = search_rows
        .iter()
        .filter(|r| chosen_searches.contains(&r.index) && !r.exists)
        .cloned()
        .collect();

    if (!missing_selected.is_empty() || !missing_selected_searches.is_empty())
        && !options.skip_missing
    {
        return Err(CoreError::MissingMaterials(format!(
            "{}\n请恢复缺失文件，或在复核包选择窗口中取消勾选缺失项后再导出。",
            format_missing_materials(&missing_selected, &missing_selected_searches)
        )));
    }

    // 一次性执行完整性校验并同步生成配套的最新 report.md 与离线 HTML 报告，
    // 校验未通过时立即中止，避免产生孤立报告且不重复做整镜像哈希。
    let (report_path, html_report) = case.generate_bundle_reports(tsk)?;
    if !case
        .data()
        .verification
        .as_ref()
        .is_some_and(|v| v.ok)
    {
        return Err(CoreError::IntegrityFailed(
            "当前镜像与案件固定值不符，不能生成复核包".to_string(),
        ));
    }

    // 一次性同步获取已验链的审计记录及原始 audit.jsonl 字节，消除压缩导出期间的 TOCTOU 窗口。
    let (records, audit_bytes) = case.check_audit_with_raw()?;
    let report_path_str = report_path.to_string_lossy();
    let report_record = records
        .iter()
        .rev()
        .find(|r| {
            r.action == "REPORT_GENERATE"
                && r.result == "成功"
                && r.subject == report_path_str.as_ref()
        })
        .or_else(|| {
            records.iter().rev().find(|r| {
                r.action == "REPORT_GENERATE"
                    && r.result == "成功"
                    && !is_html_report_audit_record(&r.subject, &r.details)
            })
        })
        .ok_or_else(|| CoreError::Other("无法获取最新报告的审计摘要".to_string()))?;
    let report_sha256 = report_record
        .details
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Other("无法获取最新报告的审计摘要".to_string()))?
        .to_string();

    let html_path_str = html_report.path.to_string_lossy();
    let html_record = records
        .iter()
        .rev()
        .find(|r| {
            r.action == "REPORT_GENERATE"
                && r.result == "成功"
                && r.subject == html_path_str.as_ref()
                && is_html_report_audit_record(&r.subject, &r.details)
        })
        .ok_or_else(|| CoreError::Other("无法获取最新 HTML 报告的审计摘要".to_string()))?;
    let html_sha256 = html_record
        .details
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Other("无法获取最新 HTML 报告的审计摘要".to_string()))?
        .to_string();
    if html_sha256 != html_report.sha256 {
        return Err(CoreError::IntegrityFailed(
            "最新 HTML 报告摘要与审计链记录不一致".to_string(),
        ));
    }

    let audit_head = records
        .last()
        .map(|r| r.hash.clone())
        .ok_or_else(|| CoreError::Other("审计链为空".to_string()))?;

    let discovered;
    let tool = match tsk {
        Some(t) => t,
        None => {
            discovered = TskCli::discover(None)?;
            &discovered
        }
    };
    let tsk_version = tool.version()?;

    let target = report_path.with_extension("zip");
    let temporary = target.with_extension("partial");
    let zip_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .large_file(true);

    let mut checksums: BTreeMap<String, String> = BTreeMap::new();
    let mut included_exports_manifest: Vec<Value> = Vec::new();
    let mut omitted_exports_manifest: Vec<Value> = Vec::new();
    let mut included_searches = 0usize;
    let mut omitted_searches_manifest: Vec<Value> = Vec::new();
    let mut missing_exports_count = 0usize;
    let mut missing_searches_count = 0usize;
    let mut bundled_html_meta: Option<(String, u64)> = None;

    let write_outcome = (|| -> CoreResult<()> {
        let temp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        // 使用 256 KiB 缓冲写入器包裹 ZIP 文件句柄，减少文件头与压缩块的碎片写系统调用。
        let mut archive = ZipWriter::new(BufWriter::with_capacity(256 * 1024, temp_file));
        let mut copy_buf = vec![0u8; 1024 * 1024];

        let put_bytes = |archive: &mut ZipWriter<BufWriter<File>>,
                         checksums: &mut BTreeMap<String, String>,
                         name: &str,
                         raw: &[u8]|
         -> CoreResult<()> {
            archive.start_file(name, zip_options)?;
            archive.write_all(raw)?;
            checksums.insert(name.to_string(), sha256_hex(raw));
            Ok(())
        };

        let copy_streaming = |archive: &mut ZipWriter<BufWriter<File>>,
                              checksums: &mut BTreeMap<String, String>,
                              buf: &mut [u8],
                              src_path: &Path,
                              member_name: &str,
                              expected_sha256: Option<&str>|
         -> CoreResult<(String, u64)> {
            let mut source = File::open(src_path)?;
            archive.start_file(member_name, zip_options)?;
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            loop {
                let n = source.read(buf)?;
                if n == 0 {
                    break;
                }
                archive.write_all(&buf[..n])?;
                hasher.update(&buf[..n]);
                total = total.saturating_add(n as u64);
            }
            let actual = hex_lower(&hasher.finalize());
            if let Some(expected) = expected_sha256
                && actual != expected
            {
                let fname = src_path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                return Err(CoreError::IntegrityFailed(format!(
                    "材料摘要不一致：{fname}"
                )));
            }
            checksums.insert(member_name.to_string(), actual.clone());
            Ok((actual, total))
        };

        // 1. report.md
        copy_streaming(
            &mut archive,
            &mut checksums,
            &mut copy_buf,
            &report_path,
            "report.md",
            Some(&report_sha256),
        )?;

        // 1b. report.html（与本次 report.md 同步生成的最新离线 HTML 报告，始终打包并纳入哈希保护）
        let (html_sha, html_len) = copy_streaming(
            &mut archive,
            &mut checksums,
            &mut copy_buf,
            &html_report.path,
            "report.html",
            Some(&html_sha256),
        )?;
        bundled_html_meta = Some((html_sha, html_len));

        // 2. exports/<index>/<filename>
        for row in &export_rows {
            if !chosen_exports.contains(&row.index) {
                let mut val = serde_json::to_value(&row.item)?;
                let reason = if !row.exists {
                    missing_exports_count += 1;
                    "本地副本缺失"
                } else {
                    "导出复核包时未勾选"
                };
                if let Some(m) = val.as_object_mut() {
                    m.insert("export_index".to_string(), Value::from(row.index as u64));
                    m.insert("reason".to_string(), Value::String(reason.to_string()));
                }
                omitted_exports_manifest.push(val);
                continue;
            }
            if !row.exists {
                missing_exports_count += 1;
                let mut val = serde_json::to_value(&row.item)?;
                if let Some(m) = val.as_object_mut() {
                    m.insert("export_index".to_string(), Value::from(row.index as u64));
                    m.insert(
                        "reason".to_string(),
                        Value::String("本地副本缺失".to_string()),
                    );
                }
                omitted_exports_manifest.push(val);
                continue;
            }
            let fname = row
                .path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let member = format!("exports/{}/{fname}", row.index);
            copy_streaming(
                &mut archive,
                &mut checksums,
                &mut copy_buf,
                &row.path,
                &member,
                Some(&row.item.sha256),
            )?;
            let mut val = serde_json::to_value(&row.item)?;
            if let Some(m) = val.as_object_mut() {
                m.insert("member".to_string(), Value::String(member));
                m.insert(
                    "recorded_size".to_string(),
                    Value::from(row.item.recorded_size.unwrap_or(row.item.size)),
                );
            }
            included_exports_manifest.push(val);
        }

        // 3. searches/<search_*.json>
        for row in &search_rows {
            if !chosen_searches.contains(&row.index) {
                let reason = if !row.exists {
                    missing_searches_count += 1;
                    "本地搜索记录缺失"
                } else {
                    "导出复核包时未勾选"
                };
                omitted_searches_manifest.push(serde_json::json!({
                    "search_index": row.index,
                    "seq": row.seq,
                    "name": row.name,
                    "query": row.query,
                    "encoding": row.encoding,
                    "hits": row.hits,
                    "sha256": row.sha256,
                    "reason": reason,
                }));
                continue;
            }
            if !row.exists {
                missing_searches_count += 1;
                omitted_searches_manifest.push(serde_json::json!({
                    "search_index": row.index,
                    "seq": row.seq,
                    "name": row.name,
                    "query": row.query,
                    "encoding": row.encoding,
                    "hits": row.hits,
                    "sha256": row.sha256,
                    "reason": "本地搜索记录缺失",
                }));
                continue;
            }
            let member = format!("searches/{}", row.name);
            copy_streaming(
                &mut archive,
                &mut checksums,
                &mut copy_buf,
                &row.path,
                &member,
                Some(&row.sha256),
            )?;
            included_searches += 1;
        }

        // 4. audit.jsonl（写入验链快照的精确原始字节，确保与 audit.head 绝对一致）
        put_bytes(&mut archive, &mut checksums, "audit.jsonl", &audit_bytes)?;

        // 5. audit.head（严格 64 字节 ASCII，不含尾部换行符）
        put_bytes(
            &mut archive,
            &mut checksums,
            "audit.head",
            audit_head.as_bytes(),
        )?;

        // 6. verify_bundle.py（内嵌独立校验脚本）
        put_bytes(
            &mut archive,
            &mut checksums,
            "verify_bundle.py",
            EMBEDDED_VERIFY_BUNDLE_PY,
        )?;

        // 7. manifest.json（保持 format_version=1 向后兼容，并记录本次同步生成的 html_report 元数据）
        let data = case.data();
        let evidence = data
            .evidence
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("请先加载镜像".to_string()))?;
        let findings: Vec<_> = records
            .iter()
            .filter(|r| operation_title(&r.action).is_some())
            .cloned()
            .collect();

        let mut manifest = serde_json::json!({
            "format_version": 1,
            "case_id": data.id,
            "number": data.number,
            "examiner": data.examiner,
            "runtime_version": "Rust / TraceDesk 2.0",
            "python_version": "native-rust",
            "tsk_version": tsk_version,
            "evidence": evidence,
            "verification": data.verification,
            "source_comparison": source_status(evidence),
            "exports": included_exports_manifest,
            "omitted_exports": omitted_exports_manifest,
            "omitted_searches": omitted_searches_manifest,
            "findings": findings,
            "audit_head": audit_head,
        });
        if let Some((ref html_sha, html_len)) = bundled_html_meta
            && let Some(obj) = manifest.as_object_mut()
        {
            obj.insert(
                "html_report".to_string(),
                serde_json::json!({
                    "member": "report.html",
                    "sha256": html_sha,
                    "size": html_len,
                }),
            );
        }
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        put_bytes(
            &mut archive,
            &mut checksums,
            "manifest.json",
            manifest_json.as_bytes(),
        )?;

        // 8. 复核说明.txt
        let mut instructions = String::from(
            "1. 与交付方单独保存的 ZIP SHA-256 比对；包内清单不能证明签名身份。\n\
             2. 可使用独立取得的 tracedesk-cli verify-bundle 或包内附带的 verify_bundle.py 核验 ZIP，或解压后逐项核对 SHA256SUMS.json。\n\
             3. 原始镜像不在包内。独立取得镜像，核对 manifest.json 中的 SHA-256、覆盖范围和交付方摘要。\n\
             4. 用 TSK icat -i raw -o 分区扇区偏移 镜像 inode 提取内容；EWF 改用 -i ewf 并指定 E01 首段；删除且未重分配时加 -r。\n\
             5. 搜索命中 file_byte 是文件流内从零起的字节偏移；按 needle 的十六进制字节复查。\n\
             6. 核对 exports 的来源、实际长度、摘要及删除恢复限制，按序号关联 findings 与 audit.jsonl。",
        );
        if !omitted_exports_manifest.is_empty() || !omitted_searches_manifest.is_empty() {
            instructions.push_str(&format!(
                "\n7. 本次复核包按需纳入 {} 个导出副本、{} 份搜索记录，另有 {} 条历史导出记录与 {} 条历史搜索记录未打入（未勾选或本地文件缺失），完整明细与原因见 manifest.json 的 omitted_exports / omitted_searches 字段。",
                included_exports_manifest.len(),
                included_searches,
                omitted_exports_manifest.len(),
                omitted_searches_manifest.len(),
            ));
        }
        put_bytes(
            &mut archive,
            &mut checksums,
            "复核说明.txt",
            instructions.as_bytes(),
        )?;

        // 9. SHA256SUMS.json（将除自身外的每个 ZIP 成员映射到 64 位十六进制 SHA-256）
        let sums_json = serde_json::to_string_pretty(&checksums)?;
        archive.start_file("SHA256SUMS.json", zip_options)?;
        archive.write_all(sums_json.as_bytes())?;

        let mut finished_file = archive.finish()?;
        finished_file.flush()?;
        Ok(())
    })();

    if let Err(err) = write_outcome {
        let _ = fs::remove_file(&temporary);
        return Err(err);
    }

    if let Err(err) = fs::rename(&temporary, &target) {
        let _ = fs::remove_file(&temporary);
        return Err(CoreError::Io(err));
    }

    let target_clean = strip_verbatim_prefix(&target);
    let digest = sha256_file(&target_clean, None, None)?;
    let target_name = target_clean
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sha256_path = target_clean.with_extension("zip.sha256");
    fs::write(&sha256_path, format!("{digest}  {target_name}\n").as_bytes())?;

    let mut log_details = Map::new();
    log_details.insert("sha256".to_string(), Value::String(digest.clone()));
    log_details.insert(
        "included_exports".to_string(),
        Value::from(included_exports_manifest.len() as u64),
    );
    log_details.insert(
        "omitted_exports".to_string(),
        Value::from(omitted_exports_manifest.len() as u64),
    );
    log_details.insert(
        "missing_exports".to_string(),
        Value::from(missing_exports_count as u64),
    );
    log_details.insert(
        "included_searches".to_string(),
        Value::from(included_searches as u64),
    );
    log_details.insert(
        "omitted_searches".to_string(),
        Value::from(omitted_searches_manifest.len() as u64),
    );
    log_details.insert(
        "missing_searches".to_string(),
        Value::from(missing_searches_count as u64),
    );
    if bundled_html_meta.is_some() {
        log_details.insert("included_html_report".to_string(), Value::Bool(true));
    }
    case.log("REVIEW_EXPORT", &target_name, "成功", log_details)?;

    Ok(BuildBundleResult {
        bundle_path: target_clean,
        sha256_path,
        sha256: digest,
        included_exports: included_exports_manifest.len(),
        omitted_exports: omitted_exports_manifest.len(),
        missing_exports: missing_exports_count,
        included_searches,
        omitted_searches: omitted_searches_manifest.len(),
        missing_searches: missing_searches_count,
    })
}

fn sha256_and_len_with_buf<R: Read>(mut reader: R, buf: &mut [u8]) -> CoreResult<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    loop {
        let n = reader.read(buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex_lower(&hasher.finalize()), total))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 构造伴随摘要文件路径（`<bundle_path>.sha256`）并尝试解析其中的 64 位十六进制 SHA-256。
pub fn read_sidecar_sha256(bundle_path: &Path) -> Option<String> {
    let mut os: OsString = bundle_path.as_os_str().to_os_string();
    os.push(".sha256");
    let sidecar = PathBuf::from(os);
    if !sidecar.is_file() {
        return None;
    }
    let raw = fs::read_to_string(&sidecar).ok()?;
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    let token = trimmed.split_whitespace().next()?;
    if is_hex64(token) {
        Some(token.to_ascii_lowercase())
    } else {
        None
    }
}

fn classify_member(path: &str) -> &'static str {
    if path == "report.md" || path == "report.html" {
        "report"
    } else if path.starts_with("exports/") {
        "export"
    } else if path.starts_with("searches/") {
        "search"
    } else if path == "audit.jsonl" || path == "audit.head" {
        "audit"
    } else if path == "manifest.json" || path == "SHA256SUMS.json" {
        "manifest"
    } else if path == "verify_bundle.py" {
        "script"
    } else if path == "复核说明.txt" {
        "doc"
    } else {
        "other"
    }
}

/// 从已验链的审计记录中提取跨文件交叉校验所需的摘要索引。
struct AuditCrossIndex {
    last_md_report_sha: Option<String>,
    last_html_report_sha: Option<String>,
    search_digests: HashMap<String, String>,
    search_subjects: HashSet<String>,
    findings: Vec<Value>,
}

fn build_audit_cross_index(records: &[Value]) -> AuditCrossIndex {
    let mut last_md_report_sha = None;
    let mut last_html_report_sha = None;
    let mut search_digests = HashMap::new();
    let mut search_subjects = HashSet::new();
    let mut findings = Vec::new();

    for rec in records {
        let action = rec.get("action").and_then(Value::as_str).unwrap_or("");
        let result = rec.get("result").and_then(Value::as_str).unwrap_or("");
        let subject = rec.get("subject").and_then(Value::as_str).unwrap_or("");
        let details = rec.get("details").and_then(Value::as_object);
        let sha = details
            .and_then(|d| d.get("sha256"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if action == "REPORT_GENERATE" && result == "成功" {
            if let Some(digest) = sha {
                let is_html = details
                    .map(|d| is_html_report_audit_record(subject, d))
                    .unwrap_or_else(|| subject.to_ascii_lowercase().ends_with(".html"));
                if is_html {
                    last_html_report_sha = Some(digest.to_ascii_lowercase());
                } else {
                    last_md_report_sha = Some(digest.to_ascii_lowercase());
                }
            }
        } else if action == "CONTENT_SEARCH" && !subject.is_empty() {
            search_subjects.insert(subject.to_string());
            if let Some(digest) = sha {
                search_digests.insert(subject.to_string(), digest.to_ascii_lowercase());
            }
        } else if operation_title(action).is_some() {
            findings.push(rec.clone());
        }
    }

    AuditCrossIndex {
        last_md_report_sha,
        last_html_report_sha,
        search_digests,
        search_subjects,
        findings,
    }
}

/// 面向桌面端可视化核验面板的独立复核包全量核验入口。
///
/// - 若 `expected_sha256` 为 `None` 或空串，将自动探测并读取伴随 `<bundle_path>.sha256` 中的 64 位摘要；
/// - 即使检测到成员篡改、审计断链或交叉不一致，仍尽可能完成其余核验步骤并返回完整定位明细（`ok == false`）；
/// - 仅在复核包文件不存在或无法打开时返回 `Err(...)`。
pub fn verify_bundle_detailed(
    bundle_path: &Path,
    expected_sha256: Option<&str>,
) -> CoreResult<BundleVerificationDetail> {
    if !bundle_path.is_file() {
        return Err(CoreError::NotFound(format!(
            "复核包文件不存在：{}",
            bundle_path.display()
        )));
    }

    let mut io_buf = vec![0u8; 1024 * 1024];
    let (bundle_sha256, _) = sha256_and_len_with_buf(File::open(bundle_path)?, &mut io_buf)?;

    let (resolved_expected, sha256_source) = match expected_sha256.map(str::trim).filter(|s| !s.is_empty())
    {
        Some(manual) => (Some(manual.to_ascii_lowercase()), "manual".to_string()),
        None => match read_sidecar_sha256(bundle_path) {
            Some(sidecar) => (Some(sidecar), "sidecar".to_string()),
            None => (None, "none".to_string()),
        },
    };

    let mut errors: Vec<String> = Vec::new();
    let sha256_matched = match resolved_expected.as_deref() {
        Some(exp) => {
            let matched = bundle_sha256 == exp;
            if !matched {
                errors.push("复核包外部 SHA-256 不匹配".to_string());
            }
            Some(matched)
        }
        None => None,
    };

    let mut detail = BundleVerificationDetail {
        ok: false,
        bundle_path: strip_verbatim_prefix(bundle_path)
            .to_string_lossy()
            .into_owned(),
        bundle_sha256,
        expected_sha256: resolved_expected,
        sha256_source,
        sha256_matched,
        audit_valid: false,
        audit_count: 0,
        audit_head: String::new(),
        audit_error: None,
        manifest_valid: false,
        members: Vec::new(),
        cross_checks: Vec::new(),
        errors,
    };

    let file = File::open(bundle_path)?;
    let mut archive = match ZipArchive::new(BufReader::with_capacity(256 * 1024, file)) {
        Ok(zip) => zip,
        Err(err) => {
            detail.errors.push(format!("无法解析 ZIP 复核包结构：{err}"));
            return Ok(detail);
        }
    };

    // 1. 枚举全部 ZIP 成员并检测重复项。
    let mut name_counts: HashMap<String, usize> = HashMap::with_capacity(archive.len());
    let mut duplicate_names: HashSet<String> = HashSet::new();
    for i in 0..archive.len() {
        match archive.by_index(i) {
            Ok(entry) => {
                let name = entry.name().to_string();
                let count = name_counts.entry(name.clone()).or_insert(0);
                *count += 1;
                if *count > 1 {
                    duplicate_names.insert(name);
                }
            }
            Err(err) => {
                detail.errors.push(format!("读取 ZIP 成员索引 #{i} 失败：{err}"));
            }
        }
    }
    if !duplicate_names.is_empty() {
        let mut dup_list: Vec<String> = duplicate_names.iter().cloned().collect();
        dup_list.sort();
        detail.errors.push(format!(
            "成员重复或与清单不一致（重复成员：{}）",
            dup_list.join(", ")
        ));
    }

    // 2. 读取并解析 SHA256SUMS.json。
    let checks: Option<BTreeMap<String, String>> = match archive.by_name("SHA256SUMS.json") {
        Ok(mut entry) => {
            let mut raw = String::new();
            match entry.read_to_string(&mut raw) {
                Ok(_) => match serde_json::from_str::<BTreeMap<String, String>>(&raw) {
                    Ok(map) => Some(map),
                    Err(err) => {
                        detail
                            .errors
                            .push(format!("SHA256SUMS.json 解析失败：{err}"));
                        None
                    }
                },
                Err(err) => {
                    detail
                        .errors
                        .push(format!("读取 SHA256SUMS.json 失败：{err}"));
                    None
                }
            }
        }
        Err(_) => {
            detail.errors.push("复核包缺少 SHA256SUMS.json".to_string());
            None
        }
    };

    // 3. 逐项核对清单内成员与多余/缺失成员，记录实际哈希与解压大小供后续交叉校验复用。
    let mut actual_hashes: HashMap<String, String> = HashMap::new();
    let mut actual_sizes: HashMap<String, u64> = HashMap::new();

    if let Some(ref checks_map) = checks {
        for (member_name, expected_digest) in checks_map {
            let category = classify_member(member_name).to_string();
            if !name_counts.contains_key(member_name) {
                detail.errors.push(format!("成员缺失：{member_name}"));
                detail.members.push(BundleMemberCheck {
                    path: member_name.clone(),
                    category,
                    status: "missing".to_string(),
                    expected_sha256: Some(expected_digest.clone()),
                    actual_sha256: None,
                    size: None,
                    message: "SHA256SUMS.json 中登记的成员在复核包中缺失".to_string(),
                });
                continue;
            }
            match archive.by_name(member_name) {
                Ok(entry) => {
                    let header_size = entry.size();
                    match sha256_and_len_with_buf(entry, &mut io_buf) {
                        Ok((actual_sha, actual_len)) => {
                            actual_hashes.insert(member_name.clone(), actual_sha.clone());
                            actual_sizes.insert(member_name.clone(), actual_len);
                            let hash_ok = actual_sha == *expected_digest;
                            let size_ok = actual_len == header_size;
                            let dup = duplicate_names.contains(member_name);
                            if hash_ok && size_ok && !dup {
                                detail.members.push(BundleMemberCheck {
                                    path: member_name.clone(),
                                    category,
                                    status: "ok".to_string(),
                                    expected_sha256: Some(expected_digest.clone()),
                                    actual_sha256: Some(actual_sha),
                                    size: Some(actual_len),
                                    message: "成员 SHA-256 与解压长度均一致".to_string(),
                                });
                            } else {
                                let msg = if !hash_ok {
                                    format!("成员摘要不匹配：{member_name}")
                                } else if !size_ok {
                                    format!("成员解压长度与 ZIP 头声明不一致：{member_name}")
                                } else {
                                    format!("ZIP 中存在重复同名成员：{member_name}")
                                };
                                detail.errors.push(msg.clone());
                                detail.members.push(BundleMemberCheck {
                                    path: member_name.clone(),
                                    category,
                                    status: "mismatch".to_string(),
                                    expected_sha256: Some(expected_digest.clone()),
                                    actual_sha256: Some(actual_sha),
                                    size: Some(actual_len),
                                    message: msg,
                                });
                            }
                        }
                        Err(err) => {
                            let msg = format!("读取成员失败（{member_name}）：{err}");
                            detail.errors.push(msg.clone());
                            detail.members.push(BundleMemberCheck {
                                path: member_name.clone(),
                                category,
                                status: "mismatch".to_string(),
                                expected_sha256: Some(expected_digest.clone()),
                                actual_sha256: None,
                                size: None,
                                message: msg,
                            });
                        }
                    }
                }
                Err(err) => {
                    let msg = format!("打开成员失败（{member_name}）：{err}");
                    detail.errors.push(msg.clone());
                    detail.members.push(BundleMemberCheck {
                        path: member_name.clone(),
                        category,
                        status: "missing".to_string(),
                        expected_sha256: Some(expected_digest.clone()),
                        actual_sha256: None,
                        size: None,
                        message: msg,
                    });
                }
            }
        }

        // 检测未在 SHA256SUMS.json 中登记的多余成员（排除 SHA256SUMS.json 本身）。
        let mut extra_names: Vec<String> = name_counts
            .keys()
            .filter(|name| name.as_str() != "SHA256SUMS.json" && !checks_map.contains_key(*name))
            .cloned()
            .collect();
        extra_names.sort();
        for extra in extra_names {
            let (actual_sha, actual_len) = archive
                .by_name(&extra)
                .ok()
                .and_then(|entry| sha256_and_len_with_buf(entry, &mut io_buf).ok())
                .map(|(h, l)| (Some(h), Some(l)))
                .unwrap_or((None, None));
            let msg = format!("成员重复或与清单不一致（未登记多余成员：{extra}）");
            detail.errors.push(msg.clone());
            detail.members.push(BundleMemberCheck {
                path: extra.clone(),
                category: classify_member(&extra).to_string(),
                status: "extra".to_string(),
                expected_sha256: None,
                actual_sha256: actual_sha,
                size: actual_len,
                message: "该成员未登记在 SHA256SUMS.json 中".to_string(),
            });
        }
    }
    detail.members.sort_by(|a, b| a.path.cmp(&b.path));

    // 4. 校验 `audit.jsonl` 完整 SHA-256 哈希链并收集记录用于跨文件交叉核对。
    let mut parsed_audit_records: Vec<Value> = Vec::new();
    let mut chain_ok = true;
    let mut computed_head = GENESIS_HASH.to_string();
    match archive.by_name("audit.jsonl") {
        Ok(entry) => {
            let reader = BufReader::new(entry);
            for (idx, line_res) in reader.lines().enumerate() {
                let seq_expected = (idx + 1) as u64;
                detail.audit_count = idx + 1;
                let line = match line_res {
                    Ok(l) => l,
                    Err(err) => {
                        chain_ok = false;
                        let msg = format!("读取 audit.jsonl 第 {seq_expected} 行失败：{err}");
                        detail.audit_error = Some(msg.clone());
                        detail.errors.push(msg);
                        break;
                    }
                };
                let mut obj: Map<String, Value> = match serde_json::from_str(&line) {
                    Ok(o) => o,
                    Err(_) => {
                        chain_ok = false;
                        let msg = format!("审计链不一致：{seq_expected}");
                        detail.audit_error = Some(msg.clone());
                        detail.errors.push(msg);
                        break;
                    }
                };
                let Some(Value::String(recorded)) = obj.remove("hash") else {
                    chain_ok = false;
                    let msg = format!("审计链不一致：{seq_expected}");
                    detail.audit_error = Some(msg.clone());
                    detail.errors.push(msg);
                    break;
                };
                let seq_ok = obj.get("seq").and_then(Value::as_u64) == Some(seq_expected);
                let prev_ok =
                    obj.get("previous").and_then(Value::as_str) == Some(computed_head.as_str());
                let canonical = match canonical_json_value(&Value::Object(obj.clone())) {
                    Ok(c) => c,
                    Err(err) => {
                        chain_ok = false;
                        let msg = format!("审计链规范化失败（#{seq_expected}）：{err}");
                        detail.audit_error = Some(msg.clone());
                        detail.errors.push(msg);
                        break;
                    }
                };
                let computed = sha256_hex(canonical.as_bytes());
                if !seq_ok || !prev_ok || computed != recorded {
                    chain_ok = false;
                    let msg = format!("审计链不一致：{seq_expected}");
                    detail.audit_error = Some(msg.clone());
                    detail.errors.push(msg);
                    break;
                }
                obj.insert("hash".to_string(), Value::String(recorded.clone()));
                parsed_audit_records.push(Value::Object(obj));
                computed_head = recorded;
            }
        }
        Err(_) => {
            chain_ok = false;
            let msg = "复核包缺少 audit.jsonl".to_string();
            detail.audit_error = Some(msg.clone());
            detail.errors.push(msg);
        }
    }
    detail.audit_head = computed_head.clone();

    // 5. 严格校验 `audit.head`（不去除空白）与 `manifest.json`。
    let audit_head_raw = match archive.by_name("audit.head") {
        Ok(mut entry) => {
            let mut s = String::new();
            match entry.read_to_string(&mut s) {
                Ok(_) => Some(s),
                Err(err) => {
                    chain_ok = false;
                    let msg = format!("读取 audit.head 失败：{err}");
                    detail.audit_error.get_or_insert_with(|| msg.clone());
                    detail.errors.push(msg);
                    None
                }
            }
        }
        Err(_) => {
            chain_ok = false;
            let msg = "复核包缺少 audit.head".to_string();
            detail.audit_error.get_or_insert_with(|| msg.clone());
            detail.errors.push(msg);
            None
        }
    };

    let manifest_val: Option<Value> = match archive.by_name("manifest.json") {
        Ok(mut entry) => {
            let mut s = String::new();
            match entry.read_to_string(&mut s) {
                Ok(_) => match serde_json::from_str::<Value>(&s) {
                    Ok(v) => Some(v),
                    Err(err) => {
                        detail.errors.push(format!("manifest.json 解析失败：{err}"));
                        None
                    }
                },
                Err(err) => {
                    detail.errors.push(format!("读取 manifest.json 失败：{err}"));
                    None
                }
            }
        }
        Err(_) => {
            detail.errors.push("复核包缺少 manifest.json".to_string());
            None
        }
    };

    let mut manifest_ok = manifest_val.is_some();
    if let Some(ref head_raw) = audit_head_raw
        && chain_ok
        && head_raw != &computed_head
    {
        chain_ok = false;
        let msg = "审计链尾不匹配".to_string();
        detail.audit_error.get_or_insert_with(|| msg.clone());
        detail.errors.push(msg);
    }
    if let Some(ref manifest) = manifest_val {
        let manifest_head = manifest
            .get("audit_head")
            .and_then(Value::as_str)
            .unwrap_or("");
        if chain_ok && manifest_head != computed_head {
            chain_ok = false;
            manifest_ok = false;
            let msg = "审计链尾不匹配".to_string();
            detail.audit_error.get_or_insert_with(|| msg.clone());
            detail.errors.push(msg);
        }
    }
    detail.audit_valid = chain_ok;

    // 6. 跨文件审计链交叉核对。
    let cross_idx = build_audit_cross_index(&parsed_audit_records);

    // 6a. `manifest.exports` 与 ZIP 内 `exports/*` 成员一致性核对
    if let Some(ref manifest) = manifest_val {
        match manifest.get("exports").and_then(Value::as_array) {
            Some(exports) => {
                let mut export_errors = Vec::new();
                let mut manifest_export_members = HashSet::new();
                for item in exports {
                    let Some(member) = item.get("member").and_then(Value::as_str) else {
                        export_errors.push("导出记录缺少 member 字段".to_string());
                        continue;
                    };
                    manifest_export_members.insert(member.to_string());
                    let expected_sha = item.get("sha256").and_then(Value::as_str).unwrap_or("");
                    let expected_size = item.get("size").and_then(Value::as_u64).unwrap_or(u64::MAX);
                    let actual_sha = actual_hashes.get(member).map(String::as_str);
                    let zip_size = actual_sizes.get(member).copied();
                    if actual_sha != Some(expected_sha) || zip_size != Some(expected_size) {
                        export_errors.push(format!("导出记录不匹配：{member}"));
                    }
                }
                for member in actual_hashes.keys() {
                    if member.starts_with("exports/") && !manifest_export_members.contains(member) {
                        export_errors.push(format!("导出成员未在 manifest.json 中登记：{member}"));
                    }
                }
                if export_errors.is_empty() {
                    detail.cross_checks.push(BundleCrossCheck {
                        name: "导出副本清单核对".to_string(),
                        status: "ok".to_string(),
                        message: format!(
                            "已核对 {} 个导出副本成员的 SHA-256 与字节长度，全部一致",
                            exports.len()
                        ),
                    });
                } else {
                    manifest_ok = false;
                    let summary = export_errors.join("；");
                    for e in export_errors {
                        detail.errors.push(e);
                    }
                    detail.cross_checks.push(BundleCrossCheck {
                        name: "导出副本清单核对".to_string(),
                        status: "mismatch".to_string(),
                        message: summary,
                    });
                }
            }
            None => {
                manifest_ok = false;
                let msg = "manifest.json 缺少 exports 列表".to_string();
                detail.errors.push(msg.clone());
                detail.cross_checks.push(BundleCrossCheck {
                    name: "导出副本清单核对".to_string(),
                    status: "mismatch".to_string(),
                    message: msg,
                });
            }
        }
    }

    // 6b. `report.md` 与 `audit.jsonl` 中 Markdown `REPORT_GENERATE` 交叉核对
    match actual_hashes.get("report.md") {
        Some(actual_md_sha) => match cross_idx.last_md_report_sha.as_deref() {
            Some(expected_md_sha) if actual_md_sha == expected_md_sha => {
                detail.cross_checks.push(BundleCrossCheck {
                    name: "Markdown 报告审计摘要核对".to_string(),
                    status: "ok".to_string(),
                    message: "report.md 摘要与审计链最新 REPORT_GENERATE 记录一致".to_string(),
                });
            }
            Some(_) => {
                let msg = "报告摘要不匹配：report.md 与审计链记录不一致".to_string();
                detail.errors.push(msg.clone());
                detail.cross_checks.push(BundleCrossCheck {
                    name: "Markdown 报告审计摘要核对".to_string(),
                    status: "mismatch".to_string(),
                    message: msg,
                });
            }
            None => {
                detail.cross_checks.push(BundleCrossCheck {
                    name: "Markdown 报告审计摘要核对".to_string(),
                    status: "skipped".to_string(),
                    message: "审计链未含 Markdown REPORT_GENERATE 摘要记录（兼容历史复核包）"
                        .to_string(),
                });
            }
        },
        None => {
            let msg = "复核包缺少取证报告 report.md".to_string();
            detail.errors.push(msg.clone());
            detail.cross_checks.push(BundleCrossCheck {
                name: "Markdown 报告审计摘要核对".to_string(),
                status: "mismatch".to_string(),
                message: msg,
            });
        }
    }

    // 6c. 可选 `report.html` 与 `manifest.html_report` 及审计链 HTML `REPORT_GENERATE` 交叉核对
    let manifest_html_meta = manifest_val
        .as_ref()
        .and_then(|m| m.get("html_report"))
        .and_then(Value::as_object);
    if let Some(actual_html_sha) = actual_hashes.get("report.html") {
        let mut html_errors = Vec::new();
        if let Some(meta) = manifest_html_meta {
            let meta_sha = meta.get("sha256").and_then(Value::as_str);
            let meta_size = meta.get("size").and_then(Value::as_u64);
            if let Some(ms) = meta_sha
                && ms != actual_html_sha
            {
                html_errors.push("HTML 报告清单摘要不匹配：report.html".to_string());
            }
            if let Some(ml) = meta_size
                && actual_sizes.get("report.html").copied() != Some(ml)
            {
                html_errors.push("HTML 报告字节长度不匹配：report.html".to_string());
            }
        }
        if let Some(expected_html_sha) = cross_idx.last_html_report_sha.as_deref()
            && actual_html_sha != expected_html_sha
        {
            html_errors.push("HTML 报告摘要不匹配：report.html 与审计链记录不一致".to_string());
        }
        if html_errors.is_empty() {
            let msg = if cross_idx.last_html_report_sha.is_some() {
                "report.html 摘要与清单及审计链 HTML REPORT_GENERATE 记录一致".to_string()
            } else {
                "report.html 已通过成员摘要核验（审计链无对应 HTML REPORT_GENERATE 记录）"
                    .to_string()
            };
            detail.cross_checks.push(BundleCrossCheck {
                name: "HTML 报告审计摘要核对".to_string(),
                status: "ok".to_string(),
                message: msg,
            });
        } else {
            manifest_ok = false;
            let summary = html_errors.join("；");
            for e in html_errors {
                detail.errors.push(e);
            }
            detail.cross_checks.push(BundleCrossCheck {
                name: "HTML 报告审计摘要核对".to_string(),
                status: "mismatch".to_string(),
                message: summary,
            });
        }
    } else if manifest_html_meta.is_some() {
        manifest_ok = false;
        let msg = "HTML 报告成员缺失：manifest.json 声明了 report.html 但包内不存在".to_string();
        detail.errors.push(msg.clone());
        detail.cross_checks.push(BundleCrossCheck {
            name: "HTML 报告审计摘要核对".to_string(),
            status: "mismatch".to_string(),
            message: msg,
        });
    } else {
        detail.cross_checks.push(BundleCrossCheck {
            name: "HTML 报告审计摘要核对".to_string(),
            status: "skipped".to_string(),
            message: "复核包未包含离线 HTML 报告（兼容不含 report.html 的复核包）".to_string(),
        });
    }

    // 6d. `searches/*.json` 与 `audit.jsonl` 中 `CONTENT_SEARCH.details.sha256` 及 `omitted_searches` 交叉核对
    let mut omitted_search_names: HashSet<String> = HashSet::new();
    if let Some(omitted) = manifest_val
        .as_ref()
        .and_then(|m| m.get("omitted_searches"))
        .and_then(Value::as_array)
    {
        for item in omitted {
            if let Some(name) = item.get("name").and_then(Value::as_str) {
                omitted_search_names.insert(name.to_string());
            }
        }
    }
    let search_members: Vec<(&String, &String)> = actual_hashes
        .iter()
        .filter(|(k, _)| k.starts_with("searches/"))
        .collect();
    if search_members.is_empty() && cross_idx.search_digests.is_empty() {
        detail.cross_checks.push(BundleCrossCheck {
            name: "搜索记录交叉核对".to_string(),
            status: "skipped".to_string(),
            message: "复核包与审计链均不含带摘要的内容搜索记录".to_string(),
        });
    } else {
        let mut search_errors = Vec::new();
        for (member, actual_sha) in &search_members {
            if let Some(name) = member.strip_prefix("searches/") {
                if let Some(expected_sha) = cross_idx.search_digests.get(name) {
                    if *actual_sha != expected_sha {
                        search_errors.push(format!("搜索记录不匹配：{member}"));
                    }
                } else if !cross_idx.search_subjects.contains(name) {
                    search_errors.push(format!("搜索记录未在审计链中登记：{member}"));
                }
            }
        }
        for (name, expected_sha) in &cross_idx.search_digests {
            let member = format!("searches/{name}");
            if let Some(actual_sha) = actual_hashes.get(&member) {
                if actual_sha != expected_sha {
                    let msg = format!("搜索记录不匹配：{member}");
                    if !search_errors.contains(&msg) {
                        search_errors.push(msg);
                    }
                }
            } else if !omitted_search_names.contains(name) {
                search_errors.push(format!(
                    "搜索记录缺失且未在 omitted_searches 登记：{member}"
                ));
            }
        }
        if search_errors.is_empty() {
            detail.cross_checks.push(BundleCrossCheck {
                name: "搜索记录交叉核对".to_string(),
                status: "ok".to_string(),
                message: format!(
                    "已核对 {} 份搜索结果文件与 {} 条省略登记，均与审计链一致",
                    search_members.len(),
                    omitted_search_names.len()
                ),
            });
        } else {
            let summary = search_errors.join("；");
            for e in search_errors {
                detail.errors.push(e);
            }
            detail.cross_checks.push(BundleCrossCheck {
                name: "搜索记录交叉核对".to_string(),
                status: "mismatch".to_string(),
                message: summary,
            });
        }
    }

    // 6e. `manifest.findings` 与 `audit.jsonl` 取证发现记录一致性核对
    if let Some(ref manifest) = manifest_val {
        match manifest.get("findings") {
            None => {
                detail.cross_checks.push(BundleCrossCheck {
                    name: "取证发现一致性核对".to_string(),
                    status: "skipped".to_string(),
                    message: "manifest.json 未包含 findings 字段（兼容旧版复核包）".to_string(),
                });
            }
            Some(Value::Array(manifest_findings)) => {
                let mut finding_err: Option<String> = None;
                if manifest_findings.len() != cross_idx.findings.len() {
                    finding_err = Some(format!(
                        "取证发现不一致：manifest.json 含 {} 条 findings，audit.jsonl 含 {} 条",
                        manifest_findings.len(),
                        cross_idx.findings.len()
                    ));
                } else {
                    for (mf, af) in manifest_findings.iter().zip(cross_idx.findings.iter()) {
                        let seq_match = mf.get("seq") == af.get("seq");
                        let action_match = mf.get("action") == af.get("action");
                        let subject_match = mf.get("subject") == af.get("subject");
                        let result_match = mf.get("result") == af.get("result");
                        let hash_match = match mf.get("hash") {
                            Some(mh) => Some(mh) == af.get("hash"),
                            None => true,
                        };
                        if !(seq_match && action_match && subject_match && result_match && hash_match)
                        {
                            let seq_str = mf
                                .get("seq")
                                .and_then(Value::as_u64)
                                .map(|n| n.to_string())
                                .unwrap_or_else(|| "?".to_string());
                            finding_err = Some(format!(
                                "取证发现不一致：manifest.json 中的 findings（seq={seq_str}）与 audit.jsonl 不匹配"
                            ));
                            break;
                        }
                    }
                }
                if let Some(err) = finding_err {
                    manifest_ok = false;
                    detail.errors.push(err.clone());
                    detail.cross_checks.push(BundleCrossCheck {
                        name: "取证发现一致性核对".to_string(),
                        status: "mismatch".to_string(),
                        message: err,
                    });
                } else {
                    detail.cross_checks.push(BundleCrossCheck {
                        name: "取证发现一致性核对".to_string(),
                        status: "ok".to_string(),
                        message: format!(
                            "manifest.json 与 audit.jsonl 的 {} 条取证发现记录完全一致",
                            manifest_findings.len()
                        ),
                    });
                }
            }
            Some(_) => {
                manifest_ok = false;
                let msg = "manifest.json 中的 findings 字段格式无效".to_string();
                detail.errors.push(msg.clone());
                detail.cross_checks.push(BundleCrossCheck {
                    name: "取证发现一致性核对".to_string(),
                    status: "mismatch".to_string(),
                    message: msg,
                });
            }
        }
    }

    detail.manifest_valid = manifest_ok;
    detail.ok = detail.errors.is_empty()
        && detail.audit_valid
        && detail.manifest_valid
        && detail.sha256_matched != Some(false);

    Ok(detail)
}

/// 原生 Rust 独立复核包校验器（对应 `core-contract.md` §2.5），
/// 与 `verify_bundle.py::verify_bundle` 语义完全一致并内置跨文件审计链交叉核对。
///
/// 返回 `SHA256SUMS.json` 中通过校验的材料成员总数。
pub fn verify_bundle(zip_path: &Path, expected_sha256: Option<&str>) -> CoreResult<usize> {
    // 跨成员复用同一块 1 MiB 缓冲区，避免多成员复核包反复分配清零内存。
    let mut io_buf = vec![0u8; 1024 * 1024];

    if let Some(exp) = expected_sha256
        && !exp.trim().is_empty()
    {
        let (actual, _) = sha256_and_len_with_buf(File::open(zip_path)?, &mut io_buf)?;
        if actual != exp.trim().to_ascii_lowercase() {
            return Err(CoreError::IntegrityFailed(
                "复核包外部 SHA-256 不匹配".to_string(),
            ));
        }
    }

    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(BufReader::with_capacity(256 * 1024, file))?;

    // 1. 收集所有成员名称并拒绝重复成员。
    let mut name_set: HashSet<String> = HashSet::with_capacity(archive.len());
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        if !name_set.insert(name) {
            return Err(CoreError::IntegrityFailed(
                "成员重复或与清单不一致".to_string(),
            ));
        }
    }

    // 2. 解析 SHA256SUMS.json 并强制要求成员集合完全一致。
    let checks: BTreeMap<String, String> = {
        let mut entry = archive.by_name("SHA256SUMS.json").map_err(|_| {
            CoreError::IntegrityFailed("复核包缺少 SHA256SUMS.json".to_string())
        })?;
        let mut raw = String::new();
        entry.read_to_string(&mut raw)?;
        serde_json::from_str(&raw)?
    };

    let mut expected_names: HashSet<String> = checks.keys().cloned().collect();
    expected_names.insert("SHA256SUMS.json".to_string());
    if name_set != expected_names {
        return Err(CoreError::IntegrityFailed(
            "成员重复或与清单不一致".to_string(),
        ));
    }

    // 3. 重新计算清单中每个成员的 SHA-256，同时记录实际解压字节数供后续核对。
    let mut actual_sizes: HashMap<&str, u64> = HashMap::with_capacity(checks.len());
    for (member_name, expected_digest) in &checks {
        let entry = archive.by_name(member_name)?;
        let header_size = entry.size();
        let (actual, actual_len) = sha256_and_len_with_buf(entry, &mut io_buf)?;
        if &actual != expected_digest || actual_len != header_size {
            return Err(CoreError::IntegrityFailed(format!(
                "成员摘要不匹配：{member_name}"
            )));
        }
        actual_sizes.insert(member_name.as_str(), actual_len);
    }

    // 4. 校验 `audit.jsonl` 内完整的 SHA-256 审计哈希链。
    let mut audit_records: Vec<Value> = Vec::new();
    let previous = {
        let entry = archive.by_name("audit.jsonl")?;
        let reader = BufReader::new(entry);
        let mut prev = GENESIS_HASH.to_string();
        for (idx, line_res) in reader.lines().enumerate() {
            let seq_expected = (idx + 1) as u64;
            let line = line_res?;
            let mut obj: Map<String, Value> = serde_json::from_str(&line).map_err(|_| {
                CoreError::AuditTampered(format!("审计链不一致：{seq_expected}"))
            })?;
            let Some(Value::String(recorded)) = obj.remove("hash") else {
                return Err(CoreError::AuditTampered(format!(
                    "审计链不一致：{seq_expected}"
                )));
            };
            let seq_ok = obj.get("seq").and_then(Value::as_u64) == Some(seq_expected);
            let prev_ok = obj.get("previous").and_then(Value::as_str) == Some(prev.as_str());
            let canonical = canonical_json_value(&Value::Object(obj.clone()))?;
            let computed = sha256_hex(canonical.as_bytes());
            if !seq_ok || !prev_ok || computed != recorded {
                return Err(CoreError::AuditTampered(format!(
                    "审计链不一致：{seq_expected}"
                )));
            }
            obj.insert("hash".to_string(), Value::String(recorded.clone()));
            audit_records.push(Value::Object(obj));
            prev = recorded;
        }
        prev
    };

    // 5. 严格校验 `audit.head`（不去除空白，与 `verify_bundle.py` 一致）与 `manifest.json`。
    let audit_head_raw = {
        let mut entry = archive.by_name("audit.head")?;
        let mut s = String::new();
        entry.read_to_string(&mut s)?;
        s
    };
    let manifest: Value = {
        let mut entry = archive.by_name("manifest.json")?;
        let mut s = String::new();
        entry.read_to_string(&mut s)?;
        serde_json::from_str(&s)?
    };
    let manifest_head = manifest
        .get("audit_head")
        .and_then(Value::as_str)
        .unwrap_or("");
    if audit_head_raw != previous || manifest_head != previous {
        return Err(CoreError::AuditTampered("审计链尾不匹配".to_string()));
    }

    // 6. 校验 `manifest.json` 中列出的每条导出记录均与对应成员的 SHA-256 及实际解压大小一致。
    let exports = manifest
        .get("exports")
        .and_then(Value::as_array)
        .ok_or_else(|| CoreError::IntegrityFailed("manifest.json 缺少 exports 列表".to_string()))?;
    let mut manifest_export_members: HashSet<&str> = HashSet::with_capacity(exports.len());
    for item in exports {
        let member = item
            .get("member")
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::IntegrityFailed("导出记录缺少 member 字段".to_string()))?;
        manifest_export_members.insert(member);
        let expected_sha = item.get("sha256").and_then(Value::as_str).unwrap_or("");
        let expected_size = item
            .get("size")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        let zip_size = actual_sizes.get(member).copied();
        if checks.get(member).map(String::as_str) != Some(expected_sha)
            || zip_size != Some(expected_size)
        {
            return Err(CoreError::IntegrityFailed(format!(
                "导出记录不匹配：{member}"
            )));
        }
    }
    for member in checks.keys() {
        if member.starts_with("exports/") && !manifest_export_members.contains(member.as_str()) {
            return Err(CoreError::IntegrityFailed(format!(
                "导出成员未在 manifest.json 中登记：{member}"
            )));
        }
    }

    // 7. 跨文件审计链交叉核对（对历史未含对应明细的旧版复核包保持温和兼容）。
    let cross_idx = build_audit_cross_index(&audit_records);

    if !checks.contains_key("report.md") {
        return Err(CoreError::IntegrityFailed(
            "复核包缺少取证报告 report.md".to_string(),
        ));
    }
    if let Some(ref expected_md_sha) = cross_idx.last_md_report_sha
        && checks.get("report.md") != Some(expected_md_sha)
    {
        return Err(CoreError::IntegrityFailed(
            "报告摘要不匹配：report.md 与审计链记录不一致".to_string(),
        ));
    }

    if let Some(html_meta) = manifest.get("html_report").and_then(Value::as_object) {
        let html_member = html_meta
            .get("member")
            .and_then(Value::as_str)
            .unwrap_or("report.html");
        let Some(actual_html_sha) = checks.get(html_member) else {
            return Err(CoreError::IntegrityFailed(format!(
                "HTML 报告成员缺失：{html_member}"
            )));
        };
        if let Some(exp_sha) = html_meta.get("sha256").and_then(Value::as_str)
            && actual_html_sha != exp_sha
        {
            return Err(CoreError::IntegrityFailed(format!(
                "HTML 报告清单摘要不匹配：{html_member}"
            )));
        }
        if let Some(exp_size) = html_meta.get("size").and_then(Value::as_u64)
            && actual_sizes.get(html_member).copied() != Some(exp_size)
        {
            return Err(CoreError::IntegrityFailed(format!(
                "HTML 报告长度不匹配：{html_member}"
            )));
        }
    }
    if let Some(actual_html_sha) = checks.get("report.html")
        && let Some(ref expected_html_sha) = cross_idx.last_html_report_sha
        && actual_html_sha != expected_html_sha
    {
        return Err(CoreError::IntegrityFailed(
            "HTML 报告摘要不匹配：report.html 与审计链记录不一致".to_string(),
        ));
    }

    let mut omitted_search_names: HashSet<String> = HashSet::new();
    if let Some(omitted) = manifest.get("omitted_searches").and_then(Value::as_array) {
        for item in omitted {
            if let Some(name) = item.get("name").and_then(Value::as_str) {
                omitted_search_names.insert(name.to_string());
            }
        }
    }
    for (member, actual_sha) in &checks {
        if let Some(search_name) = member.strip_prefix("searches/") {
            if let Some(expected_sha) = cross_idx.search_digests.get(search_name) {
                if actual_sha != expected_sha {
                    return Err(CoreError::IntegrityFailed(format!(
                        "搜索记录不匹配：{member}"
                    )));
                }
            } else if !cross_idx.search_subjects.contains(search_name) {
                return Err(CoreError::IntegrityFailed(format!(
                    "搜索记录未在审计链中登记：{member}"
                )));
            }
        }
    }
    for (search_name, expected_sha) in &cross_idx.search_digests {
        let member = format!("searches/{search_name}");
        if let Some(actual_sha) = checks.get(&member) {
            if actual_sha != expected_sha {
                return Err(CoreError::IntegrityFailed(format!(
                    "搜索记录不匹配：{member}"
                )));
            }
        } else if !omitted_search_names.contains(search_name) {
            return Err(CoreError::IntegrityFailed(format!(
                "搜索记录缺失且未在 omitted_searches 登记：{member}"
            )));
        }
    }

    if let Some(findings_val) = manifest.get("findings") {
        let manifest_findings = findings_val.as_array().ok_or_else(|| {
            CoreError::IntegrityFailed("manifest.json 中的 findings 字段格式无效".to_string())
        })?;
        if manifest_findings.len() != cross_idx.findings.len() {
            return Err(CoreError::IntegrityFailed(
                "取证发现不一致：manifest.json 中的 findings 与 audit.jsonl 数量不匹配".to_string(),
            ));
        }
        for (mf, af) in manifest_findings.iter().zip(cross_idx.findings.iter()) {
            let seq_match = mf.get("seq") == af.get("seq");
            let action_match = mf.get("action") == af.get("action");
            let subject_match = mf.get("subject") == af.get("subject");
            let result_match = mf.get("result") == af.get("result");
            let hash_match = match mf.get("hash") {
                Some(mh) => Some(mh) == af.get("hash"),
                None => true,
            };
            if !(seq_match && action_match && subject_match && result_match && hash_match) {
                return Err(CoreError::IntegrityFailed(
                    "取证发现不一致：manifest.json 中的 findings 与 audit.jsonl 不匹配".to_string(),
                ));
            }
        }
    }

    Ok(checks.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_tools::record_note;
    use crate::findings::AuditOrigin;
    use crate::paths::AppPaths;

    /// 重打包 ZIP 并对指定成员内容应用替换函数（可选择同步更新 SHA256SUMS.json 以测试跨文件核验）。
    fn repack_zip_with_edit<F>(
        src_zip: &Path,
        dst_zip: &Path,
        target_member: &str,
        update_sums: bool,
        mut edit: F,
    ) where
        F: FnMut(&mut Vec<u8>),
    {
        let mut src = ZipArchive::new(File::open(src_zip).expect("open src zip")).expect("zip");
        let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(src.len());
        for i in 0..src.len() {
            let mut e = src.by_index(i).expect("entry");
            let name = e.name().to_string();
            let mut buf = Vec::new();
            e.read_to_end(&mut buf).expect("read entry");
            if name == target_member {
                edit(&mut buf);
            }
            entries.push((name, buf));
        }
        if update_sums {
            let mut sums: BTreeMap<String, String> = BTreeMap::new();
            for (name, bytes) in &entries {
                if name != "SHA256SUMS.json" {
                    sums.insert(name.clone(), sha256_hex(bytes));
                }
            }
            let sums_bytes = serde_json::to_string_pretty(&sums).unwrap().into_bytes();
            for (name, bytes) in &mut entries {
                if name == "SHA256SUMS.json" {
                    *bytes = sums_bytes.clone();
                }
            }
        }
        let mut dst = ZipWriter::new(File::create(dst_zip).expect("create dst zip"));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, bytes) in entries {
            dst.start_file(name, opts).expect("start file");
            dst.write_all(&bytes).expect("write bytes");
        }
        dst.finish().expect("finish zip");
    }

    #[test]
    fn bundle_packs_html_report_reads_sidecar_and_pinpoints_tampering() {
        let paths = AppPaths::discover();
        let demo_dd = paths.evidence_dir.join("demo.dd");
        assert!(demo_dd.is_file(), "缺少 demo.dd 测试镜像");

        let tmp = tempfile::tempdir().expect("tempdir");
        let mut case = Case::create(
            tmp.path(),
            "P2-REVIEW-001",
            "复核测试员",
            "HTML报告与复核包交叉核验",
            None,
            None,
            AuditOrigin::Manual,
        )
        .expect("create case");
        case.load_image(&demo_dd, None, None, None).expect("load demo");
        let inventory = case
            .scan_partitions(None, None, None)
            .expect("scan partitions");
        let target_entry = inventory
            .iter()
            .find(|e| e.path == "DOCS/CASE.TXT" && !e.deleted)
            .cloned()
            .expect("find CASE.TXT");
        record_note(&mut case, &target_entry, "关键取证发现笔记").expect("record note");

        // 1. 生成离线 HTML 报告并验证审计日志含 format="html" 与 sha256
        let html_res = case
            .generate_html_report(None)
            .expect("generate html report");
        assert!(html_res.path.is_file());
        assert!(html_res.bytes > 1000);
        let records_after_html = case.check_audit().expect("audit after html");
        assert!(records_after_html.iter().any(|r| {
            r.action == "REPORT_GENERATE"
                && r.result == "成功"
                && r.details.get("format").and_then(Value::as_str) == Some("html")
                && r.details.get("sha256").and_then(Value::as_str) == Some(html_res.sha256.as_str())
        }));

        // 2. 构建复核包：应自动打包 report.html
        let bundle = build_bundle(&mut case, &BuildBundleOptions::default(), None)
            .expect("build bundle with html");
        case.close();

        // 3. 伴随 .zip.sha256 自动读取与完整可视化核验均应通过
        assert_eq!(
            read_sidecar_sha256(&bundle.bundle_path).as_deref(),
            Some(bundle.sha256.as_str())
        );
        let detail = verify_bundle_detailed(&bundle.bundle_path, None).expect("detailed verify");
        assert!(detail.ok, "detail errors: {:?}", detail.errors);
        assert_eq!(detail.sha256_source, "sidecar");
        assert_eq!(detail.sha256_matched, Some(true));
        assert!(detail.audit_valid);
        assert!(detail.manifest_valid);
        assert!(
            detail
                .members
                .iter()
                .any(|m| m.path == "report.html" && m.status == "ok" && m.category == "report")
        );
        assert!(
            detail
                .cross_checks
                .iter()
                .any(|c| c.name == "HTML 报告审计摘要核对" && c.status == "ok")
        );
        assert!(
            detail
                .cross_checks
                .iter()
                .any(|c| c.name == "取证发现一致性核对" && c.status == "ok")
        );
        verify_bundle(&bundle.bundle_path, Some(&bundle.sha256)).expect("verify_bundle passes");

        // 4. 修改 report.html 单字节（不更新 SHA256SUMS.json）：应精确定位成员摘要不匹配
        let tamper_html_1byte = tmp.path().join("tamper_html_1byte.zip");
        repack_zip_with_edit(
            &bundle.bundle_path,
            &tamper_html_1byte,
            "report.html",
            false,
            |bytes| {
                if let Some(first) = bytes.first_mut() {
                    *first ^= 0x01;
                }
            },
        );
        let d_tamper = verify_bundle_detailed(&tamper_html_1byte, None).expect("detailed tamper");
        assert!(!d_tamper.ok);
        assert_eq!(d_tamper.sha256_source, "none");
        assert!(
            d_tamper
                .members
                .iter()
                .any(|m| m.path == "report.html" && m.status == "mismatch")
        );

        // 5. 修改 report.html 并同步重算 SHA256SUMS.json：成员哈希虽过，但必须被跨文件审计链核对拦下
        let tamper_html_cross = tmp.path().join("tamper_html_cross.zip");
        repack_zip_with_edit(
            &bundle.bundle_path,
            &tamper_html_cross,
            "report.html",
            true,
            |bytes| bytes.extend_from_slice(b"<!-- tampered -->"),
        );
        let d_cross = verify_bundle_detailed(&tamper_html_cross, None).expect("detailed cross");
        assert!(!d_cross.ok);
        assert!(
            d_cross
                .cross_checks
                .iter()
                .any(|c| c.name == "HTML 报告审计摘要核对" && c.status == "mismatch")
        );
        assert!(verify_bundle(&tamper_html_cross, None).is_err());

        // 6. 篡改 audit.jsonl 中第 2 条记录并同步重算 SHA256SUMS.json：应精确定位断链序号
        let tamper_audit = tmp.path().join("tamper_audit.zip");
        repack_zip_with_edit(
            &bundle.bundle_path,
            &tamper_audit,
            "audit.jsonl",
            true,
            |bytes| {
                let text = String::from_utf8(bytes.clone()).unwrap();
                let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
                let mut rec: Value = serde_json::from_str(&lines[1]).unwrap();
                rec["result"] = Value::String("已篡改结果".to_string());
                lines[1] = serde_json::to_string(&rec).unwrap();
                *bytes = format!("{}\n", lines.join("\n")).into_bytes();
            },
        );
        let d_audit = verify_bundle_detailed(&tamper_audit, None).expect("detailed audit tamper");
        assert!(!d_audit.ok);
        assert!(!d_audit.audit_valid);
        assert!(
            d_audit
                .audit_error
                .as_deref()
                .is_some_and(|e| e.contains("审计链不一致：2"))
        );

        // 6b. 手动传入错误外部 SHA-256：应标注 sha256_source="manual" 且 sha256_matched=Some(false)
        let d_bad_manual = verify_bundle_detailed(&bundle.bundle_path, Some(&"0".repeat(64)))
            .expect("detailed manual sha mismatch");
        assert!(!d_bad_manual.ok);
        assert_eq!(d_bad_manual.sha256_source, "manual");
        assert_eq!(d_bad_manual.sha256_matched, Some(false));
        assert!(d_bad_manual.audit_valid);

        // 7. 篡改 manifest.json 的 findings 并同步重算 SHA256SUMS.json：应被取证发现一致性核对拦下
        let tamper_findings = tmp.path().join("tamper_findings.zip");
        repack_zip_with_edit(
            &bundle.bundle_path,
            &tamper_findings,
            "manifest.json",
            true,
            |bytes| {
                let mut v: Value = serde_json::from_slice(bytes).unwrap();
                v["findings"] = Value::Array(Vec::new());
                *bytes = serde_json::to_string_pretty(&v).unwrap().into_bytes();
            },
        );
        let d_findings =
            verify_bundle_detailed(&tamper_findings, None).expect("detailed findings tamper");
        assert!(!d_findings.ok);
        assert!(!d_findings.manifest_valid);
        assert!(
            d_findings
                .cross_checks
                .iter()
                .any(|c| c.name == "取证发现一致性核对" && c.status == "mismatch")
        );
        assert!(verify_bundle(&tamper_findings, None).is_err());

        // 8. 若本机有 Python，验证更新后的内嵌 verify_bundle.py 对含 report.html 的复核包通过，对篡改包拦截
        let py_script = tmp.path().join("verify_bundle.py");
        fs::write(&py_script, EMBEDDED_VERIFY_BUNDLE_PY).expect("write verify_bundle.py");
        let venv_py = paths.root.join(".venv").join("Scripts").join("python.exe");
        if venv_py.is_file() {
            let ok_out = std::process::Command::new(&venv_py)
                .arg(&py_script)
                .arg(&bundle.bundle_path)
                .output()
                .expect("run verify_bundle.py ok");
            assert!(
                ok_out.status.success(),
                "verify_bundle.py failed: {}",
                String::from_utf8_lossy(&ok_out.stderr)
            );
            let bad_out = std::process::Command::new(&venv_py)
                .arg(&py_script)
                .arg(&tamper_findings)
                .output()
                .expect("run verify_bundle.py tamper");
            assert!(!bad_out.status.success(), "verify_bundle.py 应拦截 findings 篡改");
        }
    }

    #[test]
    fn build_bundle_auto_generates_fresh_html_report_without_prior_call_and_syncs_updates() {
        let paths = AppPaths::discover();
        let demo_dd = paths.evidence_dir.join("demo.dd");
        assert!(demo_dd.is_file(), "缺少 demo.dd 测试镜像");

        let tmp = tempfile::tempdir().expect("tempdir");
        let mut case = Case::create(
            tmp.path(),
            "AUTO-HTML-001",
            "复核测试员",
            "未预先生成HTML直接导出复核包回归测试",
            None,
            None,
            AuditOrigin::Manual,
        )
        .expect("create case");
        case.load_image(&demo_dd, None, None, None).expect("load demo");
        let inventory = case
            .scan_partitions(None, None, None)
            .expect("scan partitions");
        let target_entry = inventory
            .iter()
            .find(|e| e.path == "DOCS/CASE.TXT" && !e.deleted)
            .cloned()
            .expect("find CASE.TXT");
        record_note(&mut case, &target_entry, "未预先手动生成HTML的初始笔记")
            .expect("record initial note");

        // 确认调用 build_bundle 前 reports/ 下尚未存在任何 HTML 报告文件。
        let reports_dir = case.folder().join("reports");
        let html_before = fs::read_dir(&reports_dir)
            .expect("read reports dir")
            .filter_map(Result::ok)
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("html"))
            })
            .count();
        assert_eq!(html_before, 0, "构建复核包前不应存在手工生成的 HTML 报告");

        let hash_verify_before = case
            .check_audit()
            .expect("audit before bundle")
            .iter()
            .filter(|r| r.action == "HASH_VERIFY")
            .count();

        // 1. 直接调用 build_bundle（不预先调用 generate_html_report）
        let bundle1 = build_bundle(&mut case, &BuildBundleOptions::default(), None)
            .expect("build bundle without prior html generation");

        // 确认单次 build_bundle 仅执行一次镜像完整哈希校验（未产生冗余二次哈希）。
        let audit_after_1 = case.check_audit().expect("audit after bundle 1");
        let hash_verify_after = audit_after_1
            .iter()
            .filter(|r| r.action == "HASH_VERIFY")
            .count();
        assert_eq!(
            hash_verify_after,
            hash_verify_before + 1,
            "build_bundle 不应对小镜像重复执行完整哈希校验"
        );

        // 校验 ZIP 内部结构：必含 report.html、SHA256SUMS.json["report.html"]、manifest.json.html_report 与对应内容。
        let read_bundle_html_info = |zip_path: &Path| -> (String, String, Value, BTreeMap<String, String>) {
            let mut archive = ZipArchive::new(File::open(zip_path).expect("open zip")).expect("zip");
            let mut html_text = String::new();
            archive
                .by_name("report.html")
                .expect("ZIP 必须包含 report.html")
                .read_to_string(&mut html_text)
                .expect("read report.html");
            let actual_sha = sha256_hex(html_text.as_bytes());
            let mut sums_raw = String::new();
            archive
                .by_name("SHA256SUMS.json")
                .expect("SHA256SUMS.json")
                .read_to_string(&mut sums_raw)
                .expect("read sums");
            let sums: BTreeMap<String, String> =
                serde_json::from_str(&sums_raw).expect("parse sums");
            let mut manifest_raw = String::new();
            archive
                .by_name("manifest.json")
                .expect("manifest.json")
                .read_to_string(&mut manifest_raw)
                .expect("read manifest");
            let manifest: Value = serde_json::from_str(&manifest_raw).expect("parse manifest");
            (html_text, actual_sha, manifest, sums)
        };

        let (html1_text, html1_sha, manifest1, sums1) = read_bundle_html_info(&bundle1.bundle_path);
        assert!(html1_text.starts_with("<!DOCTYPE html>"));
        assert!(html1_text.contains("AUTO-HTML-001"));
        assert!(html1_text.contains("未预先手动生成HTML的初始笔记"));
        assert_eq!(sums1.get("report.html"), Some(&html1_sha));
        assert_eq!(manifest1["html_report"]["member"].as_str(), Some("report.html"));
        assert_eq!(manifest1["html_report"]["sha256"].as_str(), Some(html1_sha.as_str()));
        assert_eq!(
            manifest1["html_report"]["size"].as_u64(),
            Some(html1_text.len() as u64)
        );

        // 核验 Rust verify_bundle、verify_bundle_detailed 与 Python verify_bundle.py 全部 0 警告通过。
        verify_bundle(&bundle1.bundle_path, Some(&bundle1.sha256))
            .expect("verify_bundle passes on auto-generated html bundle");
        let detail1 =
            verify_bundle_detailed(&bundle1.bundle_path, None).expect("detailed verify 1");
        assert!(detail1.ok, "detail1 errors: {:?}", detail1.errors);
        assert!(detail1.errors.is_empty());
        assert!(
            detail1
                .members
                .iter()
                .any(|m| m.path == "report.html" && m.status == "ok" && m.category == "report")
        );
        assert!(
            detail1
                .cross_checks
                .iter()
                .any(|c| c.name == "Markdown 报告审计摘要核对" && c.status == "ok")
        );
        assert!(
            detail1
                .cross_checks
                .iter()
                .any(|c| c.name == "HTML 报告审计摘要核对" && c.status == "ok")
        );

        let py_script = tmp.path().join("verify_bundle.py");
        fs::write(&py_script, EMBEDDED_VERIFY_BUNDLE_PY).expect("write verify_bundle.py");
        let venv_py = paths.root.join(".venv").join("Scripts").join("python.exe");
        if venv_py.is_file() {
            let py_out = std::process::Command::new(&venv_py)
                .arg(&py_script)
                .arg(&bundle1.bundle_path)
                .output()
                .expect("run verify_bundle.py on bundle1");
            assert!(
                py_out.status.success(),
                "verify_bundle.py failed on bundle1: {}",
                String::from_utf8_lossy(&py_out.stderr)
            );
        }

        // 2. 新增取证发现后再次直接导出复核包：内置 report.html 必须同步刷新而非沿用旧版 HTML。
        record_note(&mut case, &target_entry, "首次导出后新增的取证发现")
            .expect("record second note");
        let bundle2 = build_bundle(&mut case, &BuildBundleOptions::default(), None)
            .expect("build second bundle");
        case.close();

        let (html2_text, html2_sha, manifest2, sums2) = read_bundle_html_info(&bundle2.bundle_path);
        assert_ne!(html2_sha, html1_sha, "二次导出应生成全新的 HTML 报告而非复用旧文件");
        assert!(html2_text.contains("首次导出后新增的取证发现"));
        assert_eq!(sums2.get("report.html"), Some(&html2_sha));
        assert_eq!(manifest2["html_report"]["sha256"].as_str(), Some(html2_sha.as_str()));

        verify_bundle(&bundle2.bundle_path, Some(&bundle2.sha256))
            .expect("verify_bundle passes on synced bundle2");
        let detail2 =
            verify_bundle_detailed(&bundle2.bundle_path, None).expect("detailed verify 2");
        assert!(detail2.ok, "detail2 errors: {:?}", detail2.errors);
        assert!(
            detail2
                .cross_checks
                .iter()
                .any(|c| c.name == "HTML 报告审计摘要核对" && c.status == "ok")
        );
        if venv_py.is_file() {
            let py_out2 = std::process::Command::new(&venv_py)
                .arg(&py_script)
                .arg(&bundle2.bundle_path)
                .output()
                .expect("run verify_bundle.py on bundle2");
            assert!(
                py_out2.status.success(),
                "verify_bundle.py failed on bundle2: {}",
                String::from_utf8_lossy(&py_out2.stderr)
            );
        }
    }

    #[test]
    fn build_bundle_blocks_reports_when_integrity_fails_and_verifies_legacy_bundle_without_html() {
        let paths = AppPaths::discover();
        let demo_dd = paths.evidence_dir.join("demo.dd");
        assert!(demo_dd.is_file(), "缺少 demo.dd 测试镜像");

        let tmp = tempfile::tempdir().expect("tempdir");
        let cases_root = tmp.path().join("cases");
        fs::create_dir_all(&cases_root).expect("create cases root");

        // 1. 镜像被篡改时调用 build_bundle：必须拦截且不得残留任何 report.md / report.html / zip。
        let copied_img = tmp.path().join("tamper_demo.dd");
        fs::copy(&demo_dd, &copied_img).expect("copy demo.dd");
        let mut tampered_case = Case::create(
            &cases_root,
            "TAMPER-GATE-001",
            "复核测试员",
            "完整性前置拦截测试",
            None,
            None,
            AuditOrigin::Manual,
        )
        .expect("create tampered case");
        tampered_case
            .load_image(&copied_img, None, None, None)
            .expect("load copied image");

        // 修改镜像末尾单字节使完整性校验失败。
        {
            let mut raw = fs::read(&copied_img).expect("read copied image");
            if let Some(last) = raw.last_mut() {
                *last ^= 0xFF;
            }
            fs::write(&copied_img, &raw).expect("write tampered image");
        }

        let err = build_bundle(&mut tampered_case, &BuildBundleOptions::default(), None)
            .expect_err("镜像校验未通过时禁止生成复核包");
        assert!(
            matches!(err, CoreError::IntegrityFailed(_)),
            "预期 IntegrityFailed，实际为：{err:?}"
        );
        let generated_reports: Vec<_> = fs::read_dir(tampered_case.folder().join("reports"))
            .expect("read reports dir")
            .filter_map(Result::ok)
            .collect();
        assert!(
            generated_reports.is_empty(),
            "完整性校验失败时绝不应生成任何 Markdown/HTML/ZIP 文件：{generated_reports:?}"
        );
        tampered_case.close();

        // 2. 构造不含 report.html 与 manifest.html_report 的历史风格复核包，验证三套校验器均 100% 向后兼容。
        let mut ok_case = Case::create(
            &cases_root,
            "LEGACY-COMPAT-001",
            "复核测试员",
            "历史复核包向后兼容测试",
            None,
            None,
            AuditOrigin::Manual,
        )
        .expect("create ok case");
        ok_case.load_image(&demo_dd, None, None, None).expect("load demo");
        let bundle = build_bundle(&mut ok_case, &BuildBundleOptions::default(), None)
            .expect("build base bundle");
        ok_case.close();

        let legacy_zip = tmp.path().join("legacy_without_html.zip");
        {
            let mut src =
                ZipArchive::new(File::open(&bundle.bundle_path).expect("open base zip"))
                    .expect("zip");
            let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
            for i in 0..src.len() {
                let mut e = src.by_index(i).expect("entry");
                let name = e.name().to_string();
                if name == "report.html" || name == "SHA256SUMS.json" {
                    continue;
                }
                let mut buf = Vec::new();
                e.read_to_end(&mut buf).expect("read entry");
                if name == "manifest.json" {
                    let mut v: Value = serde_json::from_slice(&buf).expect("parse manifest");
                    if let Some(obj) = v.as_object_mut() {
                        obj.remove("html_report");
                    }
                    buf = serde_json::to_vec_pretty(&v).expect("serialize manifest");
                }
                entries.push((name, buf));
            }
            let mut sums: BTreeMap<String, String> = BTreeMap::new();
            for (name, bytes) in &entries {
                sums.insert(name.clone(), sha256_hex(bytes));
            }
            entries.push((
                "SHA256SUMS.json".to_string(),
                serde_json::to_vec_pretty(&sums).expect("serialize sums"),
            ));
            let mut dst = ZipWriter::new(File::create(&legacy_zip).expect("create legacy zip"));
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            for (name, bytes) in entries {
                dst.start_file(name, opts).expect("start file");
                dst.write_all(&bytes).expect("write bytes");
            }
            dst.finish().expect("finish legacy zip");
        }

        verify_bundle(&legacy_zip, None).expect("Rust verify_bundle 必须兼容不含 report.html 的旧包");
        let legacy_detail =
            verify_bundle_detailed(&legacy_zip, None).expect("detailed verify legacy");
        assert!(legacy_detail.ok, "legacy errors: {:?}", legacy_detail.errors);
        assert!(
            legacy_detail
                .cross_checks
                .iter()
                .any(|c| c.name == "HTML 报告审计摘要核对" && c.status == "skipped")
        );

        let py_script = tmp.path().join("verify_bundle.py");
        fs::write(&py_script, EMBEDDED_VERIFY_BUNDLE_PY).expect("write verify_bundle.py");
        let venv_py = paths.root.join(".venv").join("Scripts").join("python.exe");
        if venv_py.is_file() {
            let py_out = std::process::Command::new(&venv_py)
                .arg(&py_script)
                .arg(&legacy_zip)
                .output()
                .expect("run verify_bundle.py on legacy zip");
            assert!(
                py_out.status.success(),
                "verify_bundle.py 必须兼容不含 report.html 的旧包：{}",
                String::from_utf8_lossy(&py_out.stderr)
            );
        }
    }
}
