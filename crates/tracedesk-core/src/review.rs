//! 可核验复核包构建器（`reports/report_<12hex>.zip` + `.zip.sha256`）
//! 与原生 Rust 复核包校验器（`verify_bundle`），与 `scripts/verify_bundle.py`
//! 保持 100% 兼容（对应 `core-contract.md` §2.5）。

use std::collections::{BTreeMap, HashMap, HashSet};
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

/// 解析导出记录在 `<case_dir>/exports/` 下的本地文件路径，即使案件目录曾被整体移动仍可定位。
pub fn resolve_export_path(case: &Case, item: &ExportRecord) -> CoreResult<(PathBuf, PathBuf)> {
    let original = Path::new(&item.path);
    let file_name = original
        .file_name()
        .ok_or_else(|| CoreError::InvalidInput("导出记录文件名无效".to_string()))?;
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

    let report_path = case.report(tsk)?;
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
            records
                .iter()
                .rev()
                .find(|r| r.action == "REPORT_GENERATE" && r.result == "成功")
        })
        .ok_or_else(|| CoreError::Other("无法获取最新报告的审计摘要".to_string()))?;
    let report_sha256 = report_record
        .details
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::Other("无法获取最新报告的审计摘要".to_string()))?
        .to_string();
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

        let copy_verified = |archive: &mut ZipWriter<BufWriter<File>>,
                             checksums: &mut BTreeMap<String, String>,
                             buf: &mut [u8],
                             src_path: &Path,
                             member_name: &str,
                             expected_sha256: &str|
         -> CoreResult<()> {
            let mut source = File::open(src_path)?;
            archive.start_file(member_name, zip_options)?;
            let mut hasher = Sha256::new();
            loop {
                let n = source.read(buf)?;
                if n == 0 {
                    break;
                }
                archive.write_all(&buf[..n])?;
                hasher.update(&buf[..n]);
            }
            let actual = hex_lower(&hasher.finalize());
            if actual != expected_sha256 {
                let fname = src_path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                return Err(CoreError::IntegrityFailed(format!(
                    "材料摘要不一致：{fname}"
                )));
            }
            checksums.insert(member_name.to_string(), expected_sha256.to_string());
            Ok(())
        };

        // 1. report.md
        copy_verified(
            &mut archive,
            &mut checksums,
            &mut copy_buf,
            &report_path,
            "report.md",
            &report_sha256,
        )?;

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
            copy_verified(
                &mut archive,
                &mut checksums,
                &mut copy_buf,
                &row.path,
                &member,
                &row.item.sha256,
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
            copy_verified(
                &mut archive,
                &mut checksums,
                &mut copy_buf,
                &row.path,
                &member,
                &row.sha256,
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

        // 7. manifest.json
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

        let manifest = serde_json::json!({
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

/// 原生 Rust 独立复核包校验器（对应 `core-contract.md` §2.5），
/// 与 `scripts/verify_bundle.py::verify_bundle` 语义完全一致。
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
    let mut names: Vec<String> = Vec::with_capacity(archive.len());
    let mut name_set: HashSet<String> = HashSet::with_capacity(archive.len());
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        if !name_set.insert(name.clone()) {
            return Err(CoreError::IntegrityFailed(
                "成员重复或与清单不一致".to_string(),
            ));
        }
        names.push(name);
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

    // 3. 重新计算清单中每个成员的 SHA-256，同时记录实际解压字节数供第 6 步核对。
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
            let canonical = canonical_json_value(&Value::Object(obj))?;
            let computed = sha256_hex(canonical.as_bytes());
            if !seq_ok || !prev_ok || computed != recorded {
                return Err(CoreError::AuditTampered(format!(
                    "审计链不一致：{seq_expected}"
                )));
            }
            prev = recorded;
        }
        prev
    };

    // 5. 严格校验 `audit.head`（不去除空白，与 `scripts/verify_bundle.py:41` 一致）与 `manifest.json`。
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
    for item in exports {
        let member = item
            .get("member")
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::IntegrityFailed("导出记录缺少 member 字段".to_string()))?;
        let expected_sha = item
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or("");
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

    Ok(checks.len())
}
