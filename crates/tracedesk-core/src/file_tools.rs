//! 绑定到镜像 SHA-256、分区偏移、路径与 inode 的单文件取证操作：
//! 单文件哈希（`FILE_HASH`）、外部副本比对（`FILE_COMPARE`）以及
//! 取证笔记（`FILE_NOTE`）（对应 `forensic/core/file_tools.py`）。

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tracedesk_engines::{InventoryEntry, TskCli, can_export, deleted_source_note, sha256_file};

use crate::case::Case;
use crate::error::{CoreError, CoreResult};
use crate::findings::AuditRecord;
use crate::formatting::hex_lower;

/// 构建审计标识映射，将操作绑定到特定镜像与文件条目。
pub fn entry_identity(case: &Case, entry: &InventoryEntry) -> CoreResult<Map<String, Value>> {
    if !case.displayed_entries().contains(entry) || !can_export(entry) {
        return Err(CoreError::InvalidInput(
            "请选择当前案件清单中的普通文件".to_string(),
        ));
    }
    let image_sha256 = case
        .data()
        .evidence
        .as_ref()
        .and_then(|e| e.sha256.clone())
        .map(Value::String)
        .unwrap_or(Value::Null);
    let mut map = Map::new();
    map.insert("image_sha256".to_string(), image_sha256);
    map.insert("offset".to_string(), Value::from(entry.offset));
    map.insert("inode".to_string(), Value::String(entry.inode.clone()));
    map.insert("deleted".to_string(), Value::from(entry.deleted));
    Ok(map)
}

/// 记录关联到 `entry` 的取证笔记（`FILE_NOTE`）。
pub fn record_note(
    case: &mut Case,
    entry: &InventoryEntry,
    text: &str,
) -> CoreResult<AuditRecord> {
    let mut reference = entry_identity(case, entry)?;
    let source_note = case.source_note();
    if !source_note.is_empty() {
        case.operation_check(None, None, None)?;
        reference.insert(
            "source_verification".to_string(),
            Value::String(case.source_note().to_string()),
        );
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput("记录内容不能为空".to_string()));
    }
    reference.insert("note".to_string(), Value::String(trimmed.to_string()));
    case.log("FILE_NOTE", &entry.path, "成功", reference)
}

/// 记录引用内容搜索命中项的取证笔记（`FILE_NOTE`，包含 `file_byte`、`before`、
/// `after` 与 `search_record` 元数据）。
#[allow(clippy::too_many_arguments)]
pub fn record_search_hit_note(
    case: &mut Case,
    entry: &InventoryEntry,
    text: &str,
    file_byte: u64,
    before: &str,
    after: &str,
    search_record: &str,
) -> CoreResult<AuditRecord> {
    let mut reference = entry_identity(case, entry)?;
    let source_note = case.source_note();
    if !source_note.is_empty() {
        case.operation_check(None, None, None)?;
        reference.insert(
            "source_verification".to_string(),
            Value::String(case.source_note().to_string()),
        );
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidInput("记录内容不能为空".to_string()));
    }
    reference.insert("note".to_string(), Value::String(trimmed.to_string()));
    reference.insert("file_byte".to_string(), Value::from(file_byte));
    if !before.is_empty() {
        reference.insert("before".to_string(), Value::String(before.to_string()));
    }
    if !after.is_empty() {
        reference.insert("after".to_string(), Value::String(after.to_string()));
    }
    if !search_record.is_empty() {
        reference.insert(
            "search_record".to_string(),
            Value::String(search_record.to_string()),
        );
    }
    if entry.deleted {
        reference.insert(
            "source_note".to_string(),
            Value::String(deleted_source_note(entry).to_string()),
        );
    }
    case.log("FILE_NOTE", &entry.path, "成功", reference)
}

/// [`examine`] 的返回结果（`FILE_HASH` 或 `FILE_COMPARE`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExamineResult {
    pub operation: String,
    pub result: String,
    pub details: Map<String, Value>,
}

/// 流式读取镜像内文件以计算其 SHA-256（`FILE_HASH`），并可选地与磁盘上的外部副本进行比对（`FILE_COMPARE`）。
pub fn examine(
    case: &mut Case,
    entry: &InventoryEntry,
    comparison: Option<&Path>,
    tsk: Option<&TskCli>,
) -> CoreResult<ExamineResult> {
    let mut details = entry_identity(case, entry)?;
    let operation = if comparison.is_some() {
        "FILE_COMPARE"
    } else {
        "FILE_HASH"
    };
    details.insert("recorded_size".to_string(), Value::from(entry.size));
    if let Some(cmp) = comparison {
        details.insert(
            "comparison".to_string(),
            Value::String(cmp.to_string_lossy().into_owned()),
        );
    }

    let outcome = (|| -> CoreResult<ExamineResult> {
        if !case.operation_check(tsk, None, None)? {
            return Err(CoreError::IntegrityFailed("原始镜像校验失败".to_string()));
        }
        let source_note = case.source_note();
        if !source_note.is_empty() {
            details.insert(
                "source_verification".to_string(),
                Value::String(source_note.to_string()),
            );
        }

        let image = case.image_path()?;
        let discovered;
        let tool = match tsk {
            Some(t) => t,
            None => {
                discovered = TskCli::discover(None)?;
                &discovered
            }
        };

        let mut hasher = Sha256::new();
        let (size, read_note) = tool.stream_entry(&image, entry, None, |chunk| {
            hasher.update(chunk);
            Ok(())
        })?;
        let digest = hex_lower(&hasher.finalize());
        if !read_note.is_empty() {
            details.insert("read_note".to_string(), Value::String(read_note));
        }
        details.insert("size".to_string(), Value::from(size));
        details.insert("sha256".to_string(), Value::String(digest.clone()));

        if !case.operation_check(tsk, None, None)? {
            return Err(CoreError::IntegrityFailed(
                "读取期间原始镜像发生变化".to_string(),
            ));
        }

        let mut result = "成功";
        if let Some(cmp) = comparison {
            let cmp_digest = sha256_file(cmp, None, None)?;
            details.insert(
                "comparison_sha256".to_string(),
                Value::String(cmp_digest.clone()),
            );
            result = if digest == cmp_digest {
                "一致"
            } else {
                "不一致"
            };
        }
        if size < entry.size {
            result = if comparison.is_none() {
                "部分读取"
            } else {
                "部分读取，无法确认完整一致性"
            };
        }
        let src_note = if entry.deleted {
            deleted_source_note(entry)
        } else {
            ""
        };
        details.insert("source_note".to_string(), Value::String(src_note.to_string()));

        case.log(operation, &entry.path, result, details.clone())?;
        Ok(ExamineResult {
            operation: operation.to_string(),
            result: result.to_string(),
            details: details.clone(),
        })
    })();

    if let Err(err) = outcome {
        let mut fail_details = details;
        fail_details.insert("error".to_string(), Value::String(err.to_string()));
        let _ = case.log(operation, &entry.path, "失败", fail_details);
        return Err(err);
    }
    outcome
}
