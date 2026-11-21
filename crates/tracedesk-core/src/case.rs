//! Case lifecycle, isolation, atomic persistence, fast gzip inventory I/O,
//! cross-process locking, large-image directory browsing, and tamper-evident
//! SHA-256 audit hash chain (`core-contract.md` §1.2, §1.3, §2.1, §2.2, §3.4).

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use tracedesk_engines::{
    CaseFileLock, EngineError, FileStamp, InventoryEntry, MediaReader, PartitionInfo,
    SegmentDigest, SourceGuard, TskCli, ewf, map_fat_regions, sha256_file,
};
use uuid::Uuid;

use crate::coverage::{CoverageReport, Provenance, assess_coverage};
use crate::error::{CoreError, CoreResult};
use crate::findings::{AuditOrigin, AuditRecord};
use crate::formatting::{
    can_export, canonical_json_value, case_folder_name, create_unique_case_folder,
    entry_name, export_filename, now, sha256_hex, windows_filename,
};
use crate::paths::{is_within, resolve_clean, strip_verbatim_prefix};
use crate::reporting::render_report;
use crate::timeline::TimelineIndex;

/// Large-image threshold (1 GiB): images at or above this size enter on-demand directory browsing.
pub const LARGE_IMAGE_BYTES: u64 = 1u64 << 30;

/// 64-zero genesis hash for the first entry in `audit.jsonl`.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const DIR_CACHE_MAX_DIRS: usize = 8;
const DIR_CACHE_MAX_ENTRIES: usize = 20_000;

static INVENTORY_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^inventory-[0-9a-f]{32}\.jsonl\.gz$").expect("valid inventory filename regex")
});
static EWF_NUMBERED_EXT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^e\d\d$").expect("valid ewf ext regex"));
static FS_TYPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^File System Type:\s*(\S+)").expect("valid fs type regex"));

/// Tuple layout matching legacy Python `case.json` `source_stamp` rows: `(name, size, mtime_ns, ino)`.
pub type SourceStampRow = (String, u64, i64, u64);

/// Callback reporting `(bytes_done, total_bytes)` progress.
pub type ByteProgress<'a> = &'a (dyn Fn(u64, u64) + Sync);

/// Callback reporting `(stage_label, done, total)` progress.
pub type StageProgress<'a> = &'a (dyn Fn(&str, u64, u64) + Sync);

fn stamp_to_row(s: &FileStamp) -> SourceStampRow {
    (s.name.clone(), s.size, s.mtime_ns, s.ino)
}

fn stamps_to_rows(stamps: &[FileStamp]) -> Vec<SourceStampRow> {
    stamps.iter().map(stamp_to_row).collect()
}

fn deserialize_double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

/// Evidence metadata persisted inside `case.json` (`core-contract.md` §2.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceInfo {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub fixed_at: Option<String>,
    pub partitions: Vec<PartitionInfo>,
    pub layout: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub large_image: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_stamp: Option<Vec<SourceStampRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<SegmentDigest>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageReport>,
}

impl EvidenceInfo {
    pub fn format_label(&self) -> &str {
        self.format.as_deref().unwrap_or("RAW")
    }

    pub fn is_ewf(&self) -> bool {
        self.format.as_deref() == Some("EWF")
    }

    pub fn is_large_image(&self) -> bool {
        self.large_image.unwrap_or(false) || self.size >= LARGE_IMAGE_BYTES
    }
}

/// Single exported copy record stored in `case.json` `exports` (`core-contract.md` §2.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportRecord {
    pub path: String,
    pub source: String,
    pub inode: String,
    pub offset: u64,
    pub sha256: String,
    pub size: u64,
    pub time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_verification: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_double_option"
    )]
    pub image_sha256: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reallocated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_cluster_allocated: Option<bool>,
}

/// Per-partition scan summary stored in `case.json` `partition_scans`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionScan {
    pub offset: u64,
    pub status: String,
    pub count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn default_verify_method() -> String {
    "复算 RAW SHA-256".to_string()
}

/// Latest image integrity verification result stored in `case.json` `verification`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationInfo {
    pub time: String,
    pub actual: Option<String>,
    pub ok: bool,
    #[serde(default = "default_verify_method")]
    pub method: String,
}

/// In-memory case metadata model (with full `inventory` materialized).
#[derive(Debug, Clone, PartialEq)]
pub struct CaseData {
    pub id: String,
    pub number: String,
    pub examiner: String,
    pub target: String,
    pub created: String,
    pub evidence: Option<EvidenceInfo>,
    pub inventory: Vec<InventoryEntry>,
    pub exports: Vec<ExportRecord>,
    pub partition_scans: Option<Vec<PartitionScan>>,
    pub offset: Option<Option<u64>>,
    pub fsstat: Option<String>,
    pub index_verification: Option<String>,
    pub verification: Option<VerificationInfo>,
}

/// On-disk representation of `case.json` (either `inventory_file` + `inventory_count`, or `inventory: []`).
#[derive(Serialize)]
struct CaseJsonDisk<'a> {
    id: &'a str,
    number: &'a str,
    examiner: &'a str,
    target: &'a str,
    created: &'a str,
    evidence: &'a Option<EvidenceInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory: Option<&'a [InventoryEntry]>,
    exports: &'a [ExportRecord],
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: &'a Option<VerificationInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    partition_scans: &'a Option<Vec<PartitionScan>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: &'a Option<Option<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index_verification: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fsstat: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_count: Option<usize>,
}

/// Zero-allocation canonical serialization wrapper for [`InventoryEntry`]:
/// fields are declared in strict alphabetical (UTF-8 / Unicode code point) order matching
/// `canonical_json(&entry)` byte-for-byte without constructing an intermediate `serde_json::Value`.
#[derive(Serialize)]
struct CanonicalInventoryEntry<'a> {
    atime: i64,
    crtime: i64,
    ctime: i64,
    deleted: bool,
    directory: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    extents: &'a Option<Vec<(u64, u64)>>,
    #[serde(skip_serializing_if = "str::is_empty")]
    filesystem: &'a str,
    inode: &'a str,
    mode: &'a str,
    mtime: i64,
    offset: u64,
    path: &'a str,
    reallocated: bool,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_cluster_allocated: &'a Option<bool>,
}

impl<'a> From<&'a InventoryEntry> for CanonicalInventoryEntry<'a> {
    fn from(e: &'a InventoryEntry) -> Self {
        Self {
            atime: e.atime,
            crtime: e.crtime,
            ctime: e.ctime,
            deleted: e.deleted,
            directory: e.directory,
            extents: &e.extents,
            filesystem: &e.filesystem,
            inode: &e.inode,
            mode: &e.mode,
            mtime: e.mtime,
            offset: e.offset,
            path: &e.path,
            reallocated: e.reallocated,
            size: e.size,
            start_cluster_allocated: &e.start_cluster_allocated,
        }
    }
}

/// Write an inventory slice to `path` as fast gzip-compressed (`compresslevel=1`) canonical JSONL.
pub fn write_inventory_gz(
    path: &Path,
    entries: &[InventoryEntry],
    cancel: Option<&AtomicBool>,
) -> CoreResult<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let write_res = (|| -> CoreResult<()> {
        let buffered = BufWriter::with_capacity(256 * 1024, file);
        let mut gz = GzEncoder::new(buffered, Compression::fast());
        let mut line_buf = Vec::with_capacity(512);
        for (idx, entry) in entries.iter().enumerate() {
            if idx.is_multiple_of(1024) && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(CoreError::Cancelled("已取消建立索引".to_string()));
            }
            line_buf.clear();
            serde_json::to_writer(&mut line_buf, &CanonicalInventoryEntry::from(entry))?;
            line_buf.push(b'\n');
            gz.write_all(&line_buf)?;
        }
        let mut inner = gz.finish()?;
        inner.flush()?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = fs::remove_file(path);
    }
    write_res
}

/// Read a gzip-compressed JSONL inventory file from `path`.
pub fn read_inventory_gz(path: &Path) -> CoreResult<Vec<InventoryEntry>> {
    let file = File::open(path)?;
    let gz = GzDecoder::new(BufReader::with_capacity(256 * 1024, file));
    let mut reader = BufReader::with_capacity(256 * 1024, gz);
    let mut entries = Vec::new();
    let mut line = String::with_capacity(512);
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: InventoryEntry = serde_json::from_str(trimmed)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Atomically persist pretty-printed UTF-8 JSON (2-space indent) via `.tmp` + rename.
pub fn save_json_atomic<T: Serialize>(path: &Path, value: &T) -> CoreResult<()> {
    let tmp = path.with_extension("tmp");
    let raw = serde_json::to_string_pretty(value)?;
    fs::write(&tmp, raw.as_bytes())?;
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(CoreError::Io(err));
    }
    Ok(())
}

/// Result of [`Case::measure_hash`], separated from [`Case::accept_hash`] so UI background workers
/// can compute long hashes without holding a mutable borrow on `Case` for the entire duration.
#[derive(Debug, Clone)]
pub struct MeasuredHash {
    pub verification: VerificationInfo,
    pub sha256_update: Option<(String, String)>, // (sha256, fixed_at)
    pub segments_update: Option<Vec<SegmentDigest>>,
    pub source_stamp_update: Option<Vec<SourceStampRow>>,
    pub coverage_update: Option<CoverageReport>,
}

/// Current directory location in large-image quick-browse mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryLocation {
    pub offset: u64,
    pub inode: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirCacheKey {
    offset: u64,
    inode: Option<String>,
    path: String,
}

#[derive(Debug, Clone)]
struct AuditCache {
    file_len: u64,
    mtime_ns: Option<i128>,
    count: u64,
    head: String,
}

fn system_time_to_ns(t: SystemTime) -> Option<i128> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i128)
}

/// Independently verify `<case_dir>/audit.jsonl` and `<case_dir>/audit.head` from disk
/// without mutating any state (`core-contract.md` §1.2).
pub fn verify_audit_chain_at(folder: &Path) -> CoreResult<Vec<AuditRecord>> {
    let audit_path = folder.join("audit.jsonl");
    let content = fs::read_to_string(&audit_path)
        .map_err(|e| CoreError::CorruptCase(format!("无法读取 audit.jsonl：{e}")))?;

    let mut previous = GENESIS_HASH.to_string();
    let mut records = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let seq_expected = (idx + 1) as u64;
        let mut obj: Map<String, Value> = serde_json::from_str(line).map_err(|_| {
            CoreError::AuditTampered(format!("审计链第 {seq_expected} 条记录不完整或被修改"))
        })?;
        let Some(Value::String(signature)) = obj.remove("hash") else {
            return Err(CoreError::AuditTampered(format!(
                "审计链第 {seq_expected} 条记录不完整或被修改"
            )));
        };
        let seq_ok = obj.get("seq").and_then(Value::as_u64) == Some(seq_expected);
        let prev_ok = obj.get("previous").and_then(Value::as_str) == Some(previous.as_str());
        let canonical = canonical_json_value(&Value::Object(obj.clone()))?;
        let computed = sha256_hex(canonical.as_bytes());

        if !seq_ok || !prev_ok || computed != signature {
            return Err(CoreError::AuditTampered(format!(
                "审计链第 {seq_expected} 条记录不完整或被修改"
            )));
        }
        obj.insert("hash".to_string(), Value::String(signature.clone()));
        let record: AuditRecord = serde_json::from_value(Value::Object(obj)).map_err(|_| {
            CoreError::AuditTampered(format!("审计链第 {seq_expected} 条记录不完整或被修改"))
        })?;
        previous = signature;
        records.push(record);
    }

    let anchor = folder.join("audit.head");
    if anchor.exists() {
        let head_text = fs::read_to_string(&anchor)
            .map_err(|e| CoreError::AuditTampered(format!("无法读取审计尾部锚点：{e}")))?;
        if head_text.trim() != previous {
            return Err(CoreError::AuditTampered(
                "审计日志尾部锚点不匹配，可能被截断".to_string(),
            ));
        }
    } else if !records.is_empty() {
        return Err(CoreError::AuditTampered("审计尾部锚点缺失".to_string()));
    }

    Ok(records)
}

/// Active TraceDesk forensic case holding `case.lock`, optional `SourceGuard`, in-memory
/// metadata/inventory, directory browse LRU cache, and audit chain state.
pub struct Case {
    folder: PathBuf,
    actor: String,
    origin: AuditOrigin,
    lease: Option<CaseFileLock>,
    source_guard: Option<SourceGuard>,
    source_paths: Vec<PathBuf>,
    session_verified: bool,
    session_stamp: Option<Vec<SourceStampRow>>,
    inventory_file: Option<String>,
    data: CaseData,
    directory_cache: VecDeque<(DirCacheKey, Vec<InventoryEntry>)>,
    directory_cache_total: usize,
    directory_entries: Vec<InventoryEntry>,
    directory_location: Option<DirectoryLocation>,
    audit_cache: Option<AuditCache>,
}

impl Case {
    /// Create a brand-new case directory under `root`, initialize `case.json` and `audit.jsonl`,
    /// acquire `case.lock`, and append the initial `CASE_CREATE` audit entry.
    pub fn create(
        root: &Path,
        number: &str,
        examiner: &str,
        target: &str,
        folder_name: Option<&str>,
        actor: Option<&str>,
        origin: AuditOrigin,
    ) -> CoreResult<Self> {
        if number.trim().is_empty() || examiner.trim().is_empty() || target.trim().is_empty() {
            return Err(CoreError::InvalidInput(
                "案件编号、取证人员和取证对象不能为空".to_string(),
            ));
        }
        let root_resolved = resolve_clean(root);
        fs::create_dir_all(&root_resolved)?;

        let name = match folder_name {
            Some(explicit) => explicit.to_string(),
            None => case_folder_name(number, examiner, target),
        };
        if name.is_empty() || name != windows_filename(&name, 255) {
            return Err(CoreError::InvalidInput(
                "案件文件夹名称含有无效字符".to_string(),
            ));
        }

        let folder = create_unique_case_folder(&root_resolved, &name)?;
        fs::create_dir(folder.join("exports"))?;
        fs::create_dir(folder.join("reports"))?;

        let init_data = CaseJsonDisk {
            id: &Uuid::new_v4().simple().to_string(),
            number,
            examiner,
            target,
            created: &now(),
            evidence: &None,
            inventory: Some(&[]),
            exports: &[],
            verification: &None,
            partition_scans: &None,
            offset: &None,
            index_verification: &None,
            fsstat: &None,
            inventory_file: None,
            inventory_count: None,
        };
        save_json_atomic(&folder.join("case.json"), &init_data)?;
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(folder.join("audit.jsonl"))?;

        let mut case = Self::open(&folder, actor, origin)?;
        case.log("CASE_CREATE", number, "成功", Map::new())?;
        Ok(case)
    }

    /// Open an existing case directory, acquire `case.lock`, validate metadata & inventory,
    /// verify the entire SHA-256 audit chain, and auto-migrate legacy inline inventories.
    pub fn open(folder: &Path, actor: Option<&str>, origin: AuditOrigin) -> CoreResult<Self> {
        let folder = resolve_clean(folder);
        let metadata_path = folder.join("case.json");
        if !metadata_path.is_file() {
            return Err(CoreError::CorruptCase("缺少案件元数据 case.json".to_string()));
        }

        let lease = CaseFileLock::acquire(&folder.join("case.lock")).map_err(|e| match e {
            EngineError::Locked(msg) => CoreError::Locked(msg),
            other => CoreError::Locked(format!("案件已被占用或无法加锁：{other}")),
        })?;

        let raw_text = fs::read_to_string(&metadata_path)
            .map_err(|e| CoreError::CorruptCase(format!("无法读取 case.json：{e}")))?;
        let mut root_val: Value = serde_json::from_str(&raw_text)
            .map_err(|e| CoreError::CorruptCase(format!("case.json 格式错误：{e}")))?;
        let obj = root_val
            .as_object_mut()
            .ok_or_else(|| CoreError::CorruptCase("case.json 根节点必须为对象".to_string()))?;

        for key in ["id", "examiner", "number", "target", "created"] {
            let valid = obj
                .get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty());
            if !valid {
                return Err(CoreError::CorruptCase(key.to_string()));
            }
        }
        if !obj.get("exports").is_some_and(Value::is_array) {
            return Err(CoreError::CorruptCase("案件清单格式错误".to_string()));
        }

        // Resolve inventory from either `inventory_file` (.jsonl.gz) or legacy inline `inventory`.
        let inventory_file = match obj.remove("inventory_file") {
            Some(Value::String(name)) => Some(name),
            Some(Value::Null) | None => None,
            Some(_) => return Err(CoreError::CorruptCase("清单文件名无效".to_string())),
        };
        let inventory: Vec<InventoryEntry> = if let Some(ref idx_name) = inventory_file {
            if !INVENTORY_FILE_RE.is_match(idx_name) {
                return Err(CoreError::CorruptCase("清单文件名无效".to_string()));
            }
            let expected_count = obj
                .remove("inventory_count")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| CoreError::CorruptCase("缺少 inventory_count".to_string()))?
                as usize;
            let loaded = read_inventory_gz(&folder.join(idx_name))
                .map_err(|e| CoreError::CorruptCase(format!("读取清单文件失败：{e}")))?;
            if loaded.len() != expected_count {
                return Err(CoreError::CorruptCase("案件清单数量不匹配".to_string()));
            }
            loaded
        } else {
            let arr = obj
                .get("inventory")
                .ok_or_else(|| CoreError::CorruptCase("案件清单格式错误".to_string()))?;
            if !arr.is_array() {
                return Err(CoreError::CorruptCase("案件清单格式错误".to_string()));
            }
            serde_json::from_value(arr.clone())
                .map_err(|e| CoreError::CorruptCase(format!("案件清单格式错误：{e}")))?
        };

        // Validate evidence required keys if non-null.
        let evidence: Option<EvidenceInfo> = match obj.get("evidence") {
            None | Some(Value::Null) => None,
            Some(ev_val) => {
                let ev_obj = ev_val
                    .as_object()
                    .ok_or_else(|| CoreError::CorruptCase("证据信息不完整".to_string()))?;
                for req in ["path", "sha256", "layout", "partitions", "fixed_at", "size"] {
                    if !ev_obj.contains_key(req) {
                        return Err(CoreError::CorruptCase("证据信息不完整".to_string()));
                    }
                }
                let mut ev: EvidenceInfo = serde_json::from_value(ev_val.clone())
                    .map_err(|e| CoreError::CorruptCase(format!("证据信息不完整：{e}")))?;
                if ev.size >= LARGE_IMAGE_BYTES {
                    ev.large_image = Some(true);
                }
                Some(ev)
            }
        };

        if !folder.join("reports").is_dir() || !folder.join("exports").is_dir() {
            return Err(CoreError::CorruptCase("案件输出目录缺失".to_string()));
        }

        let id = obj["id"].as_str().unwrap_or_default().to_string();
        let number = obj["number"].as_str().unwrap_or_default().to_string();
        let examiner = obj["examiner"].as_str().unwrap_or_default().to_string();
        let target = obj["target"].as_str().unwrap_or_default().to_string();
        let created = obj["created"].as_str().unwrap_or_default().to_string();
        let exports: Vec<ExportRecord> = serde_json::from_value(obj["exports"].clone())
            .map_err(|e| CoreError::CorruptCase(format!("导出记录格式错误：{e}")))?;
        let partition_scans = match obj.get("partition_scans") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                serde_json::from_value(v.clone())
                    .map_err(|e| CoreError::CorruptCase(format!("partition_scans 格式错误：{e}")))?,
            ),
        };
        let offset = match obj.get("offset") {
            None => None,
            Some(Value::Null) => Some(None),
            Some(v) => Some(Some(v.as_u64().ok_or_else(|| {
                CoreError::CorruptCase("offset 格式错误".to_string())
            })?)),
        };
        let fsstat = obj
            .get("fsstat")
            .and_then(Value::as_str)
            .map(str::to_string);
        let index_verification = obj
            .get("index_verification")
            .and_then(Value::as_str)
            .map(str::to_string);
        let verification = match obj.get("verification") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                serde_json::from_value(v.clone())
                    .map_err(|e| CoreError::CorruptCase(format!("verification 格式错误：{e}")))?,
            ),
        };

        let resolved_actor = actor
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&examiner)
            .to_string();

        let needs_legacy_migration = inventory_file.is_none() && !inventory.is_empty();

        let mut case = Self {
            folder,
            actor: resolved_actor,
            origin,
            lease: Some(lease),
            source_guard: None,
            source_paths: Vec::new(),
            session_verified: false,
            session_stamp: None,
            inventory_file,
            data: CaseData {
                id,
                number,
                examiner,
                target,
                created,
                evidence,
                inventory,
                exports,
                partition_scans,
                offset,
                fsstat,
                index_verification,
                verification,
            },
            directory_cache: VecDeque::new(),
            directory_cache_total: 0,
            directory_entries: Vec::new(),
            directory_location: None,
            audit_cache: None,
        };

        case.check_audit()?;
        if needs_legacy_migration {
            case.save_internal(true, None)?;
        }

        Ok(case)
    }

    /// Release `SourceGuard` and `case.lock`, marking the case closed.
    pub fn close(&mut self) {
        self.source_guard = None;
        self.source_paths.clear();
        self.session_verified = false;
        self.lease = None;
    }

    pub fn is_closed(&self) -> bool {
        self.lease.is_none()
    }

    fn ensure_open(&self) -> CoreResult<()> {
        if self.lease.is_none() {
            return Err(CoreError::CaseClosed);
        }
        Ok(())
    }

    pub fn folder(&self) -> &Path {
        &self.folder
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn origin(&self) -> AuditOrigin {
        self.origin
    }

    pub fn data(&self) -> &CaseData {
        &self.data
    }

    pub fn is_session_verified(&self) -> bool {
        self.session_verified
    }

    pub fn directory_location(&self) -> Option<&DirectoryLocation> {
        self.directory_location.as_ref()
    }

    /// Path of the loaded forensic image, or error if no image is attached yet.
    pub fn image_path(&self) -> CoreResult<PathBuf> {
        let ev = self
            .data
            .evidence
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("请先加载镜像".to_string()))?;
        Ok(PathBuf::from(&ev.path))
    }

    /// True when the case holds a `>= 1 GiB` image that has not yet completed a full partition scan.
    pub fn browsing_directories(&self) -> bool {
        let large = self
            .data
            .evidence
            .as_ref()
            .is_some_and(EvidenceInfo::is_large_image);
        let no_scans = self
            .data
            .partition_scans
            .as_ref()
            .is_none_or(Vec::is_empty);
        large && no_scans
    }

    /// True when the set of scanned partition offsets does not cover all recognized partitions.
    pub fn needs_partition_scan(&self) -> bool {
        let Some(ref ev) = self.data.evidence else {
            return false;
        };
        let expected: HashSet<u64> = ev.partitions.iter().map(|p| p.offset).collect();
        let scanned: HashSet<u64> = self
            .data
            .partition_scans
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|p| p.offset)
            .collect();
        expected != scanned
    }

    /// Entries currently visible to the user (either the quick-browsed directory or full inventory).
    pub fn displayed_entries(&self) -> &[InventoryEntry] {
        if self.browsing_directories() {
            &self.directory_entries
        } else {
            &self.data.inventory
        }
    }

    /// Persist `case.json` atomically; if `rewrite_inventory` is true and inventory is non-empty,
    /// writes a fresh `inventory-<uuid32>.jsonl.gz` and removes the previous file after replacement.
    pub fn save(&mut self, rewrite_inventory: bool, cancel: Option<&AtomicBool>) -> CoreResult<()> {
        self.save_internal(rewrite_inventory, cancel)
    }

    fn save_internal(
        &mut self,
        rewrite_inventory: bool,
        cancel: Option<&AtomicBool>,
    ) -> CoreResult<()> {
        self.ensure_open()?;
        let previous_index = self.inventory_file.clone();
        let mut next_index = previous_index.clone();

        if rewrite_inventory && !self.data.inventory.is_empty() {
            let new_name = format!("inventory-{}.jsonl.gz", Uuid::new_v4().simple());
            let new_path = self.folder.join(&new_name);
            write_inventory_gz(&new_path, &self.data.inventory, cancel)?;
            next_index = Some(new_name);
        }
        if self.data.inventory.is_empty() {
            next_index = None;
        }

        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            if let Some(ref idx) = next_index
                && previous_index.as_deref() != Some(idx.as_str())
            {
                let _ = fs::remove_file(self.folder.join(idx));
            }
            return Err(CoreError::Cancelled("已取消建立索引".to_string()));
        }

        let (inv_inline, inv_file, inv_count) = match next_index.as_deref() {
            Some(file_name) => (None, Some(file_name), Some(self.data.inventory.len())),
            None => (Some(self.data.inventory.as_slice()), None, None),
        };

        let disk = CaseJsonDisk {
            id: &self.data.id,
            number: &self.data.number,
            examiner: &self.data.examiner,
            target: &self.data.target,
            created: &self.data.created,
            evidence: &self.data.evidence,
            inventory: inv_inline,
            exports: &self.data.exports,
            verification: &self.data.verification,
            partition_scans: &self.data.partition_scans,
            offset: &self.data.offset,
            index_verification: &self.data.index_verification,
            fsstat: &self.data.fsstat,
            inventory_file: inv_file,
            inventory_count: inv_count,
        };

        if let Err(err) = save_json_atomic(&self.folder.join("case.json"), &disk) {
            if let Some(ref idx) = next_index
                && previous_index.as_deref() != Some(idx.as_str())
            {
                let _ = fs::remove_file(self.folder.join(idx));
            }
            return Err(err);
        }

        self.inventory_file = next_index.clone();
        if let Some(prev) = previous_index
            && next_index.as_deref() != Some(prev.as_str())
        {
            let _ = fs::remove_file(self.folder.join(prev));
        }
        Ok(())
    }

    /// Perform full verification of `audit.jsonl` and `audit.head` from disk, refreshing the
    /// internal O(1)-append cache.
    pub fn check_audit(&mut self) -> CoreResult<Vec<AuditRecord>> {
        let records = verify_audit_chain_at(&self.folder)?;
        let meta = fs::metadata(self.folder.join("audit.jsonl"))?;
        let head = records
            .last()
            .map(|r| r.hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        self.audit_cache = Some(AuditCache {
            file_len: meta.len(),
            mtime_ns: meta.modified().ok().and_then(system_time_to_ns),
            count: records.len() as u64,
            head,
        });
        Ok(records)
    }

    /// Check whether the on-disk `audit.jsonl` (`len`, `mtime`) and `audit.head` still match our
    /// in-memory cache; returns `Some((count, head))` on fast-path hit, or `None` requiring a full
    /// chain re-verification.
    fn audit_fast_check(&self) -> Option<(u64, String)> {
        let cache = self.audit_cache.as_ref()?;
        let audit_path = self.folder.join("audit.jsonl");
        let meta = fs::metadata(&audit_path).ok()?;
        if meta.len() != cache.file_len {
            return None;
        }
        let mtime = meta.modified().ok().and_then(system_time_to_ns);
        if mtime.is_none() || mtime != cache.mtime_ns {
            return None;
        }
        let anchor = self.folder.join("audit.head");
        if cache.count == 0 {
            if anchor.exists() {
                let raw = fs::read(&anchor).ok()?;
                if raw != GENESIS_HASH.as_bytes() {
                    return None;
                }
            }
        } else {
            let raw = fs::read(&anchor).ok()?;
            if raw != cache.head.as_bytes() {
                return None;
            }
        }
        Some((cache.count, cache.head.clone()))
    }

    /// Append a new entry to `audit.jsonl` (fsync'd) and update `audit.head` (exact 64 ASCII bytes,
    /// NO trailing newline). Uses the `len`/`mtime`/`head` cache to avoid O(N²) disk re-reads on
    /// bursts while automatically falling back to full chain verification on any external change.
    pub fn log(
        &mut self,
        action: &str,
        subject: &str,
        result: &str,
        details: Map<String, Value>,
    ) -> CoreResult<AuditRecord> {
        self.ensure_open()?;
        let (count, previous) = match self.audit_fast_check() {
            Some(hit) => hit,
            None => {
                self.audit_cache = None;
                let records = self.check_audit()?;
                let prev = records
                    .last()
                    .map(|r| r.hash.clone())
                    .unwrap_or_else(|| GENESIS_HASH.to_string());
                (records.len() as u64, prev)
            }
        };

        let seq = count + 1;
        let timestamp = now();
        let mut unsigned = Map::new();
        unsigned.insert("seq".to_string(), Value::from(seq));
        unsigned.insert("timestamp".to_string(), Value::String(timestamp.clone()));
        unsigned.insert("actor".to_string(), Value::String(self.actor.clone()));
        unsigned.insert(
            "origin".to_string(),
            Value::String(self.origin.as_str().to_string()),
        );
        unsigned.insert("action".to_string(), Value::String(action.to_string()));
        unsigned.insert("subject".to_string(), Value::String(subject.to_string()));
        unsigned.insert("result".to_string(), Value::String(result.to_string()));
        unsigned.insert("details".to_string(), Value::Object(details.clone()));
        unsigned.insert("previous".to_string(), Value::String(previous.clone()));

        let unsigned_canonical = canonical_json_value(&Value::Object(unsigned.clone()))?;
        let hash = sha256_hex(unsigned_canonical.as_bytes());
        unsigned.insert("hash".to_string(), Value::String(hash.clone()));

        let signed_line = canonical_json_value(&Value::Object(unsigned))?;

        // Invalidate cache before I/O so any partial failure forces full verification next time.
        self.audit_cache = None;

        let audit_path = self.folder.join("audit.jsonl");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)?;
        file.write_all(signed_line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        file.sync_all()?;
        drop(file);

        // CRITICAL: exact 64 ASCII hex bytes, NO trailing newline (`scripts/verify_bundle.py:41`).
        fs::write(self.folder.join("audit.head"), hash.as_bytes())?;

        if let Ok(meta) = fs::metadata(&audit_path) {
            self.audit_cache = Some(AuditCache {
                file_len: meta.len(),
                mtime_ns: meta.modified().ok().and_then(system_time_to_ns),
                count: seq,
                head: hash.clone(),
            });
        }

        Ok(AuditRecord {
            seq,
            timestamp,
            actor: self.actor.clone(),
            origin: Some(self.origin.as_str().to_string()),
            action: action.to_string(),
            subject: subject.to_string(),
            result: result.to_string(),
            details,
            previous,
            hash,
        })
    }

    fn hold_source(&mut self, paths: &[PathBuf]) -> CoreResult<Vec<SourceStampRow>> {
        if self.source_guard.is_none() {
            let guard = SourceGuard::acquire(paths)?;
            self.source_paths = paths.to_vec();
            self.source_guard = Some(guard);
        }
        if paths != self.source_paths.as_slice() {
            return Err(CoreError::InvalidInput("镜像分段清单已变化".to_string()));
        }
        let stamps = SourceGuard::snapshot(paths)?;
        Ok(stamps_to_rows(&stamps))
    }

    /// Acquire/verify the OS kernel `FILE_SHARE_READ` guard on all source image files and
    /// confirm file identity/size/mtime have not changed.
    pub fn check_source(&mut self) -> CoreResult<()> {
        self.ensure_open()?;
        let image = self.image_path()?;
        let is_ewf = self
            .data
            .evidence
            .as_ref()
            .is_some_and(EvidenceInfo::is_ewf);
        let paths = if is_ewf {
            ewf::discover_segments(&image)?
        } else {
            vec![image]
        };
        let stamp = self.hold_source(&paths)?;
        let expected = self
            .data
            .evidence
            .as_ref()
            .and_then(|e| e.source_stamp.as_ref())
            .or(self.session_stamp.as_ref());
        if let Some(exp) = expected
            && exp != &stamp
        {
            return Err(CoreError::IntegrityFailed(
                "镜像身份、大小或修改时间与加载记录不一致".to_string(),
            ));
        }
        self.session_stamp = Some(stamp);
        Ok(())
    }

    /// Load a RAW or EWF (`.E01`) image into the case (`core-contract.md` §2.1, §3.4).
    pub fn load_image(
        &mut self,
        image: &Path,
        tsk: Option<&TskCli>,
        cancel: Option<&AtomicBool>,
        progress: Option<&(dyn Fn(u64, u64) + Sync)>,
    ) -> CoreResult<()> {
        self.ensure_open()?;
        if self.data.evidence.is_some() {
            return Err(CoreError::InvalidInput(
                "本原型每案固定一个镜像；请新建案件分析其他镜像".to_string(),
            ));
        }
        let canon = fs::canonicalize(image).map_err(|_| {
            CoreError::NotFound(format!("镜像文件不存在：{}", image.display()))
        })?;
        let image = strip_verbatim_prefix(&canon);
        let cases_root = self.folder.parent().unwrap_or(&self.folder);
        if !image.is_file() || is_within(&image, cases_root) {
            return Err(CoreError::InvalidInput(
                "镜像必须是案件库目录之外的普通文件".to_string(),
            ));
        }

        let image_str = image.to_string_lossy().into_owned();
        self.log("IMAGE_LOAD_BEGIN", &image_str, "开始", Map::new())?;

        let result = (|| -> CoreResult<()> {
            let discovered;
            let tool = match tsk {
                Some(t) => t,
                None => {
                    discovered = TskCli::discover(None)?;
                    &discovered
                }
            };

            let ext = image
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let is_ewf = ext.eq_ignore_ascii_case("e01");
            if EWF_NUMBERED_EXT_RE.is_match(ext) && !is_ewf {
                return Err(CoreError::InvalidInput("请从首段 E01 打开".to_string()));
            }

            let mut size = fs::metadata(&image)?.len();
            let mut ewf_parts: Vec<PathBuf> = Vec::new();
            let mut ewf_stamp: Vec<FileStamp> = Vec::new();
            let mut format: Option<String> = None;
            let mut provenance: Option<Provenance> = None;

            if is_ewf {
                ewf_parts = ewf::discover_segments(&image)?;
                ewf_stamp = SourceGuard::snapshot(&ewf_parts)?;
                let (logical_size, sector_size) = tool.img_stat_ewf(&image)?;
                if sector_size != 512 {
                    return Err(CoreError::InvalidInput(
                        "无法确定受支持的 EWF 逻辑大小或扇区大小".to_string(),
                    ));
                }
                size = logical_size;
                format = Some("EWF".to_string());
                let acq = ewf::acquisition_info(&image);
                provenance = Some(Provenance::from_map(&acq));
            }

            let quick = size >= LARGE_IMAGE_BYTES;
            let mut large_image: Option<bool> = None;
            let mut source_stamp: Option<Vec<SourceStampRow>> = None;
            let mut opened_at: Option<String> = None;
            let mut segments: Option<Vec<SegmentDigest>> = None;
            let baseline: Option<String>;

            if quick {
                let paths = if is_ewf {
                    ewf_parts.clone()
                } else {
                    vec![image.clone()]
                };
                let held = self.hold_source(&paths)?;
                if !is_ewf && size != held[0].1 {
                    return Err(CoreError::IntegrityFailed(
                        "打开期间镜像大小发生变化".to_string(),
                    ));
                }
                large_image = Some(true);
                source_stamp = Some(held);
                opened_at = Some(now());
                baseline = None;
                if is_ewf {
                    let mut segs = Vec::with_capacity(ewf_parts.len());
                    for p in &ewf_parts {
                        segs.push(SegmentDigest {
                            name: p
                                .file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                            size: fs::metadata(p)?.len(),
                            sha256: String::new(),
                        });
                    }
                    segments = Some(segs);
                }
            } else {
                let digest = if is_ewf {
                    let logical = ewf::hash_logical_stream(tool, &image, size, cancel, progress)?;
                    let segs = ewf::hash_physical_segments(&ewf_parts, cancel, progress)?;
                    segments = Some(segs);
                    logical
                } else {
                    sha256_file(&image, cancel, progress)?
                };
                baseline = Some(digest.clone());
                let mut hash_details = Map::new();
                hash_details.insert("sha256".to_string(), Value::String(digest));
                self.log("HASH_FIXED", &image_str, "成功", hash_details)?;
            }

            let (layout, partitions) = tool.inspect(&image)?;
            let coverage = if is_ewf {
                let native_ewf = ewf::EwfMediaReader::open(&image).ok();
                let mut boot_reader = |offset: u64| -> Option<Vec<u8>> {
                    if let Some(ref reader) = native_ewf {
                        let mut buf = vec![0u8; 512];
                        if reader.read_exact_at(offset.saturating_mul(512), &mut buf).is_ok() {
                            return Some(buf);
                        }
                    }
                    tool.read_ewf_sector(&image, offset).ok()
                };
                assess_coverage(&image, &partitions, &layout, Some(size), Some(&mut boot_reader))?
            } else {
                assess_coverage::<fn(u64) -> Option<Vec<u8>>>(
                    &image,
                    &partitions,
                    &layout,
                    Some(size),
                    None,
                )?
            };

            if is_ewf {
                let latest_parts = ewf::discover_segments(&image)?;
                if SourceGuard::snapshot(&latest_parts)? != ewf_stamp {
                    return Err(CoreError::IntegrityFailed(
                        "分析期间 EWF 分段发生变化".to_string(),
                    ));
                }
            }

            let evidence = EvidenceInfo {
                path: image_str.clone(),
                size,
                sha256: baseline.clone(),
                fixed_at: baseline.as_ref().map(|_| now()),
                partitions: partitions.clone(),
                layout,
                format,
                large_image,
                opened_at,
                source_stamp,
                segments,
                provenance,
                coverage: Some(coverage),
            };
            self.data.evidence = Some(evidence);
            self.save_internal(false, None)?;

            let mut load_details = Map::new();
            load_details.insert(
                "sha256".to_string(),
                baseline.map(Value::String).unwrap_or(Value::Null),
            );
            load_details.insert(
                "partitions".to_string(),
                serde_json::to_value(&partitions)?,
            );
            self.log("IMAGE_LOAD", &image_str, "成功", load_details)?;
            Ok(())
        })();

        if let Err(err) = result {
            self.source_guard = None;
            self.source_paths.clear();
            let mut fail_details = Map::new();
            fail_details.insert("error".to_string(), Value::String(err.to_string()));
            let _ = self.log("IMAGE_LOAD", &image_str, "失败", fail_details);
            return Err(err);
        }
        Ok(())
    }

    /// Return the large-image verification status note, or empty string for standard (`< 1 GiB`) images.
    pub fn source_note(&self) -> &'static str {
        let Some(ref ev) = self.data.evidence else {
            return "";
        };
        if ev.is_large_image() {
            if ev.sha256.is_some() && !self.session_verified {
                return "本次会话待复核，请点击“校验完整性”";
            }
            if self.session_verified {
                "本次会话已完成 SHA-256 读取，镜像持续拒写保护"
            } else {
                "初步分析：仅核对源文件身份并持有拒写句柄，整镜像 SHA-256 待固定"
            }
        } else {
            ""
        }
    }

    /// Pre-operation integrity guard (`core-contract.md` §3.4).
    ///
    /// Small images run full `verify_integrity`; large images verify the held `SourceGuard`
    /// and require an explicit session verification when reopened after hash fixing.
    pub fn operation_check(
        &mut self,
        tsk: Option<&TskCli>,
        cancel: Option<&AtomicBool>,
        progress: Option<&(dyn Fn(u64, u64) + Sync)>,
    ) -> CoreResult<bool> {
        let is_large = self
            .data
            .evidence
            .as_ref()
            .is_some_and(EvidenceInfo::is_large_image);
        if !is_large {
            return self.verify_integrity(tsk, cancel, progress);
        }
        self.check_source()?;
        let has_baseline = self
            .data
            .evidence
            .as_ref()
            .and_then(|e| e.sha256.as_ref())
            .is_some();
        if has_baseline && !self.session_verified {
            return Err(CoreError::InvalidInput(
                "案件已重新打开，请先校验完整性以确认本次会话的镜像。".to_string(),
            ));
        }
        Ok(true)
    }

    /// Register or update the 5 evidence provenance fields (`SOURCE_REGISTER`).
    pub fn register_source(&mut self, values: &Provenance) -> CoreResult<()> {
        let image = self.image_path()?;
        let image_str = image.to_string_lossy().into_owned();
        let clean = values.normalized_and_validated()?;
        let mut details = Map::new();
        details.insert(
            "evidence_id".to_string(),
            Value::String(clean.evidence_id.clone()),
        );
        details.insert("source".to_string(), Value::String(clean.source.clone()));
        details.insert(
            "acquired".to_string(),
            Value::String(clean.acquired.clone()),
        );
        details.insert("tool".to_string(), Value::String(clean.tool.clone()));
        details.insert(
            "expected_sha256".to_string(),
            Value::String(clean.expected_sha256.clone()),
        );
        self.log("SOURCE_REGISTER", &image_str, "登记", details)?;
        if let Some(ref mut ev) = self.data.evidence {
            ev.provenance = Some(clean);
        }
        self.save_internal(false, None)?;
        Ok(())
    }

    /// Compute the image hash / segment comparison without committing to `case.json` or audit log.
    pub fn measure_hash(
        &mut self,
        tsk: Option<&TskCli>,
        cancel: Option<&AtomicBool>,
        progress: Option<&(dyn Fn(u64, u64) + Sync)>,
    ) -> CoreResult<MeasuredHash> {
        self.ensure_open()?;
        let ev = self
            .data
            .evidence
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("请先加载镜像".to_string()))?
            .clone();
        let image = PathBuf::from(&ev.path);
        let large = ev.is_large_image();
        if large {
            self.check_source()?;
        }
        let first = ev.sha256.as_deref().is_none_or(str::is_empty);

        let mut segments_update: Option<Vec<SegmentDigest>> = None;
        let mut source_stamp_update: Option<Vec<SourceStampRow>> = None;
        let mut coverage_update: Option<CoverageReport> = None;

        let (actual, ok, mut method) = if ev.is_ewf() {
            let parts = ewf::discover_segments(&image)?;
            let before = SourceGuard::snapshot(&parts)?;
            let mut total_bytes: u64 = 0;
            for p in &parts {
                total_bytes = total_bytes.saturating_add(fs::metadata(p)?.len());
            }
            let logical_size = ev.size;
            let combined_total = logical_size.saturating_add(total_bytes);

            let logical_digest = if first {
                let discovered;
                let tool = match tsk {
                    Some(t) => t,
                    None => {
                        discovered = TskCli::discover(None)?;
                        &discovered
                    }
                };
                let cb = |done: u64, _t: u64| {
                    if let Some(p) = progress {
                        p(done, combined_total);
                    }
                };
                let cb_ref: Option<&(dyn Fn(u64, u64) + Sync)> = progress.map(|_| &cb as _);
                Some(ewf::hash_logical_stream(
                    tool,
                    &image,
                    logical_size,
                    cancel,
                    cb_ref,
                )?)
            } else {
                ev.sha256.clone()
            };

            let phys_cb = |done: u64, _t: u64| {
                if let Some(p) = progress {
                    if first {
                        p(logical_size.saturating_add(done), combined_total);
                    } else {
                        p(done, total_bytes);
                    }
                }
            };
            let phys_ref: Option<&(dyn Fn(u64, u64) + Sync)> = progress.map(|_| &phys_cb as _);
            let segs = ewf::hash_physical_segments(&parts, cancel, phys_ref)?;

            let after_parts = ewf::discover_segments(&image)?;
            if SourceGuard::snapshot(&after_parts)? != before {
                return Err(CoreError::IntegrityFailed(
                    "校验期间 EWF 分段发生变化".to_string(),
                ));
            }
            let ok = first || ev.segments.as_ref() == Some(&segs);
            if first {
                segments_update = Some(segs);
            }
            let actual = if ok { logical_digest } else { None };
            (
                actual,
                ok,
                "逐段复算封装 SHA-256，与首次逻辑流校验时的全部分段比对".to_string(),
            )
        } else {
            let digest = sha256_file(&image, cancel, progress)?;
            let ok = first || ev.sha256.as_deref() == Some(digest.as_str());
            (Some(digest), ok, "复算 RAW SHA-256".to_string())
        };

        if large {
            self.check_source()?;
            if ok && ev.source_stamp.is_none() {
                source_stamp_update = self.session_stamp.clone();
            }
        }
        let sha256_update = if first {
            method = "首次完整读取并建立 SHA-256 基线".to_string();
            actual.as_ref().map(|d| (d.clone(), now()))
        } else {
            None
        };
        if ok && ev.coverage.is_none() {
            coverage_update = Some(assess_coverage::<fn(u64) -> Option<Vec<u8>>>(
                &image,
                &ev.partitions,
                &ev.layout,
                None,
                None,
            )?);
        }

        Ok(MeasuredHash {
            verification: VerificationInfo {
                time: now(),
                actual,
                ok,
                method,
            },
            sha256_update,
            segments_update,
            source_stamp_update,
            coverage_update,
        })
    }

    /// Commit a [`MeasuredHash`] to `case.json`, append `HASH_FIXED` or `HASH_VERIFY`,
    /// and mark the session verified for large images.
    pub fn accept_hash(&mut self, measured: MeasuredHash) -> CoreResult<bool> {
        self.ensure_open()?;
        let is_large = self
            .data
            .evidence
            .as_ref()
            .is_some_and(EvidenceInfo::is_large_image);
        if is_large {
            self.check_source()?;
        }
        let image_str = self.image_path()?.to_string_lossy().into_owned();
        let initial_fixed = measured.sha256_update.is_some();
        let ok = measured.verification.ok;

        if let Some(ref mut ev) = self.data.evidence {
            if let Some((sha, fixed_at)) = measured.sha256_update {
                ev.sha256 = Some(sha);
                ev.fixed_at = Some(fixed_at);
            }
            if let Some(segs) = measured.segments_update {
                ev.segments = Some(segs);
            }
            if let Some(stamps) = measured.source_stamp_update {
                ev.source_stamp = Some(stamps);
            }
            if let Some(cov) = measured.coverage_update {
                ev.coverage = Some(cov);
            }
        }
        self.data.verification = Some(measured.verification.clone());
        self.save_internal(false, None)?;

        if initial_fixed {
            let mut details = Map::new();
            details.insert(
                "sha256".to_string(),
                measured
                    .verification
                    .actual
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            self.log("HASH_FIXED", &image_str, "成功", details)?;
        } else {
            let mut details = Map::new();
            details.insert(
                "actual".to_string(),
                measured
                    .verification
                    .actual
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            details.insert(
                "method".to_string(),
                Value::String(measured.verification.method),
            );
            self.log(
                "HASH_VERIFY",
                &image_str,
                if ok { "通过" } else { "不匹配" },
                details,
            )?;
        }

        self.session_verified = is_large && ok;
        Ok(ok)
    }

    /// Re-verify (or initially fix) the image SHA-256 baseline (`HASH_VERIFY` / `HASH_FIXED`).
    pub fn verify_integrity(
        &mut self,
        tsk: Option<&TskCli>,
        cancel: Option<&AtomicBool>,
        progress: Option<&(dyn Fn(u64, u64) + Sync)>,
    ) -> CoreResult<bool> {
        self.session_verified = false;
        let image_str = self.image_path()?.to_string_lossy().into_owned();
        match self
            .measure_hash(tsk, cancel, progress)
            .and_then(|m| self.accept_hash(m))
        {
            Ok(ok) => Ok(ok),
            Err(err) => {
                let mut details = Map::new();
                details.insert("error".to_string(), Value::String(err.to_string()));
                let _ = self.log("HASH_VERIFY", &image_str, "失败", details);
                Err(err)
            }
        }
    }

    /// Alias for [`Self::verify_integrity`] when explicitly fixing an unhashed large image.
    pub fn fix_hash(
        &mut self,
        tsk: Option<&TskCli>,
        cancel: Option<&AtomicBool>,
        progress: Option<&(dyn Fn(u64, u64) + Sync)>,
    ) -> CoreResult<bool> {
        self.verify_integrity(tsk, cancel, progress)
    }

    /// Browse a single directory on-demand in large-image quick-browse mode (LRU cache: <=8 dirs, <=20k entries).
    pub fn browse_directory(
        &mut self,
        offset: u64,
        dir_inode: Option<&str>,
        path: &str,
        tsk: Option<&TskCli>,
    ) -> CoreResult<Vec<InventoryEntry>> {
        self.ensure_open()?;
        let valid_offset = self.data.evidence.as_ref().is_some_and(|e| {
            self.browsing_directories() && e.partitions.iter().any(|p| p.offset == offset)
        });
        if !valid_offset {
            return Err(CoreError::InvalidInput(
                "请选择快速浏览模式下的已识别分区".to_string(),
            ));
        }
        self.check_source()?;

        let key = DirCacheKey {
            offset,
            inode: dir_inode.map(str::to_string),
            path: path.to_string(),
        };

        let cached = self
            .directory_cache
            .iter()
            .position(|(k, _)| k == &key)
            .and_then(|pos| self.directory_cache.remove(pos))
            .map(|(_, entries)| {
                self.directory_cache_total = self.directory_cache_total.saturating_sub(entries.len());
                entries
            });

        let entries = match cached {
            Some(list) => list,
            None => {
                let discovered;
                let tool = match tsk {
                    Some(t) => t,
                    None => {
                        discovered = TskCli::discover(None)?;
                        &discovered
                    }
                };
                let image = self.image_path()?;
                let mut list = tool.list_entries(&image, offset, false, dir_inode, path, None)?;
                let kind = self
                    .data
                    .evidence
                    .as_ref()
                    .and_then(|e| e.coverage.as_ref())
                    .and_then(|c| c.volumes.iter().find(|v| v.offset == offset))
                    .map(|v| v.filesystem.clone())
                    .unwrap_or_default();
                for row in &mut list {
                    row.filesystem = kind.clone();
                }
                self.check_source()?;
                list
            }
        };

        if entries.len() <= DIR_CACHE_MAX_ENTRIES {
            self.directory_cache_total += entries.len();
            self.directory_cache.push_back((key, entries.clone()));
            while self.directory_cache.len() > DIR_CACHE_MAX_DIRS
                || self.directory_cache_total > DIR_CACHE_MAX_ENTRIES
            {
                if let Some((_, evicted)) = self.directory_cache.pop_front() {
                    self.directory_cache_total =
                        self.directory_cache_total.saturating_sub(evicted.len());
                } else {
                    break;
                }
            }
        }

        self.directory_entries = entries.clone();
        self.directory_location = Some(DirectoryLocation {
            offset,
            inode: dir_inode.map(str::to_string),
            path: path.to_string(),
        });
        Ok(entries)
    }

    fn read_partition(
        &self,
        tool: &TskCli,
        offset: u64,
        cancel: Option<&AtomicBool>,
    ) -> CoreResult<(String, Vec<InventoryEntry>)> {
        let ev = self
            .data
            .evidence
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("请先加载镜像".to_string()))?;
        let image = PathBuf::from(&ev.path);
        let mut info = if ev.is_large_image() {
            let kind = tool.fsstat(&image, offset, true)?.trim().to_ascii_uppercase();
            format!("File System Type: {kind}\n完整索引采用文件系统类型探测。")
        } else {
            tool.fsstat(&image, offset, false)?
        };

        let mut entries = tool.list_entries(&image, offset, true, None, "", cancel)?;
        let fs_name = FS_TYPE_RE
            .captures(&info)
            .map(|c| c[1].to_string())
            .unwrap_or_default();
        for entry in &mut entries {
            entry.filesystem = fs_name.clone();
        }

        if !ev.is_ewf() {
            match map_fat_regions(&image, offset, &info, &mut entries, cancel) {
                Ok(extra) => entries.extend(extra),
                Err(err) if err.is_cancelled() => return Err(CoreError::Engine(err)),
                Err(err) => {
                    info.push_str(&format!("\nFAT 空间区域未能映射：{err}"));
                }
            }
        }
        Ok((info, entries))
    }

    /// Scan a single partition offset (`FILE_BROWSE`).
    pub fn scan_partition(
        &mut self,
        offset: u64,
        tsk: Option<&TskCli>,
        cancel: Option<&AtomicBool>,
    ) -> CoreResult<Vec<InventoryEntry>> {
        self.ensure_open()?;
        let allowed = self
            .data
            .evidence
            .as_ref()
            .is_some_and(|e| e.partitions.iter().any(|p| p.offset == offset));
        if !allowed {
            return Err(CoreError::InvalidInput("请选择已识别分区".to_string()));
        }
        let image_str = self.image_path()?.to_string_lossy().into_owned();
        let res = (|| -> CoreResult<Vec<InventoryEntry>> {
            if !self.operation_check(tsk, cancel, None)? {
                return Err(CoreError::IntegrityFailed(
                    "镜像校验失败，禁止扫描".to_string(),
                ));
            }
            let discovered;
            let tool = match tsk {
                Some(t) => t,
                None => {
                    discovered = TskCli::discover(None)?;
                    &discovered
                }
            };
            let (info, entries) = self.read_partition(tool, offset, cancel)?;
            if !self.operation_check(tsk, cancel, None)? {
                return Err(CoreError::IntegrityFailed(
                    "扫描期间镜像变化，文件清单未保存".to_string(),
                ));
            }
            let count = entries.len();
            self.data.inventory = entries.clone();
            self.data.fsstat = Some(info);
            self.data.offset = Some(Some(offset));
            self.data.partition_scans = Some(vec![PartitionScan {
                offset,
                status: "ready".to_string(),
                count,
                error: None,
            }]);
            self.save_internal(true, cancel)?;

            let mut details = Map::new();
            details.insert("count".to_string(), Value::from(count as u64));
            self.log("FILE_BROWSE", &format!("{image_str}@{offset}"), "成功", details)?;
            Ok(entries)
        })();

        if let Err(err) = res {
            let mut details = Map::new();
            details.insert("error".to_string(), Value::String(err.to_string()));
            let _ = self.log("FILE_BROWSE", &offset.to_string(), "失败", details);
            return Err(err);
        }
        res
    }

    /// Scan all recognized partitions (`FILE_BROWSE` per partition + `PARTITIONS_SCAN`).
    /// Failures on individual partitions are recorded without aborting readable partitions.
    pub fn scan_partitions(
        &mut self,
        tsk: Option<&TskCli>,
        cancel: Option<&AtomicBool>,
        progress: Option<StageProgress<'_>>,
    ) -> CoreResult<Vec<InventoryEntry>> {
        self.ensure_open()?;
        let image_str = self.image_path()?.to_string_lossy().into_owned();
        let partitions = self
            .data
            .evidence
            .as_ref()
            .map(|e| e.partitions.clone())
            .unwrap_or_default();

        let res = (|| -> CoreResult<Vec<InventoryEntry>> {
            let pre_cb = |done: u64, total: u64| {
                if let Some(p) = progress {
                    p("扫描前校验", done, total);
                }
            };
            let pre_ref: Option<&(dyn Fn(u64, u64) + Sync)> = progress.map(|_| &pre_cb as _);
            if !self.operation_check(tsk, cancel, pre_ref)? {
                return Err(CoreError::IntegrityFailed(
                    "镜像校验失败，禁止扫描".to_string(),
                ));
            }

            let discovered;
            let tool = match tsk {
                Some(t) => t,
                None => {
                    discovered = TskCli::discover(None)?;
                    &discovered
                }
            };

            let mut inventory: Vec<InventoryEntry> = Vec::new();
            let mut scans: Vec<PartitionScan> = Vec::with_capacity(partitions.len());
            let mut sections: Vec<String> = Vec::with_capacity(partitions.len());

            for part in &partitions {
                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return Err(CoreError::Cancelled("已取消建立索引".to_string()));
                }
                let offset = part.offset;
                if let Some(p) = progress {
                    p(&format!("扫描分区（偏移 {offset} 扇区）"), 0, 0);
                }
                match self.read_partition(tool, offset, cancel) {
                    Ok((info, entries)) => {
                        let count = entries.len();
                        inventory.extend(entries);
                        scans.push(PartitionScan {
                            offset,
                            status: "ready".to_string(),
                            count,
                            error: None,
                        });
                        let mut d = Map::new();
                        d.insert("count".to_string(), Value::from(count as u64));
                        self.log("FILE_BROWSE", &format!("{image_str}@{offset}"), "成功", d)?;
                        sections.push(format!(
                            "分区偏移 {offset} 扇区 · {}\n{info}",
                            part.description
                        ));
                    }
                    Err(err) if err.is_cancelled() => return Err(err),
                    Err(err) => {
                        let msg = err.to_string();
                        scans.push(PartitionScan {
                            offset,
                            status: "error".to_string(),
                            count: 0,
                            error: Some(msg.clone()),
                        });
                        let mut d = Map::new();
                        d.insert("error".to_string(), Value::String(msg.clone()));
                        self.log("FILE_BROWSE", &format!("{image_str}@{offset}"), "失败", d)?;
                        sections.push(format!(
                            "分区偏移 {offset} 扇区 · {}\n无法读取此分区：{msg}",
                            part.description
                        ));
                    }
                }
            }

            let post_cb = |done: u64, total: u64| {
                if let Some(p) = progress {
                    p("扫描后校验", done, total);
                }
            };
            let post_ref: Option<&(dyn Fn(u64, u64) + Sync)> = progress.map(|_| &post_cb as _);
            if !self.operation_check(tsk, cancel, post_ref)? {
                return Err(CoreError::IntegrityFailed(
                    "扫描期间镜像变化，文件清单未保存".to_string(),
                ));
            }
            if let Some(p) = progress {
                p("保存文件清单", 0, 0);
            }

            let index_note = self.source_note().to_string();
            let failed = scans.iter().filter(|s| s.status == "error").count();
            let total_count = inventory.len();

            self.data.inventory = inventory.clone();
            self.data.partition_scans = Some(scans.clone());
            self.data.offset = Some(None);
            self.data.index_verification = Some(index_note);
            self.data.fsstat = Some(sections.join("\n\n"));
            self.save_internal(true, cancel)?;

            self.directory_cache.clear();
            self.directory_cache_total = 0;
            self.directory_location = None;
            self.directory_entries.clear();

            let mut summary_details = Map::new();
            summary_details.insert("partitions".to_string(), Value::from(scans.len() as u64));
            summary_details.insert("failed".to_string(), Value::from(failed as u64));
            summary_details.insert("count".to_string(), Value::from(total_count as u64));
            self.log(
                "PARTITIONS_SCAN",
                &image_str,
                if failed > 0 { "部分分区不可读" } else { "成功" },
                summary_details,
            )?;
            Ok(inventory)
        })();

        match res {
            Ok(list) => Ok(list),
            Err(err) if err.is_cancelled() => {
                let _ = self.log("PARTITIONS_SCAN", &image_str, "已取消", Map::new());
                Err(err)
            }
            Err(err) => {
                let mut d = Map::new();
                d.insert("error".to_string(), Value::String(err.to_string()));
                let _ = self.log("PARTITIONS_SCAN", &image_str, "失败", d);
                Err(err)
            }
        }
    }

    /// Export full `fsstat` output for a partition into `reports/fsstat-<offset>-<12hex>.txt`
    /// (`FSSTAT_EXPORT`).
    pub fn export_fsstat(&mut self, offset: u64, tsk: Option<&TskCli>) -> CoreResult<PathBuf> {
        self.ensure_open()?;
        let valid = self
            .data
            .evidence
            .as_ref()
            .is_some_and(|e| e.partitions.iter().any(|p| p.offset == offset));
        if !valid {
            return Err(CoreError::InvalidInput("请选择已识别分区".to_string()));
        }
        self.check_source()?;
        let image = self.image_path()?;
        let discovered;
        let tool = match tsk {
            Some(t) => t,
            None => {
                discovered = TskCli::discover(None)?;
                &discovered
            }
        };

        let uuid_hex = Uuid::new_v4().simple().to_string();
        let file_name = format!("fsstat-{offset}-{}.txt", &uuid_hex[..12]);
        let dest = self.folder.join("reports").join(&file_name);
        let temporary = dest.with_extension("partial");

        let res = (|| -> CoreResult<PathBuf> {
            tool.fsstat_to_file(&image, offset, &temporary)?;
            self.check_source()?;
            fs::rename(&temporary, &dest)?;
            let digest = sha256_file(&dest, None, None)?;
            let mut details = Map::new();
            details.insert("offset".to_string(), Value::from(offset));
            details.insert("sha256".to_string(), Value::String(digest));
            details.insert(
                "source_verification".to_string(),
                Value::String(self.source_note().to_string()),
            );
            self.log("FSSTAT_EXPORT", &file_name, "成功", details)?;
            Ok(dest.clone())
        })();

        if res.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        res
    }

    /// Filter `displayed_entries()` by suffix (auto-prefixed with `.`) and path/name keyword,
    /// recording a `FILE_FILTER` audit entry (`core-contract.md` §3.5).
    pub fn filtered(&mut self, suffix: &str, keyword: &str) -> CoreResult<Vec<InventoryEntry>> {
        self.ensure_open()?;
        let mut sfx = suffix.trim().to_lowercase();
        if !sfx.is_empty() && !sfx.starts_with('.') {
            sfx.insert(0, '.');
        }
        let needle = keyword.to_lowercase();
        let items: Vec<InventoryEntry> = self
            .displayed_entries()
            .iter()
            .filter(|f| {
                (sfx.is_empty() || f.path.to_lowercase().ends_with(&sfx))
                    && (needle.is_empty()
                        || f.path.to_lowercase().contains(&needle)
                        || entry_name(f).to_lowercase().contains(&needle))
            })
            .cloned()
            .collect();
        let mut details = Map::new();
        details.insert("keyword".to_string(), Value::String(keyword.to_string()));
        details.insert("count".to_string(), Value::from(items.len() as u64));
        self.log(
            "FILE_FILTER",
            if sfx.is_empty() { "*" } else { &sfx },
            "成功",
            details,
        )?;
        Ok(items)
    }

    /// Export a regular or deleted file from the image into `<case_dir>/exports/` with
    /// atomic no-clobber collision handling (`同名副本-<random>/`) and `FILE_EXPORT` audit.
    pub fn export(&mut self, entry: &InventoryEntry, tsk: Option<&TskCli>) -> CoreResult<PathBuf> {
        self.ensure_open()?;
        if !self.displayed_entries().contains(entry) || !can_export(entry) {
            return Err(CoreError::InvalidInput(
                "请选择当前文件清单中的普通文件或已删除文件".to_string(),
            ));
        }

        let name = export_filename(&entry.path);
        let exports_dir = self.folder.join("exports");
        let mut destination = exports_dir.join(&name);
        let mut duplicate_folder: Option<PathBuf> = None;
        let mut published = false;
        let mut committed = false;

        let res = (|| -> CoreResult<PathBuf> {
            if !self.operation_check(tsk, None, None)? {
                return Err(CoreError::IntegrityFailed(
                    "原始镜像完整性校验失败，禁止导出".to_string(),
                ));
            }
            let image = self.image_path()?;
            let discovered;
            let tool = match tsk {
                Some(t) => t,
                None => {
                    discovered = TskCli::discover(None)?;
                    &discovered
                }
            };

            let staging = tempfile::tempdir_in(&exports_dir)?;
            let partial = staging.path().join("copy");
            let deleted = entry.deleted;
            let read_note = if deleted {
                let mut out_file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&partial)?;
                let (_written, note) = tool.stream_entry(&image, entry, None, |chunk| {
                    out_file.write_all(chunk)?;
                    Ok(())
                })?;
                out_file.flush()?;
                note
            } else {
                tool.export_file(&image, entry.offset, &entry.inode, entry.size, &partial)?;
                String::new()
            };

            let actual_size = fs::metadata(&partial)?.len();
            if !deleted && actual_size != entry.size {
                return Err(CoreError::IntegrityFailed(
                    "导出大小与文件元数据不一致".to_string(),
                ));
            }
            let digest = sha256_file(&partial, None, None)?;
            if !self.operation_check(tsk, None, None)? {
                return Err(CoreError::IntegrityFailed(
                    "导出期间原始镜像变化，副本不可采信".to_string(),
                ));
            }

            // Publish atomically WITHOUT overwriting any existing file at `destination`.
            match fs::hard_link(&partial, &destination) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let dup_dir = tempfile::Builder::new()
                        .prefix("同名副本-")
                        .tempdir_in(&exports_dir)?
                        .keep();
                    let dup_dest = dup_dir.join(&name);
                    fs::hard_link(&partial, &dup_dest).or_else(|_| fs::rename(&partial, &dup_dest))?;
                    duplicate_folder = Some(dup_dir);
                    destination = dup_dest;
                }
                Err(_) => {
                    // Fallback on filesystems without hardlink support (e.g. FAT32).
                    if destination.exists() {
                        let dup_dir = tempfile::Builder::new()
                            .prefix("同名副本-")
                            .tempdir_in(&exports_dir)?
                            .keep();
                        let dup_dest = dup_dir.join(&name);
                        fs::rename(&partial, &dup_dest)?;
                        duplicate_folder = Some(dup_dir);
                        destination = dup_dest;
                    } else {
                        fs::rename(&partial, &destination)?;
                    }
                }
            }
            published = true;
            drop(staging);

            let dest_clean = strip_verbatim_prefix(&destination);
            let source_note = self.source_note();
            let (source_verification, image_sha256) = if !source_note.is_empty() {
                (
                    Some(source_note.to_string()),
                    Some(self.data.evidence.as_ref().and_then(|e| e.sha256.clone())),
                )
            } else {
                (None, None)
            };

            let record = ExportRecord {
                path: dest_clean.to_string_lossy().into_owned(),
                source: entry.path.clone(),
                inode: entry.inode.clone(),
                offset: entry.offset,
                sha256: digest,
                size: actual_size,
                time: now(),
                source_verification,
                image_sha256,
                deleted: deleted.then_some(true),
                recorded_size: deleted.then_some(entry.size),
                read_note: deleted.then_some(read_note),
                reallocated: deleted.then_some(entry.reallocated),
                start_cluster_allocated: deleted
                    .then_some(entry.start_cluster_allocated.unwrap_or(false)),
            };

            self.data.exports.push(record.clone());
            self.save_internal(false, None)?;
            committed = true;

            let details_val = serde_json::to_value(&record)?;
            let details = details_val.as_object().cloned().unwrap_or_default();
            self.log(
                "FILE_EXPORT",
                &entry.path,
                if actual_size < entry.size {
                    "部分导出"
                } else {
                    "成功"
                },
                details,
            )?;
            Ok(dest_clean)
        })();

        if let Err(err) = res {
            if published && !committed {
                let _ = fs::remove_file(&destination);
            }
            if let Some(dup) = duplicate_folder
                && !committed
            {
                let _ = fs::remove_dir(dup);
            }
            let mut details = Map::new();
            details.insert("error".to_string(), Value::String(err.to_string()));
            details.insert("inode".to_string(), Value::String(entry.inode.clone()));
            details.insert("offset".to_string(), Value::from(entry.offset));
            details.insert("deleted".to_string(), Value::from(entry.deleted));
            let _ = self.log("FILE_EXPORT", &entry.path, "失败", details);
            return Err(err);
        }
        res
    }

    /// Build the MACB [`TimelineIndex`] from the case's current inventory without logging.
    pub fn timeline_events(&self) -> TimelineIndex {
        TimelineIndex::build(self.data.inventory.clone())
    }

    /// Build the MACB [`TimelineIndex`] and record a `TIMELINE` audit entry.
    pub fn timeline(&mut self) -> CoreResult<TimelineIndex> {
        let image_str = self.image_path()?.to_string_lossy().into_owned();
        let events = self.timeline_events();
        let mut details = Map::new();
        details.insert("count".to_string(), Value::from(events.len() as u64));
        self.log("TIMELINE", &image_str, "成功", details)?;
        Ok(events)
    }

    /// Verify integrity and generate the 10-section Markdown forensic report
    /// (`reports/report_<12hex>.md`, `REPORT_GENERATE`).
    pub fn report(&mut self, tsk: Option<&TskCli>) -> CoreResult<PathBuf> {
        match self.write_report(tsk) {
            Ok(path) => Ok(path),
            Err(err) => {
                let mut d = Map::new();
                d.insert("error".to_string(), Value::String(err.to_string()));
                let _ = self.log("REPORT_GENERATE", "Markdown", "失败", d);
                Err(err)
            }
        }
    }

    fn write_report(&mut self, tsk: Option<&TskCli>) -> CoreResult<PathBuf> {
        self.ensure_open()?;
        let ev = self
            .data
            .evidence
            .as_ref()
            .ok_or_else(|| CoreError::InvalidInput("请先加载镜像".to_string()))?;
        let is_large = ev.is_large_image();
        let is_ewf = ev.is_ewf();

        let conclusion = if is_large {
            self.operation_check(tsk, None, None)?;
            if !self.session_verified {
                return Err(CoreError::InvalidInput(
                    "生成正式报告前，请先在“校验完整性”中固定整镜像 SHA-256。".to_string(),
                ));
            }
            format!("{}。完整读取时间见校验记录。", self.source_note())
        } else if !self.verify_integrity(tsk, None, None)? {
            "不通过：镜像当前 SHA-256 与固定值不一致。".to_string()
        } else if is_ewf {
            "通过：每个 EWF 分段摘要均与首次解码固定时一致。".to_string()
        } else {
            "通过：本次报告生成时镜像 SHA-256 与初始固定值一致。".to_string()
        };

        self.log("REPORT_GENERATE", "Markdown", "开始", Map::new())?;
        let records = self.check_audit()?;
        let content = render_report(&self.data, &records, &conclusion);

        let uuid_hex = Uuid::new_v4().simple().to_string();
        let destination = self
            .folder
            .join("reports")
            .join(format!("report_{}.md", &uuid_hex[..12]));
        fs::write(&destination, content.as_bytes())?;
        let digest = sha256_file(&destination, None, None)?;

        let dest_clean = strip_verbatim_prefix(&destination);
        let mut details = Map::new();
        details.insert("sha256".to_string(), Value::String(digest));
        self.log(
            "REPORT_GENERATE",
            &dest_clean.to_string_lossy(),
            "成功",
            details,
        )?;
        Ok(dest_clean)
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        self.close();
    }
}
