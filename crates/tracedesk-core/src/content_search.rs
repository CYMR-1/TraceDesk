//! Multi-core SIMD exact byte search (`UTF-8` / `UTF-16LE` / `GBK` / `HEX`) with hardlink
//! deduplication, rolling-window inode sorting, 64 MiB / 32 MiB parallel large-file splitting
//! with sparse-zero skipping, 8-thread `icat` fallback pool, instant `AtomicBool` cancellation,
//! and strict original-inventory-order streaming hit publication (`core-contract.md` §2.3, §3.8).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use memchr::memmem;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracedesk_engines::{
    ByteInterval, EngineError, EntryReadPlan, InventoryEntry, MediaReader, SourceGuard, TskCli,
    VolumeReader, can_export, deleted_source_note, ewf, open_media, sha256_file,
};
use uuid::Uuid;

use crate::case::{Case, PartitionScan, StageProgress};
use crate::error::{CoreError, CoreResult};
use crate::formatting::hex_lower;

/// Streaming callback receiving hit batches in strict original inventory order.
pub type HitCallback<'a> = &'a mut dyn FnMut(&[SearchHit]);

type IcatOutcome = CoreResult<(DedupKey, Vec<RawHit>, Option<String>)>;

/// Context bytes captured before and after each match.
pub const CONTEXT_BYTES: usize = 12;
/// Initial rolling window file budget (fast time-to-first-hit).
pub const WIN_INIT_FILES: usize = 2048;
/// Maximum rolling window file budget.
pub const WIN_MAX_FILES: usize = 8192;
/// Initial rolling window byte budget (128 MiB).
pub const WIN_INIT_BYTES: u64 = 128 << 20;
/// Maximum rolling window byte budget (512 MiB).
pub const WIN_MAX_BYTES: u64 = 512 << 20;
/// Files at or above 64 MiB are split into 32 MiB parallel pieces.
pub const PIECE_SPLIT_MIN: u64 = 64 << 20;
/// Piece size for parallel large-file scanning (32 MiB).
pub const PIECE_BYTES: u64 = 32 << 20;
/// Concurrency level for external `icat` fallback subprocess pool.
pub const ICAT_THREADS: usize = 8;

const STREAM_CHUNK_BYTES: usize = 1024 * 1024;

/// Format bytes as lowercase space-separated 2-digit hex (`"43 61 73 65 20"`), `""` if empty.
pub fn hex_spaced_lower(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 3 - 1);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Encode a search `query` under `encoding` (`UTF-8`, `UTF-16LE`, `GBK`, `HEX`) and enforce
/// the `1..=4096` byte length limit (`core-contract.md` §3.8).
pub fn parse_pattern(query: &str, encoding: &str) -> CoreResult<Vec<u8>> {
    let bytes = match encoding.trim().to_ascii_uppercase().as_str() {
        "HEX" => decode_hex_pattern(query)?,
        "UTF-8" | "UTF8" => query.as_bytes().to_vec(),
        "UTF-16LE" | "UTF16LE" => query
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>(),
        "GBK" => {
            let (cow, _, had_errors) = encoding_rs::GBK.encode(query);
            if had_errors {
                return Err(CoreError::InvalidInput(
                    "搜索内容包含无法以 GBK 编码的字符".to_string(),
                ));
            }
            cow.into_owned()
        }
        other => {
            return Err(CoreError::InvalidInput(format!(
                "不支持的内容搜索编码：{other}（支持 UTF-8 / UTF-16LE / GBK / HEX）"
            )));
        }
    };
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(CoreError::InvalidInput(
            "搜索内容须为 1 至 4096 字节".to_string(),
        ));
    }
    Ok(bytes)
}

fn decode_hex_pattern(raw: &str) -> CoreResult<Vec<u8>> {
    let clean: Vec<u8> = raw.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err(CoreError::InvalidInput(
            "十六进制搜索内容长度须为偶数".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for &pair in clean.as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[inline]
fn hex_nibble(b: u8) -> CoreResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(CoreError::InvalidInput(
            "十六进制搜索内容包含非法字符".to_string(),
        )),
    }
}

/// Raw match coordinate & hex context within a single file stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHit {
    pub file_byte: u64,
    pub before: String,
    pub after: String,
}

/// Streaming AVX2 SIMD (`memchr::memmem`) sliding-window matcher preserving exact 12-byte
/// `before`/`after` context across chunk boundaries and supporting overlapping hits.
pub struct StreamMatcher<'a> {
    finder: &'a memmem::Finder<'a>,
    needle_len: usize,
    total_len: u64,
    base_offset: u64,
    emit_lo: u64,
    emit_hi: u64,
    limit: Option<usize>,
    tail: Vec<u8>,
    work_buf: Vec<u8>,
    consumed: u64,
    cursor: u64,
    hits: Vec<RawHit>,
}

impl<'a> StreamMatcher<'a> {
    pub fn new(
        finder: &'a memmem::Finder<'a>,
        needle_len: usize,
        total_len: u64,
        base_offset: u64,
        emit_lo: u64,
        emit_hi: u64,
        limit: Option<usize>,
    ) -> Self {
        Self {
            finder,
            needle_len,
            total_len,
            base_offset,
            emit_lo,
            emit_hi,
            limit,
            tail: Vec::new(),
            work_buf: Vec::new(),
            consumed: 0,
            cursor: 0,
            hits: Vec::new(),
        }
    }

    /// Feed the next contiguous chunk of bytes; returns `Ok(true)` if the hit `limit` was reached.
    pub fn push_chunk(&mut self, block: &[u8], cancel: Option<&AtomicBool>) -> CoreResult<bool> {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
        }
        let base = self.consumed - (self.tail.len() as u64);
        self.work_buf.clear();
        self.work_buf.reserve(self.tail.len() + block.len());
        self.work_buf.extend_from_slice(&self.tail);
        self.work_buf.extend_from_slice(block);
        self.consumed += block.len() as u64;

        let at_end = self.consumed >= self.total_len || block.is_empty();
        let search_end = if at_end {
            self.work_buf.len()
        } else {
            self.work_buf.len().saturating_sub(CONTEXT_BYTES)
        };

        while search_end >= self.needle_len {
            let start_in_buf = self.cursor.saturating_sub(base) as usize;
            if start_in_buf + self.needle_len > search_end {
                break;
            }
            let Some(rel) = self
                .finder
                .find(&self.work_buf[start_in_buf..search_end])
            else {
                break;
            };
            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
            }
            let pos = start_in_buf + rel;
            let file_byte = self.base_offset + base + (pos as u64);
            self.cursor = base + (pos as u64) + 1;
            if file_byte >= self.emit_hi {
                break;
            }
            if file_byte >= self.emit_lo {
                let before_start = pos.saturating_sub(CONTEXT_BYTES);
                let after_start = pos + self.needle_len;
                let after_end = (after_start + CONTEXT_BYTES).min(self.work_buf.len());
                self.hits.push(RawHit {
                    file_byte,
                    before: hex_spaced_lower(&self.work_buf[before_start..pos]),
                    after: hex_spaced_lower(&self.work_buf[after_start..after_end]),
                });
                if self.limit.is_some_and(|l| self.hits.len() >= l) {
                    return Ok(true);
                }
            }
        }

        let advance = base + (search_end as u64).saturating_sub(self.needle_len as u64) + 1;
        self.cursor = self.cursor.max(advance);

        let keep = (self.needle_len + 2 * CONTEXT_BYTES).min(self.work_buf.len());
        self.tail.clear();
        self.tail
            .extend_from_slice(&self.work_buf[self.work_buf.len() - keep..]);
        Ok(false)
    }

    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    pub fn into_hits(self) -> Vec<RawHit> {
        self.hits
    }
}

/// Search an arbitrary `Read` stream of known `size` using AVX2 SIMD `memmem`.
pub fn find_matches_in_reader<R: Read>(
    reader: &mut R,
    size: u64,
    needle: &[u8],
    cancel: Option<&AtomicBool>,
    limit: Option<usize>,
    progress: Option<&dyn Fn(u64, u64)>,
) -> CoreResult<Vec<RawHit>> {
    if size < needle.len() as u64 || needle.is_empty() {
        return Ok(Vec::new());
    }
    let finder = memmem::Finder::new(needle);
    let mut matcher = StreamMatcher::new(&finder, needle.len(), size, 0, 0, size, limit);
    let mut buf = vec![0u8; (size as usize).min(STREAM_CHUNK_BYTES)];
    while matcher.consumed() < size {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
        }
        let want = ((size - matcher.consumed()) as usize).min(buf.len());
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("仅读到 {}/{size} 字节", matcher.consumed()),
            )));
        }
        let reached_limit = matcher.push_chunk(&buf[..n], cancel)?;
        if let Some(cb) = progress {
            cb(matcher.consumed(), size);
        }
        if reached_limit {
            break;
        }
    }
    Ok(matcher.into_hits())
}

/// Selected single-file target metadata recorded in `reports/search_<32hex>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedSearchTarget {
    pub path: String,
    pub offset: u64,
    pub inode: String,
}

/// Error encountered while reading an individual entry during content search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchErrorEntry {
    pub path: String,
    pub offset: u64,
    pub inode: String,
    pub error: String,
}

/// Single content search match serialized into `reports/search_<32hex>.json` (`core-contract.md` §2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub path: String,
    pub offset: u64,
    pub inode: String,
    pub deleted: bool,
    pub file_byte: u64,
    pub before: String,
    pub after: String,
    pub reallocated: bool,
    pub source_note: String,
}

/// Full content search record persisted to `reports/search_<32hex>.json` (`core-contract.md` §2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchRecord {
    pub query: String,
    pub encoding: String,
    pub needle: String,
    pub image_sha256: Option<String>,
    pub verification: String,
    pub scope: String,
    pub selected: Option<SelectedSearchTarget>,
    pub partition_scans: Vec<PartitionScan>,
    pub status: String,
    pub visited: usize,
    pub eligible: usize,
    pub errors: Vec<SearchErrorEntry>,
    pub hits: Vec<SearchHit>,
}

/// Parameters for [`search_case`].
#[derive(Debug, Clone)]
pub struct SearchOptions {
    pub query: String,
    pub encoding: String,
    pub limit: Option<usize>,
    pub selected: Option<InventoryEntry>,
}

/// Output returned by [`search_case`].
#[derive(Debug, Clone)]
pub struct SearchOutput {
    pub record: SearchRecord,
    pub report_name: String,
    pub report_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DedupKey {
    Shared {
        offset: u64,
        inode: String,
        size: u64,
    },
    Unique(usize),
}

fn parse_inode_num(inode: &str) -> Option<u64> {
    let first = inode.split('-').next()?;
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    first.parse::<u64>().ok()
}

fn scan_direct_intervals(
    vol: &mut VolumeReader,
    entry: &InventoryEntry,
    intervals: &[ByteInterval],
    needle: &[u8],
    finder: &memmem::Finder<'_>,
    limit: Option<usize>,
    cancel: &AtomicBool,
) -> CoreResult<Vec<RawHit>> {
    let mut hits = Vec::new();
    let extra = (needle.len() as u64).saturating_sub(1) + CONTEXT_BYTES as u64;
    for iv in intervals {
        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
        }
        let read_lo = iv.start.saturating_sub(CONTEXT_BYTES as u64);
        let read_hi = iv.end.saturating_add(extra).min(entry.size);
        if read_hi.saturating_sub(read_lo) < needle.len() as u64 {
            continue;
        }
        let rem_limit = limit.map(|l| l.saturating_sub(hits.len()));
        if rem_limit == Some(0) {
            break;
        }
        let total = read_hi - read_lo;
        let mut matcher = StreamMatcher::new(
            finder,
            needle.len(),
            total,
            read_lo,
            iv.start,
            iv.end,
            rem_limit,
        );
        let mut pos = read_lo;
        while pos < read_hi {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
            }
            let want = ((read_hi - pos) as usize).min(STREAM_CHUNK_BYTES);
            let block = vol.read_entry_at(entry, pos, want)?;
            if block.len() != want {
                return Err(CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "原始文件内容短读",
                )));
            }
            let reached = matcher.push_chunk(&block, Some(cancel))?;
            pos += want as u64;
            if reached {
                break;
            }
        }
        hits.extend(matcher.into_hits());
        if limit.is_some_and(|l| hits.len() >= l) {
            break;
        }
    }
    Ok(hits)
}

#[allow(clippy::too_many_arguments)]
fn scan_via_icat(
    tool: &TskCli,
    image: &Path,
    entry: &InventoryEntry,
    needle: &[u8],
    finder: &memmem::Finder<'_>,
    limit: Option<usize>,
    cancel: &AtomicBool,
    byte_progress: Option<StageProgress<'_>>,
) -> CoreResult<(Vec<RawHit>, Option<String>)> {
    if cancel.load(Ordering::Relaxed) {
        return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
    }
    if entry.size < needle.len() as u64 {
        return Ok((Vec::new(), None));
    }

    let mut matcher = StreamMatcher::new(
        finder,
        needle.len(),
        entry.size,
        0,
        0,
        entry.size,
        limit,
    );
    let mut hit_limit = false;

    let stream_res = tool.stream_entry(image, entry, Some(cancel), |chunk| {
        if cancel.load(Ordering::Relaxed) {
            return Err(EngineError::Cancelled("已取消内容搜索".to_string()));
        }
        let reached = matcher
            .push_chunk(chunk, Some(cancel))
            .map_err(|e| EngineError::Cancelled(e.to_string()))?;
        if let Some(cb) = byte_progress {
            cb("搜索文件字节", matcher.consumed(), entry.size);
        }
        if reached {
            hit_limit = true;
            return Err(EngineError::Cancelled("hit_limit".to_string()));
        }
        Ok(())
    });

    if cancel.load(Ordering::Relaxed) {
        return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
    }

    match stream_res {
        Ok(_) => Ok((matcher.into_hits(), None)),
        Err(err) if hit_limit && err.is_cancelled() => Ok((matcher.into_hits(), None)),
        Err(err) if err.is_cancelled() => Err(CoreError::Cancelled("已取消内容搜索".to_string())),
        Err(err) => Ok((matcher.into_hits(), Some(err.to_string()))),
    }
}

struct DirectTask {
    key: DedupKey,
    piece_start: u64,
    entry: InventoryEntry,
    sort_key: (u64, u64, u64), // (offset, inode_num, piece_start)
    preplanned_intervals: Option<Vec<ByteInterval>>,
}

enum DirectOutcome {
    Hits(Vec<RawHit>),
    NeedsIcat,
}

/// Execute content search over all exportable entries (or a single `selected` entry),
/// streaming hits strictly in original inventory order via `on_hit`, persisting
/// `reports/search_<32hex>.json`, and logging `CONTENT_SEARCH` (`core-contract.md` §2.3, §3.8).
pub fn search_case(
    case: &mut Case,
    options: &SearchOptions,
    cancel: &AtomicBool,
    progress: Option<StageProgress<'_>>,
    mut on_hit: Option<HitCallback<'_>>,
    tsk: Option<&TskCli>,
) -> CoreResult<SearchOutput> {
    let needle = parse_pattern(&options.query, &options.encoding)?;
    let image = case.image_path()?;
    let evidence = case
        .data()
        .evidence
        .as_ref()
        .ok_or_else(|| CoreError::InvalidInput("请先加载镜像".to_string()))?
        .clone();

    if let Some(ref sel) = options.selected
        && (!can_export(sel) || !case.displayed_entries().contains(sel))
    {
        return Err(CoreError::InvalidInput(
            "请选择当前案件中的普通文件".to_string(),
        ));
    }
    if options.selected.is_none() && case.browsing_directories() {
        return Err(CoreError::InvalidInput(
            "全案搜索需要先在文件浏览中建立完整文件索引，亦可选择搜索单个文件。".to_string(),
        ));
    }

    let entries: Vec<InventoryEntry> = match options.selected {
        Some(ref sel) => vec![sel.clone()],
        None => case
            .data()
            .inventory
            .iter()
            .filter(|e| can_export(e))
            .cloned()
            .collect(),
    };

    let discovered;
    let tool = match tsk {
        Some(t) => t,
        None => {
            discovered = TskCli::discover(None)?;
            &discovered
        }
    };

    let mut hits: Vec<SearchHit> = Vec::new();
    let mut errors: Vec<SearchErrorEntry> = Vec::new();
    let mut completed: usize = 0;
    let mut state = "完成".to_string();
    let mut verification = "校验未完成".to_string();

    let run_result: CoreResult<()> = (|| {
        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
        }

        let source_paths = if evidence.is_ewf() {
            ewf::discover_segments(&image)?
        } else {
            vec![image.clone()]
        };
        let guard = SourceGuard::acquire(&source_paths).ok();
        let protected = guard.is_some();

        let pre_cb = |done: u64, total: u64| {
            if let Some(p) = progress {
                p("搜索前校验", done, total);
            }
        };
        let pre_ref: Option<&(dyn Fn(u64, u64) + Sync)> = progress.map(|_| &pre_cb as _);
        if !case.operation_check(Some(tool), Some(cancel), pre_ref)? {
            return Err(CoreError::IntegrityFailed(
                "镜像摘要与案件不一致，拒绝使用搜索结果".to_string(),
            ));
        }

        verification = if !case.source_note().is_empty() {
            case.source_note().to_string()
        } else if protected {
            "全程持有镜像只读共享句柄，搜索前复算 SHA-256".to_string()
        } else {
            "搜索前后分别复算 SHA-256".to_string()
        };

        let total = entries.len();
        if total > 0 {
            let nlen = needle.len() as u64;
            let finder = memmem::Finder::new(&needle);
            let byte_progress = if total == 1 { progress } else { None };
            if byte_progress.is_none()
                && let Some(p) = progress
            {
                p("搜索文件内容", 0, total as u64);
            }

            // Hardlink reference counts for non-deleted regular files.
            let mut key_counts: HashMap<DedupKey, usize> = HashMap::new();
            for entry in &entries {
                if entry.size >= nlen && !entry.deleted && entry.mode.starts_with("r/") {
                    let key = DedupKey::Shared {
                        offset: entry.offset,
                        inode: entry.inode.clone(),
                        size: entry.size,
                    };
                    *key_counts.entry(key).or_insert(0) += 1;
                }
            }
            let mut shared_remaining: HashMap<DedupKey, usize> = key_counts
                .into_iter()
                .filter(|&(_, count)| count > 1)
                .collect();
            let mut shared_cache: HashMap<DedupKey, (Vec<RawHit>, Option<String>)> = HashMap::new();

            let media: Option<Arc<dyn MediaReader>> = open_media(&image).ok();
            let mut probe_vol: Option<VolumeReader> = media
                .as_ref()
                .map(|m| VolumeReader::open_with_media(Arc::clone(m)));
            let icat_pool = rayon::ThreadPoolBuilder::new()
                .num_threads(ICAT_THREADS)
                .build()
                .map_err(|e| CoreError::Other(format!("无法创建 icat 线程池：{e}")))?;

            let mut cursor = 0usize;
            let mut emitted = 0usize;
            let mut win_files = WIN_INIT_FILES;
            let mut max_win_bytes = WIN_INIT_BYTES;
            let mut hit_limit_reached = false;

            while cursor < total && !hit_limit_reached {
                if cancel.load(Ordering::Relaxed) {
                    return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
                }

                // 1. Slice the next rolling window while preserving original inventory order.
                let mut win_end = cursor;
                let mut win_bytes: u64 = 0;
                let mut win_seen_keys: HashSet<DedupKey> = HashSet::new();
                while win_end < total && (win_end - cursor) < win_files {
                    let entry = &entries[win_end];
                    let size = entry.size;
                    let mut cost = 0u64;
                    if size >= nlen {
                        if !entry.deleted && entry.mode.starts_with("r/") {
                            let key = DedupKey::Shared {
                                offset: entry.offset,
                                inode: entry.inode.clone(),
                                size,
                            };
                            if !shared_cache.contains_key(&key) && win_seen_keys.insert(key) {
                                cost = size.min(128 << 20);
                            }
                        } else {
                            cost = size.min(128 << 20);
                        }
                    }
                    if win_end > cursor && win_bytes.saturating_add(cost) > max_win_bytes {
                        break;
                    }
                    win_bytes = win_bytes.saturating_add(cost);
                    win_end += 1;
                }

                // 2. Partition window entries into skip / hardlink-reuse / direct / icat-fallback.
                let mut entry_keys: HashMap<usize, DedupKey> = HashMap::new();
                let mut key_entry: HashMap<DedupKey, InventoryEntry> = HashMap::new();
                let mut key_results: HashMap<DedupKey, (Vec<RawHit>, Option<String>)> =
                    HashMap::new();
                let mut direct_tasks: Vec<DirectTask> = Vec::new();
                let mut icat_tasks: Vec<(DedupKey, InventoryEntry)> = Vec::new();

                for (idx, entry) in entries.iter().enumerate().take(win_end).skip(cursor) {
                    if entry.size < nlen {
                        let k = DedupKey::Unique(idx);
                        entry_keys.insert(idx, k.clone());
                        key_results.insert(k, (Vec::new(), None));
                        continue;
                    }

                    let is_regular = !entry.deleted && entry.mode.starts_with("r/");
                    let key = if is_regular {
                        DedupKey::Shared {
                            offset: entry.offset,
                            inode: entry.inode.clone(),
                            size: entry.size,
                        }
                    } else {
                        DedupKey::Unique(idx)
                    };
                    entry_keys.insert(idx, key.clone());

                    if shared_cache.contains_key(&key) || key_entry.contains_key(&key) {
                        continue;
                    }
                    key_entry.insert(key.clone(), entry.clone());

                    let Some(ino_num) = parse_inode_num(&entry.inode) else {
                        icat_tasks.push((key, entry.clone()));
                        continue;
                    };

                    if media.is_none() {
                        icat_tasks.push((key, entry.clone()));
                        continue;
                    }

                    if is_regular && entry.size >= PIECE_SPLIT_MIN {
                        let plan = probe_vol
                            .as_mut()
                            .map(|v| v.plan_entry(entry, &needle))
                            .unwrap_or(EntryReadPlan::FallbackToIcat);
                        match plan {
                            EntryReadPlan::FallbackToIcat => {
                                icat_tasks.push((key, entry.clone()));
                            }
                            EntryReadPlan::Direct { intervals, .. } => {
                                if intervals.is_empty() {
                                    key_results.insert(key, (Vec::new(), None));
                                } else {
                                    for iv in intervals {
                                        let mut p_start = iv.start;
                                        while p_start < iv.end {
                                            let p_end = (p_start + PIECE_BYTES).min(iv.end);
                                            direct_tasks.push(DirectTask {
                                                key: key.clone(),
                                                piece_start: p_start,
                                                entry: entry.clone(),
                                                sort_key: (entry.offset, ino_num, p_start),
                                                preplanned_intervals: Some(vec![ByteInterval {
                                                    start: p_start,
                                                    end: p_end,
                                                }]),
                                            });
                                            p_start = p_end;
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        direct_tasks.push(DirectTask {
                            key,
                            piece_start: 0,
                            entry: entry.clone(),
                            sort_key: (entry.offset, ino_num, 0),
                            preplanned_intervals: None,
                        });
                    }
                }

                // 3. Sort direct tasks by (offset, inode_num, piece_start) for MFT/disk locality
                //    and execute in parallel across rayon workers sharing `Arc<dyn MediaReader>`.
                direct_tasks.sort_unstable_by_key(|t| t.sort_key);
                let window_done = AtomicUsize::new(0);

                if let Some(ref shared_media) = media
                    && !direct_tasks.is_empty()
                {
                    let raw_outcomes: Vec<CoreResult<(DedupKey, u64, DirectOutcome)>> = direct_tasks
                        .into_par_iter()
                        .map_init(
                            || VolumeReader::open_with_media(Arc::clone(shared_media)),
                            |vol, task| {
                                if cancel.load(Ordering::Relaxed) {
                                    return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
                                }
                                let intervals = match task.preplanned_intervals {
                                    Some(iv) => iv,
                                    None => match vol.plan_entry(&task.entry, &needle) {
                                        EntryReadPlan::Direct { intervals, .. } => intervals,
                                        EntryReadPlan::FallbackToIcat => {
                                            return Ok((
                                                task.key,
                                                task.piece_start,
                                                DirectOutcome::NeedsIcat,
                                            ));
                                        }
                                    },
                                };
                                match scan_direct_intervals(
                                    vol,
                                    &task.entry,
                                    &intervals,
                                    &needle,
                                    &finder,
                                    options.limit,
                                    cancel,
                                ) {
                                    Ok(found) => {
                                        let done = window_done.fetch_add(1, Ordering::Relaxed) + 1;
                                        if byte_progress.is_none()
                                            && done.is_multiple_of(64)
                                            && let Some(p) = progress
                                        {
                                            p(
                                                "搜索文件内容",
                                                (emitted + done).min(total) as u64,
                                                total as u64,
                                            );
                                        }
                                        Ok((task.key, task.piece_start, DirectOutcome::Hits(found)))
                                    }
                                    Err(err) if err.is_cancelled() => Err(err),
                                    Err(_) => Ok((
                                        task.key,
                                        task.piece_start,
                                        DirectOutcome::NeedsIcat,
                                    )),
                                }
                            },
                        )
                        .collect();

                    // Reassemble pieces per DedupKey deterministically ordered by `piece_start`.
                    let mut assembled: HashMap<DedupKey, (bool, BTreeMap<u64, Vec<RawHit>>)> =
                        HashMap::new();
                    for item in raw_outcomes {
                        let (key, p_start, outcome) = item?;
                        let slot = assembled.entry(key).or_insert_with(|| (false, BTreeMap::new()));
                        match outcome {
                            DirectOutcome::Hits(list) => {
                                slot.1.insert(p_start, list);
                            }
                            DirectOutcome::NeedsIcat => {
                                slot.0 = true;
                            }
                        }
                    }

                    for (key, (needs_icat, pieces)) in assembled {
                        if needs_icat {
                            if let Some(entry) = key_entry.get(&key) {
                                icat_tasks.push((key, entry.clone()));
                            }
                        } else {
                            let mut merged: Vec<RawHit> = Vec::new();
                            for (_, mut piece_hits) in pieces {
                                merged.append(&mut piece_hits);
                            }
                            if let Some(lim) = options.limit {
                                merged.truncate(lim);
                            }
                            key_results.insert(key, (merged, None));
                        }
                    }
                }

                // 4. Run all fallback / FAT-deleted entries concurrently on the 8-thread `icat` pool.
                if !icat_tasks.is_empty() {
                    let icat_outcomes: Vec<IcatOutcome> = icat_pool.install(|| {
                            icat_tasks
                                .into_par_iter()
                                .map(|(key, entry)| {
                                    let (found, err) = scan_via_icat(
                                        tool,
                                        &image,
                                        &entry,
                                        &needle,
                                        &finder,
                                        options.limit,
                                        cancel,
                                        byte_progress,
                                    )?;
                                    Ok((key, found, err))
                                })
                                .collect()
                        });
                    for item in icat_outcomes {
                        let (key, found, err) = item?;
                        key_results.insert(key, (found, err));
                    }
                }

                // Cache hardlinked keys needed by future windows.
                for (key, val) in &key_results {
                    if shared_remaining.contains_key(key) {
                        shared_cache.insert(key.clone(), val.clone());
                    }
                }

                // 5. Publish results strictly in original `entries` order.
                for (idx, entry) in entries.iter().enumerate().take(win_end).skip(cursor) {
                    if cancel.load(Ordering::Relaxed) {
                        return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
                    }
                    let key = &entry_keys[&idx];
                    let (raw_hits, err_msg) = key_results
                        .get(key)
                        .or_else(|| shared_cache.get(key))
                        .cloned()
                        .unwrap_or_default();

                    if let Some(rem) = shared_remaining.get_mut(key) {
                        *rem -= 1;
                        if *rem == 0 {
                            shared_remaining.remove(key);
                            shared_cache.remove(key);
                        }
                    }

                    let src_note = deleted_source_note(entry).to_string();
                    let mut entry_hits: Vec<SearchHit> = raw_hits
                        .into_iter()
                        .map(|h| SearchHit {
                            path: entry.path.clone(),
                            offset: entry.offset,
                            inode: entry.inode.clone(),
                            deleted: entry.deleted,
                            file_byte: h.file_byte,
                            before: h.before,
                            after: h.after,
                            reallocated: entry.reallocated,
                            source_note: src_note.clone(),
                        })
                        .collect();

                    if let Some(lim) = options.limit {
                        let remaining = lim.saturating_sub(hits.len());
                        entry_hits.truncate(remaining);
                    }
                    if !entry_hits.is_empty() {
                        if let Some(ref mut cb) = on_hit {
                            cb(&entry_hits);
                        }
                        hits.extend(entry_hits);
                    }
                    emitted += 1;
                    if let Some(lim) = options.limit
                        && hits.len() >= lim
                    {
                        state = format!("达到 {lim} 条上限，未搜索全部内容");
                        hit_limit_reached = true;
                        break;
                    }
                    if let Some(msg) = err_msg {
                        errors.push(SearchErrorEntry {
                            path: entry.path.clone(),
                            offset: entry.offset,
                            inode: entry.inode.clone(),
                            error: msg,
                        });
                    }
                    completed += 1;
                }

                if byte_progress.is_none()
                    && let Some(p) = progress
                {
                    p("搜索文件内容", emitted.min(total) as u64, total as u64);
                }

                cursor = win_end;
                win_files = (win_files * 2).min(WIN_MAX_FILES);
                max_win_bytes = (max_win_bytes * 2).min(WIN_MAX_BYTES);
            }
        }

        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled("已取消内容搜索".to_string()));
        }

        if let Some(ref g) = guard {
            let latest_paths = if evidence.is_ewf() {
                ewf::discover_segments(&image)?
            } else {
                vec![image.clone()]
            };
            if g.verify_unchanged(&latest_paths).is_err() {
                return Err(CoreError::IntegrityFailed(
                    "搜索期间镜像或分段清单发生变化，结果未发布".to_string(),
                ));
            }
        }
        drop(guard);

        if !protected || evidence.is_large_image() {
            let post_cb = |done: u64, total: u64| {
                if let Some(p) = progress {
                    p("搜索后校验", done, total);
                }
            };
            let post_ref: Option<&(dyn Fn(u64, u64) + Sync)> = progress.map(|_| &post_cb as _);
            if !case.operation_check(Some(tool), Some(cancel), post_ref)? {
                return Err(CoreError::IntegrityFailed(
                    "镜像摘要与案件不一致，拒绝使用搜索结果".to_string(),
                ));
            }
        }

        Ok(())
    })();

    match run_result {
        Ok(()) => {}
        Err(err) if err.is_cancelled() => {
            state = "已取消；结果未发布".to_string();
            hits.clear();
        }
        Err(err) => return Err(err),
    }

    if cancel.load(Ordering::Relaxed) {
        state = "已取消；结果未发布".to_string();
        hits.clear();
    }
    if !errors.is_empty() && state == "完成" {
        state = "部分文件读取失败".to_string();
    }

    let record = SearchRecord {
        query: options.query.clone(),
        encoding: options.encoding.clone(),
        needle: hex_lower(&needle),
        image_sha256: evidence.sha256.clone(),
        verification,
        scope: if options.selected.is_some() {
            "选中文件".to_string()
        } else {
            "清单内可读取的文件，不含未分配空间".to_string()
        },
        selected: options.selected.as_ref().map(|s| SelectedSearchTarget {
            path: s.path.clone(),
            offset: s.offset,
            inode: s.inode.clone(),
        }),
        partition_scans: case.data().partition_scans.clone().unwrap_or_default(),
        status: state.clone(),
        visited: completed,
        eligible: entries.len(),
        errors: errors.clone(),
        hits: hits.clone(),
    };

    let report_name = format!("search_{}.json", Uuid::new_v4().simple());
    let report_path = case.folder().join("reports").join(&report_name);
    let json_text = serde_json::to_string_pretty(&record)?;
    fs::write(&report_path, json_text.as_bytes())?;
    let report_sha256 = sha256_file(&report_path, None, None)?;

    let mut details = Map::new();
    details.insert("query".to_string(), Value::String(options.query.clone()));
    details.insert(
        "encoding".to_string(),
        Value::String(options.encoding.clone()),
    );
    details.insert("hits".to_string(), Value::from(hits.len() as u64));
    details.insert("failed".to_string(), Value::from(errors.len() as u64));
    details.insert("visited".to_string(), Value::from(completed as u64));
    details.insert("eligible".to_string(), Value::from(entries.len() as u64));
    details.insert("sha256".to_string(), Value::String(report_sha256));
    case.log("CONTENT_SEARCH", &report_name, &state, details)?;

    Ok(SearchOutput {
        record,
        report_name,
        report_path,
    })
}
