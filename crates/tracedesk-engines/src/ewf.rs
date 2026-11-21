use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use adler2::adler32_slice;
use flate2::read::ZlibDecoder;
use lru::LruCache;
use rayon::prelude::*;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::error::{EngineError, EngineResult};
use crate::hash::{hex_lower, sha256_file};
use crate::media::{MediaReader, file_read_exact_at};
use crate::tsk::TskCli;
use crate::types::SegmentDigest;
use crate::win::strip_verbatim_prefix;

/// EWF1 (EnCase v1) 8-byte file header signature: `EVF\x09\x0d\x0a\xff\x00`.
pub const EWF1_MAGIC: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

const FILE_HEADER_LEN: u64 = 13;
const SECTION_DESC_LEN: usize = 76;
const VOLUME_BODY_LEN: usize = 1052;
const TABLE_HEADER_LEN: usize = 24;
const CACHE_SHARDS: usize = 16;
const CACHE_ENTRIES_PER_SHARD: usize = 64;
const PARALLEL_BATCH_CHUNKS: usize = 256;

static INFO_SHA256_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?mi)^SHA256 hash\s*:\s*([0-9a-f]{64})\b").expect("valid info sha256 regex")
});
static INFO_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^Version\s*:\s*([^\r\n]+)").expect("valid version regex"));
static INFO_STARTED_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^Acquisition started\s*:\s*([^\r\n(]+)").expect("valid started regex")
});

/// Discover and validate all contiguous EWF segments starting from `.E01`
/// (supports `.E01`–`.E99` and `.EAA`+ alphabetic continuations).
pub fn discover_segments(e01: &Path) -> EngineResult<Vec<PathBuf>> {
    let resolved = fs::canonicalize(e01).map_err(|_| {
        EngineError::InvalidArgument(format!("E01 文件不存在：{}", e01.display()))
    })?;
    let first = strip_verbatim_prefix(&resolved);
    let first_ext = first
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if !first_ext.eq_ignore_ascii_case("e01") {
        return Err(EngineError::InvalidArgument(
            "请选择首段 .E01".to_string(),
        ));
    }
    let first_stem = first
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| EngineError::InvalidArgument("无效的 E01 文件名".to_string()))?
        .to_lowercase();
    let parent = first
        .parent()
        .ok_or_else(|| EngineError::InvalidArgument("无法获取 E01 所在目录".to_string()))?;

    let mut numbered: BTreeMap<u32, PathBuf> = BTreeMap::new();
    let mut other_extensions: HashSet<u32> = HashSet::new();

    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if stem.to_lowercase() != first_stem {
            continue;
        }
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        let suffix = ext.to_ascii_uppercase();
        let bytes = suffix.as_bytes();
        if bytes.len() != 3 {
            continue;
        }
        let number = if bytes[0] == b'E' && bytes[1].is_ascii_digit() && bytes[2].is_ascii_digit() {
            ((bytes[1] - b'0') as u32) * 10 + (bytes[2] - b'0') as u32
        } else if (b'E'..=b'Z').contains(&bytes[0])
            && bytes[1].is_ascii_uppercase()
            && bytes[2].is_ascii_uppercase()
        {
            let num = 100
                + ((bytes[0] - b'E') as u32) * 676
                + ((bytes[1] - b'A') as u32) * 26
                + ((bytes[2] - b'A') as u32);
            if !path.is_file() {
                continue;
            }
            let mut magic = [0u8; 8];
            let valid_magic = File::open(&path)
                .and_then(|mut f| {
                    let n = f.read(&mut magic)?;
                    Ok(n == 8 && magic == EWF1_MAGIC)
                })
                .unwrap_or(false);
            if !valid_magic {
                other_extensions.insert(num);
                continue;
            }
            num
        } else {
            continue;
        };
        numbered.insert(number, path);
    }

    let expected_len = numbered.len() as u32;
    if expected_len == 0
        || numbered
            .keys()
            .copied()
            .ne(1..=expected_len)
    {
        return Err(EngineError::Ewf("E01 分段缺失或编号不连续".to_string()));
    }
    if other_extensions.contains(&(expected_len + 1)) {
        return Err(EngineError::Ewf("EWF 字母续段文件头无效".to_string()));
    }
    Ok((1..=expected_len)
        .map(|i| numbered.remove(&i).expect("contiguous key"))
        .collect())
}

/// Parse companion Guymager `.info` acquisition metadata alongside an `.E01` file.
pub fn acquisition_info(e01: &Path) -> HashMap<String, String> {
    let info_path = e01.with_extension("info");
    let Ok(meta) = fs::metadata(&info_path) else {
        return HashMap::new();
    };
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return HashMap::new();
    }
    let Ok(raw) = fs::read(&info_path) else {
        return HashMap::new();
    };
    let text = String::from_utf8_lossy(&raw);
    let Some(sha_caps) = INFO_SHA256_RE.captures(&text) else {
        return HashMap::new();
    };
    let mut result = HashMap::new();
    result.insert("expected_sha256".to_string(), sha_caps[1].to_ascii_lowercase());
    let file_name = info_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    result.insert("source".to_string(), format!("随附采集记录：{file_name}"));
    if text.contains("GUYMAGER ACQUISITION INFO FILE")
        && let Some(ver) = INFO_VERSION_RE.captures(&text)
    {
        result.insert("tool".to_string(), format!("Guymager {}", ver[1].trim()));
    }
    if let Some(started) = INFO_STARTED_RE.captures(&text) {
        result.insert(
            "acquired".to_string(),
            format!("{}（按采集记录原文）", started[1].trim()),
        );
    }
    result
}

/// Hash all physical EWF segment files in parallel using `rayon` and return digests in original order.
pub fn hash_physical_segments(
    parts: &[PathBuf],
    cancel: Option<&AtomicBool>,
    progress: Option<&(dyn Fn(u64, u64) + Sync)>,
) -> EngineResult<Vec<SegmentDigest>> {
    if parts.is_empty() {
        return Ok(Vec::new());
    }
    let mut sizes = Vec::with_capacity(parts.len());
    let mut total: u64 = 0;
    for path in parts {
        let len = fs::metadata(path)?.len();
        sizes.push(len);
        total = total.saturating_add(len);
    }

    let done_bytes = AtomicU64::new(0);
    let threads = parts.len().clamp(1, 4);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| EngineError::Ewf(format!("无法创建分段哈希线程池：{e}")))?;

    pool.install(|| {
        parts
            .par_iter()
            .zip(sizes.par_iter())
            .map(|(path, &size)| {
                let prev = AtomicU64::new(0);
                let cb = |count: u64, _seg_total: u64| {
                    let old = prev.swap(count, Ordering::Relaxed);
                    let delta = count.saturating_sub(old);
                    let agg = done_bytes.fetch_add(delta, Ordering::Relaxed) + delta;
                    if let Some(p) = progress {
                        p(agg, total);
                    }
                };
                let digest = sha256_file(path, cancel, progress.map(|_| &cb as &(dyn Fn(u64, u64) + Sync)))?;
                let name = path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Ok(SegmentDigest {
                    name,
                    size,
                    sha256: digest,
                })
            })
            .collect()
    })
}

/// Global index entry locating a single EWF1 chunk within one physical segment file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLoc {
    pub segment_idx: u16,
    pub file_offset: u64,
    pub stored_size: u32,
    pub compressed: bool,
}

/// Parsed EWF1 global chunk index across all segments.
#[derive(Debug, Clone)]
pub struct EwfIndex {
    pub segments: Vec<PathBuf>,
    pub chunk_size: usize,
    pub bytes_per_sector: u32,
    pub sectors_per_chunk: u32,
    pub sector_count: u64,
    pub logical_size: u64,
    pub chunks: Vec<ChunkLoc>,
}

#[derive(Debug, Clone, Copy)]
struct VolumeMeta {
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
}

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn parse_section_name(raw: &[u8]) -> Option<&str> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..end]).ok()
}

fn parse_volume_section(file: &File, body_offset: u64, body_len: u64) -> EngineResult<VolumeMeta> {
    if body_len < VOLUME_BODY_LEN as u64 {
        return Err(EngineError::Ewf("EWF1 volume/data 节长度不足".to_string()));
    }
    let mut body = [0u8; VOLUME_BODY_LEN];
    file_read_exact_at(file, body_offset, &mut body)?;

    let expected_crc = read_u32_le(&body, 1048);
    let actual_crc = adler32_slice(&body[..1048]);
    if expected_crc != actual_crc {
        return Err(EngineError::Ewf(format!(
            "EWF1 volume/data 节 Adler-32 校验失败（期望 {expected_crc:#x}，实际 {actual_crc:#x}）"
        )));
    }

    let chunk_count = read_u32_le(&body, 4);
    let sectors_per_chunk = read_u32_le(&body, 8);
    let bytes_per_sector = read_u32_le(&body, 12);
    let sector_count = read_u64_le(&body, 16);

    if chunk_count == 0 || sectors_per_chunk == 0 || bytes_per_sector == 0 || sector_count == 0 {
        return Err(EngineError::Ewf("EWF1 volume 几何参数无效".to_string()));
    }
    Ok(VolumeMeta {
        chunk_count,
        sectors_per_chunk,
        bytes_per_sector,
        sector_count,
    })
}

fn parse_table_section(
    file: &File,
    seg_idx: u16,
    sec_offset: u64,
    sec_size: u64,
    file_len: u64,
    sectors_ranges: &[(u64, u64)],
) -> EngineResult<Vec<ChunkLoc>> {
    if sec_size < (SECTION_DESC_LEN + TABLE_HEADER_LEN + 4) as u64 {
        return Err(EngineError::Ewf("EWF1 table 节长度不足".to_string()));
    }
    let body_offset = sec_offset + SECTION_DESC_LEN as u64;
    let mut hdr = [0u8; TABLE_HEADER_LEN];
    file_read_exact_at(file, body_offset, &mut hdr)?;

    let entry_count = read_u32_le(&hdr, 0) as usize;
    let base_offset = read_u64_le(&hdr, 8);
    let hdr_checksum = read_u32_le(&hdr, 20);
    if adler32_slice(&hdr[..20]) != hdr_checksum {
        return Err(EngineError::Ewf("EWF1 table 头 Adler-32 校验失败".to_string()));
    }
    if entry_count == 0 {
        return Ok(Vec::new());
    }

    let entries_bytes_len = entry_count
        .checked_mul(4)
        .ok_or_else(|| EngineError::Ewf("EWF1 table 项数溢出".to_string()))?;
    let required_body = TABLE_HEADER_LEN
        .checked_add(entries_bytes_len)
        .and_then(|v| v.checked_add(4))
        .ok_or_else(|| EngineError::Ewf("EWF1 table 长度溢出".to_string()))? as u64;
    if sec_size < SECTION_DESC_LEN as u64 + required_body
        || body_offset.saturating_add(required_body) > file_len
    {
        return Err(EngineError::Ewf("EWF1 table 节超出文件边界".to_string()));
    }

    let mut buf = vec![0u8; entries_bytes_len + 4];
    file_read_exact_at(file, body_offset + TABLE_HEADER_LEN as u64, &mut buf)?;

    let entries_slice = &buf[..entries_bytes_len];
    let footer_crc = read_u32_le(&buf, entries_bytes_len);
    if adler32_slice(entries_slice) != footer_crc {
        return Err(EngineError::Ewf("EWF1 table 条目 Adler-32 校验失败".to_string()));
    }

    let mut raw_entries = Vec::with_capacity(entry_count);
    for &chunk4 in entries_slice.as_chunks::<4>().0 {
        let val = u32::from_le_bytes(chunk4);
        let compressed = (val & 0x8000_0000) != 0;
        let offset = base_offset
            .checked_add((val & 0x7FFF_FFFF) as u64)
            .ok_or_else(|| EngineError::Ewf("EWF1 块偏移溢出".to_string()))?;
        raw_entries.push((offset, compressed));
    }

    let mut locs = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let (off, compressed) = raw_entries[i];
        let next_off = if i + 1 < entry_count {
            raw_entries[i + 1].0
        } else {
            // Find the end of the `sectors` section containing `off`.
            sectors_ranges
                .iter()
                .rev()
                .find(|&&(s_start, s_end)| off >= s_start && off < s_end)
                .map(|&(_, s_end)| s_end)
                .or_else(|| (off < sec_offset).then_some(sec_offset))
                .ok_or_else(|| EngineError::Ewf("无法确定 EWF1 末尾块长度".to_string()))?
        };
        if next_off <= off || next_off > file_len {
            return Err(EngineError::Ewf(format!(
                "EWF1 块范围无效：[{off}, {next_off})（文件长度 {file_len}）"
            )));
        }
        let stored_len = next_off - off;
        let stored_size = u32::try_from(stored_len)
            .map_err(|_| EngineError::Ewf("EWF1 单块压缩长度异常".to_string()))?;
        locs.push(ChunkLoc {
            segment_idx: seg_idx,
            file_offset: off,
            stored_size,
            compressed,
        });
    }

    Ok(locs)
}

impl EwfIndex {
    /// Parse an EWF1 (EnCase v1) segment set starting at `.E01` and build the global chunk index.
    pub fn open(e01: &Path) -> EngineResult<Self> {
        let segments = discover_segments(e01)?;
        let mut volume_meta: Option<VolumeMeta> = None;
        let mut chunks: Vec<ChunkLoc> = Vec::new();
        let mut saw_done = false;

        for (idx, seg_path) in segments.iter().enumerate() {
            let seg_idx = u16::try_from(idx)
                .map_err(|_| EngineError::Ewf("EWF 分段数超过上限".to_string()))?;
            let file = File::open(seg_path)?;
            let file_len = file.metadata()?.len();
            if file_len < FILE_HEADER_LEN + SECTION_DESC_LEN as u64 {
                return Err(EngineError::Ewf(format!(
                    "EWF 分段过短：{}",
                    seg_path.display()
                )));
            }

            let mut file_hdr = [0u8; FILE_HEADER_LEN as usize];
            file_read_exact_at(&file, 0, &mut file_hdr)?;
            if file_hdr[0..8] != EWF1_MAGIC {
                return Err(EngineError::Ewf(
                    "非标准 EWF1 文件魔数（可能为 EWF2 或加密格式）".to_string(),
                ));
            }
            if file_hdr[8] != 0x01 || file_hdr[11] != 0x00 || file_hdr[12] != 0x00 {
                return Err(EngineError::Ewf("EWF1 文件头字段无效".to_string()));
            }
            let seg_num = read_u16_le(&file_hdr, 9);
            if seg_num != seg_idx + 1 {
                return Err(EngineError::Ewf(format!(
                    "EWF1 分段序号不匹配：期望 {}，实际 {}",
                    seg_idx + 1,
                    seg_num
                )));
            }

            let mut sec_offset = FILE_HEADER_LEN;
            let mut sectors_ranges: Vec<(u64, u64)> = Vec::new();
            let mut last_table_failed = false;
            let mut visited = 0usize;

            while sec_offset + SECTION_DESC_LEN as u64 <= file_len {
                visited += 1;
                if visited > 100_000 {
                    return Err(EngineError::Ewf("EWF1 节链异常过长或成环".to_string()));
                }
                let mut desc = [0u8; SECTION_DESC_LEN];
                file_read_exact_at(&file, sec_offset, &mut desc)?;

                let expected_crc = read_u32_le(&desc, 72);
                if adler32_slice(&desc[..72]) != expected_crc {
                    return Err(EngineError::Ewf(format!(
                        "EWF1 节描述符 Adler-32 校验失败（偏移 {sec_offset}）"
                    )));
                }

                let sec_type = parse_section_name(&desc[..16])
                    .ok_or_else(|| EngineError::Ewf("EWF1 节类型名非法".to_string()))?;
                let next_offset = read_u64_le(&desc, 16);
                let raw_sec_size = read_u64_le(&desc, 24);
                let sec_size = if raw_sec_size == 0 && next_offset > sec_offset {
                    next_offset - sec_offset
                } else {
                    raw_sec_size
                };

                match sec_type {
                    "volume" | "disk" | "data" => {
                        let body_len = sec_size.saturating_sub(SECTION_DESC_LEN as u64);
                        let meta = parse_volume_section(
                            &file,
                            sec_offset + SECTION_DESC_LEN as u64,
                            body_len,
                        )?;
                        if let Some(prev) = volume_meta {
                            if prev.chunk_count != meta.chunk_count
                                || prev.sectors_per_chunk != meta.sectors_per_chunk
                                || prev.bytes_per_sector != meta.bytes_per_sector
                                || prev.sector_count != meta.sector_count
                            {
                                return Err(EngineError::Ewf(
                                    "EWF1 分段间卷参数不一致".to_string(),
                                ));
                            }
                        } else {
                            volume_meta = Some(meta);
                        }
                    }
                    "sectors" => {
                        if sec_size < SECTION_DESC_LEN as u64
                            || sec_offset.saturating_add(sec_size) > file_len
                        {
                            return Err(EngineError::Ewf("EWF1 sectors 节越界".to_string()));
                        }
                        sectors_ranges.push((
                            sec_offset + SECTION_DESC_LEN as u64,
                            sec_offset + sec_size,
                        ));
                    }
                    "table" => {
                        match parse_table_section(
                            &file,
                            seg_idx,
                            sec_offset,
                            sec_size,
                            file_len,
                            &sectors_ranges,
                        ) {
                            Ok(mut locs) => {
                                chunks.append(&mut locs);
                                last_table_failed = false;
                            }
                            Err(_) => {
                                last_table_failed = true;
                            }
                        }
                    }
                    "table2" => {
                        // Backup table: only consume if the primary `table` failed checksum/parse.
                        if last_table_failed {
                            let mut locs = parse_table_section(
                                &file,
                                seg_idx,
                                sec_offset,
                                sec_size,
                                file_len,
                                &sectors_ranges,
                            )?;
                            chunks.append(&mut locs);
                            last_table_failed = false;
                        }
                    }
                    "next" => {
                        if last_table_failed {
                            return Err(EngineError::Ewf("EWF1 table 节损坏且无有效 table2 备份".to_string()));
                        }
                        break;
                    }
                    "done" => {
                        if last_table_failed {
                            return Err(EngineError::Ewf("EWF1 table 节损坏且无有效 table2 备份".to_string()));
                        }
                        saw_done = true;
                        break;
                    }
                    "header" | "header2" | "hash" | "digest" | "session" | "error2" | "ltree"
                    | "xhash" => {}
                    other => {
                        return Err(EngineError::Ewf(format!(
                            "遇到不受支持的 EWF 节类型：{other}"
                        )));
                    }
                }

                if next_offset <= sec_offset || next_offset >= file_len {
                    break;
                }
                sec_offset = next_offset;
            }

            if last_table_failed {
                return Err(EngineError::Ewf("EWF1 table 节损坏".to_string()));
            }
        }

        let meta = volume_meta
            .ok_or_else(|| EngineError::Ewf("EWF1 缺少 volume/data 节".to_string()))?;
        if !saw_done {
            return Err(EngineError::Ewf("EWF1 缺少末尾 done 节".to_string()));
        }

        let chunk_size = (meta.sectors_per_chunk as usize)
            .checked_mul(meta.bytes_per_sector as usize)
            .ok_or_else(|| EngineError::Ewf("EWF1 块大小溢出".to_string()))?;
        if chunk_size == 0 || chunk_size > 64 * 1024 * 1024 {
            return Err(EngineError::Ewf(format!(
                "EWF1 块大小异常：{chunk_size}"
            )));
        }
        let logical_size = meta
            .sector_count
            .checked_mul(meta.bytes_per_sector as u64)
            .ok_or_else(|| EngineError::Ewf("EWF1 逻辑大小溢出".to_string()))?;
        let expected_chunks = logical_size.div_ceil(chunk_size as u64);

        if chunks.len() != meta.chunk_count as usize || chunks.len() as u64 != expected_chunks {
            return Err(EngineError::Ewf(format!(
                "EWF1 块数量不匹配：索引 {}，卷声明 {}，逻辑推算 {}",
                chunks.len(),
                meta.chunk_count,
                expected_chunks
            )));
        }

        Ok(Self {
            segments,
            chunk_size,
            bytes_per_sector: meta.bytes_per_sector,
            sectors_per_chunk: meta.sectors_per_chunk,
            sector_count: meta.sector_count,
            logical_size,
            chunks,
        })
    }

    #[inline]
    pub fn expected_chunk_logical_len(&self, chunk_idx: usize) -> usize {
        let start = (chunk_idx as u64) * (self.chunk_size as u64);
        let remaining = self.logical_size.saturating_sub(start);
        remaining.min(self.chunk_size as u64) as usize
    }
}

/// Decode and verify a single EWF1 chunk (zlib compressed or raw + trailing LE Adler-32).
fn decode_chunk(
    raw: &[u8],
    compressed: bool,
    chunk_size: usize,
    expected_logical_len: usize,
) -> EngineResult<Vec<u8>> {
    if compressed {
        let mut decoder = ZlibDecoder::new(raw);
        let mut out = Vec::with_capacity(chunk_size);
        let mut limited = decoder.by_ref().take((chunk_size + 1) as u64);
        limited
            .read_to_end(&mut out)
            .map_err(|e| EngineError::Ewf(format!("EWF1 压缩块 zlib/Adler-32 解压失败：{e}")))?;
        if out.len() < expected_logical_len || out.len() > chunk_size {
            return Err(EngineError::Ewf(format!(
                "EWF1 压缩块解压长度异常：{}（期望 {}..={}）",
                out.len(),
                expected_logical_len,
                chunk_size
            )));
        }
        out.truncate(expected_logical_len);
        Ok(out)
    } else {
        // Uncompressed EWF1 chunk: raw chunk bytes followed by 4-byte LE Adler-32 checksum.
        if raw.len() >= chunk_size + 4 {
            let expected = read_u32_le(raw, chunk_size);
            if adler32_slice(&raw[..chunk_size]) == expected {
                return Ok(raw[..expected_logical_len].to_vec());
            }
        }
        if raw.len() >= expected_logical_len + 4 {
            let expected = read_u32_le(raw, expected_logical_len);
            if adler32_slice(&raw[..expected_logical_len]) == expected {
                return Ok(raw[..expected_logical_len].to_vec());
            }
        }
        Err(EngineError::Ewf(
            "EWF1 非压缩块 Adler-32 校验失败或长度不符".to_string(),
        ))
    }
}

/// Thread-safe random-access reader for EWF1 multi-segment images with a sharded LRU chunk cache.
pub struct EwfMediaReader {
    index: Arc<EwfIndex>,
    files: Vec<File>,
    cache: Vec<Mutex<LruCache<usize, Arc<Vec<u8>>>>>,
}

impl EwfMediaReader {
    /// Open an EWF1 image starting from its `.E01` segment.
    pub fn open(e01: &Path) -> EngineResult<Self> {
        let index = Arc::new(EwfIndex::open(e01)?);
        let mut files = Vec::with_capacity(index.segments.len());
        for seg in &index.segments {
            files.push(File::open(seg)?);
        }
        let cap = NonZeroUsize::new(CACHE_ENTRIES_PER_SHARD).expect("non-zero");
        let cache = (0..CACHE_SHARDS)
            .map(|_| Mutex::new(LruCache::new(cap)))
            .collect();
        Ok(Self {
            index,
            files,
            cache,
        })
    }

    /// Access the parsed [`EwfIndex`].
    pub fn index(&self) -> &EwfIndex {
        &self.index
    }

    fn get_chunk(&self, chunk_idx: usize) -> EngineResult<Arc<Vec<u8>>> {
        let shard_idx = chunk_idx % CACHE_SHARDS;
        if let Ok(mut guard) = self.cache[shard_idx].lock()
            && let Some(cached) = guard.get(&chunk_idx)
        {
            return Ok(Arc::clone(cached));
        }

        let loc = *self
            .index
            .chunks
            .get(chunk_idx)
            .ok_or_else(|| EngineError::Ewf(format!("EWF1 块索引越界：{chunk_idx}")))?;
        let file = self
            .files
            .get(loc.segment_idx as usize)
            .ok_or_else(|| EngineError::Ewf("EWF1 分段句柄越界".to_string()))?;

        let mut raw = vec![0u8; loc.stored_size as usize];
        file_read_exact_at(file, loc.file_offset, &mut raw)?;

        let expected_len = self.index.expected_chunk_logical_len(chunk_idx);
        let decoded = Arc::new(decode_chunk(
            &raw,
            loc.compressed,
            self.index.chunk_size,
            expected_len,
        )?);

        if let Ok(mut guard) = self.cache[shard_idx].lock() {
            guard.put(chunk_idx, Arc::clone(&decoded));
        }
        Ok(decoded)
    }
}

impl MediaReader for EwfMediaReader {
    fn media_size(&self) -> u64 {
        self.index.logical_size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> EngineResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| EngineError::RandomRead("EWF 读取范围溢出".to_string()))?;
        if end > self.index.logical_size {
            return Err(EngineError::RandomRead(format!(
                "EWF 读取范围 [{offset}, {end}) 超出逻辑大小 {}",
                self.index.logical_size
            )));
        }

        let chunk_size = self.index.chunk_size as u64;
        let mut cursor = offset;
        let mut out_pos = 0usize;

        while out_pos < buf.len() {
            let chunk_idx = (cursor / chunk_size) as usize;
            let in_chunk = (cursor % chunk_size) as usize;
            let chunk = self.get_chunk(chunk_idx)?;
            let avail = chunk.len().saturating_sub(in_chunk);
            if avail == 0 {
                return Err(EngineError::Ewf("EWF1 块数据不足".to_string()));
            }
            let take = avail.min(buf.len() - out_pos);
            buf[out_pos..out_pos + take].copy_from_slice(&chunk[in_chunk..in_chunk + take]);
            cursor += take as u64;
            out_pos += take;
        }
        Ok(())
    }
}

/// Multi-core `rayon` parallel EWF1 logical stream SHA-256 decoder (no fallback).
pub fn hash_logical_ewf1_parallel(
    e01: &Path,
    logical_size: u64,
    cancel: Option<&AtomicBool>,
    progress: Option<&(dyn Fn(u64, u64) + Sync)>,
) -> EngineResult<String> {
    let index = EwfIndex::open(e01)?;
    if index.logical_size != logical_size {
        return Err(EngineError::Ewf(format!(
            "EWF1 逻辑大小与预期不符（索引 {} vs 预期 {}）",
            index.logical_size, logical_size
        )));
    }
    let mut files = Vec::with_capacity(index.segments.len());
    for seg in &index.segments {
        files.push(File::open(seg)?);
    }

    let mut hasher = Sha256::new();
    let mut done: u64 = 0;
    let total_chunks = index.chunks.len();
    let chunk_size = index.chunk_size;

    let mut batch_start = 0usize;
    while batch_start < total_chunks {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消 EWF 逻辑流哈希计算".to_string()));
        }
        let batch_end = (batch_start + PARALLEL_BATCH_CHUNKS).min(total_chunks);
        let mut raw_batch = Vec::with_capacity(batch_end - batch_start);

        // Stage 1: Sequential I/O reading compressed/raw chunk payloads in disk order.
        for chunk_idx in batch_start..batch_end {
            let loc = index.chunks[chunk_idx];
            let mut raw = vec![0u8; loc.stored_size as usize];
            file_read_exact_at(&files[loc.segment_idx as usize], loc.file_offset, &mut raw)?;
            let expected_len = index.expected_chunk_logical_len(chunk_idx);
            raw_batch.push((raw, loc.compressed, expected_len));
        }

        // Stage 2: Multi-core parallel zlib decompression & Adler-32 verification via rayon.
        let decoded_batch: Vec<Vec<u8>> = raw_batch
            .into_par_iter()
            .map(|(raw, compressed, expected_len)| {
                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return Err(EngineError::Cancelled(
                        "已取消 EWF 逻辑流哈希计算".to_string(),
                    ));
                }
                decode_chunk(&raw, compressed, chunk_size, expected_len)
            })
            .collect::<EngineResult<Vec<Vec<u8>>>>()?;

        // Stage 3: Deterministic ordered SHA-256 feeding.
        for block in decoded_batch {
            hasher.update(&block);
            done += block.len() as u64;
        }
        if let Some(cb) = progress {
            cb(done, logical_size);
        }
        batch_start = batch_end;
    }

    if done != logical_size {
        return Err(EngineError::Ewf(format!(
            "EWF1 解码字节数不匹配：{done}/{logical_size}"
        )));
    }
    Ok(hex_lower(&hasher.finalize()))
}

/// Compute logical SHA-256 of an EWF image using multi-core pure Rust EWF1 parallel decompression,
/// automatically falling back to `TskCli::img_cat` for EWF2, encrypted, or non-standard images.
pub fn hash_logical_stream(
    tsk: &TskCli,
    e01: &Path,
    logical_size: u64,
    cancel: Option<&AtomicBool>,
    progress: Option<&(dyn Fn(u64, u64) + Sync)>,
) -> EngineResult<String> {
    match hash_logical_ewf1_parallel(e01, logical_size, cancel, progress) {
        Ok(digest) => Ok(digest),
        Err(err) if err.is_cancelled() => Err(err),
        Err(_) => {
            let mut hasher = Sha256::new();
            let mut done: u64 = 0;
            tsk.img_cat_ewf_stream(e01, logical_size, cancel, |block| {
                hasher.update(block);
                done += block.len() as u64;
                if let Some(cb) = progress {
                    cb(done, logical_size);
                }
                Ok(())
            })?;
            Ok(hex_lower(&hasher.finalize()))
        }
    }
}
