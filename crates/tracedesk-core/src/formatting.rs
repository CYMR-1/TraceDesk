//! UTC+8 time formatting, Windows filename sanitization, canonical JSON serialization,
//! and forensic display helpers (`core-contract.md` §1.1, §3.1, §3.4).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use tracedesk_engines::{can_export, deleted_source_note, entry_name, entry_status};

use crate::case::ExportRecord;
use crate::error::{CoreError, CoreResult};

/// Fixed UTC+08:00 timezone offset in seconds.
pub const EAST_8_OFFSET_SECS: i32 = 8 * 3600;

static INVALID_WIN_CHARS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[<>:"/\\|?*\x00-\x1f]"#).expect("valid win char regex"));
static RESERVED_WIN_DEVICE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])$")
        .expect("valid win device regex")
});

/// Returns the fixed UTC+08:00 offset (`+08:00`).
#[inline]
pub fn east_8() -> FixedOffset {
    FixedOffset::east_opt(EAST_8_OFFSET_SECS).expect("valid UTC+8 offset")
}

/// Current wall-clock timestamp formatted in UTC+08:00 ISO-8601 (matching Python `datetime.now(EAST_8).isoformat()`).
pub fn now() -> String {
    let dt = Utc::now().with_timezone(&east_8());
    format_datetime_iso(&dt)
}

fn format_datetime_iso(dt: &DateTime<FixedOffset>) -> String {
    if dt.timestamp_subsec_micros() == 0 {
        dt.to_rfc3339_opts(SecondsFormat::Secs, false)
    } else {
        dt.to_rfc3339_opts(SecondsFormat::Micros, false)
    }
}

/// Timestamp input accepted by [`display_time`].
#[derive(Debug, Clone, Copy)]
pub enum TimeValue<'a> {
    Unix(i64),
    Iso(&'a str),
}

/// Convert a Unix timestamp (seconds) to UTC+8 display text.
/// Returns `"未记录"` when `unix_secs <= 0`.
pub fn display_timestamp(unix_secs: i64, compact: bool) -> String {
    if unix_secs <= 0 {
        return "未记录".to_string();
    }
    let Some(utc) = DateTime::from_timestamp(unix_secs, 0) else {
        return "未记录".to_string();
    };
    let dt = utc.with_timezone(&east_8());
    if compact {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    } else {
        dt.to_rfc3339_opts(SecondsFormat::Secs, false)
    }
}

/// Parse an ISO-8601 string (interpreting naive timestamps as UTC) and format in UTC+8.
pub fn display_iso_time(value: &str, compact: bool) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let parsed = parse_iso_to_east8(trimmed);
    match parsed {
        Some(dt) => {
            if compact {
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                format_datetime_iso(&dt)
            }
        }
        None => trimmed.to_string(),
    }
}

/// Parse ISO-8601 datetime strings (with timezone offset, `Z`, space separator, or naive UTC) into UTC+8.
pub fn parse_iso_to_east8(raw: &str) -> Option<DateTime<FixedOffset>> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&east_8()));
    }
    // Support space separator with offset (`2026-11-21 17:45:00+08:00` or `.123456+08:00`).
    let normalized = if s.len() >= 11 && s.as_bytes()[10] == b' ' {
        let mut owned = s.to_string();
        owned.replace_range(10..11, "T");
        owned
    } else {
        s.to_string()
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
        return Some(dt.with_timezone(&east_8()));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.f%:z",
        "%Y-%m-%dT%H:%M:%S%:z",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ] {
        if let Ok(dt) = DateTime::parse_from_str(&normalized, fmt) {
            return Some(dt.with_timezone(&east_8()));
        }
    }
    // Naive ISO strings without timezone are interpreted as UTC, then converted to UTC+8.
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(&normalized, fmt) {
            return Some(Utc.from_utc_datetime(&naive).with_timezone(&east_8()));
        }
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(&normalized, "%Y-%m-%d")
        && let Some(naive) = date.and_hms_opt(0, 0, 0)
    {
        return Some(Utc.from_utc_datetime(&naive).with_timezone(&east_8()));
    }
    None
}

/// Unified UTC+8 time formatter accepting either Unix timestamp seconds or ISO-8601 strings.
pub fn display_time(value: TimeValue<'_>, compact: bool) -> String {
    match value {
        TimeValue::Unix(secs) => display_timestamp(secs, compact),
        TimeValue::Iso(s) => display_iso_time(s, compact),
    }
}

/// Zero-allocation UTC+8 ISO-8601 formatter (`YYYY-MM-DDTHH:MM:SS+08:00`, exact 25 ASCII bytes)
/// for hot loops such as parallel MACB timeline filtering.
///
/// Uses Howard Hinnant's civil-from-days algorithm and returns `None` for out-of-range years
/// outside `0000..=9999`.
#[inline]
pub fn format_unix_east8_stack(unix_secs: i64) -> Option<[u8; 25]> {
    if unix_secs <= 0 {
        return None;
    }
    let local = unix_secs.checked_add(EAST_8_OFFSET_SECS as i64)?;
    let days = local.div_euclid(86_400);
    let secs_of_day = local.rem_euclid(86_400) as u32;

    // Howard Hinnant civil_from_days (days since 1970-01-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = y + i64::from(m <= 2);

    if !(0..=9999).contains(&year) {
        return None;
    }
    let y_u32 = year as u32;
    let hour = secs_of_day / 3600;
    let min = (secs_of_day % 3600) / 60;
    let sec = secs_of_day % 60;

    let mut out = *b"0000-00-00T00:00:00+08:00";
    out[0] = b'0' + (y_u32 / 1000) as u8;
    out[1] = b'0' + ((y_u32 / 100) % 10) as u8;
    out[2] = b'0' + ((y_u32 / 10) % 10) as u8;
    out[3] = b'0' + (y_u32 % 10) as u8;
    out[5] = b'0' + (m / 10) as u8;
    out[6] = b'0' + (m % 10) as u8;
    out[8] = b'0' + (d / 10) as u8;
    out[9] = b'0' + (d % 10) as u8;
    out[11] = b'0' + (hour / 10) as u8;
    out[12] = b'0' + (hour % 10) as u8;
    out[14] = b'0' + (min / 10) as u8;
    out[15] = b'0' + (min % 10) as u8;
    out[17] = b'0' + (sec / 10) as u8;
    out[18] = b'0' + (sec % 10) as u8;
    Some(out)
}

/// Truncate a UTF-8 string to at most `max_units` UTF-16 code units without splitting surrogate pairs.
pub fn truncate_utf16_units(s: &str, max_units: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_units * 3));
    let mut units = 0usize;
    for ch in s.chars() {
        let len = ch.len_utf16();
        if units + len > max_units {
            break;
        }
        out.push(ch);
        units += len;
    }
    out
}

/// Count the UTF-16 code unit length of `s`.
#[inline]
pub fn utf16_unit_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// Sanitize a single filename component for Windows NTFS/FAT (`core-contract.md` §3.1).
pub fn windows_filename(name: &str, max_units: usize) -> String {
    let mut cleaned = INVALID_WIN_CHARS_RE.replace_all(name, "_").into_owned();
    let stem = cleaned.split('.').next().unwrap_or(&cleaned);
    let device = stem.trim_end_matches(' ').to_uppercase();
    if RESERVED_WIN_DEVICE_RE.is_match(&device) {
        cleaned.insert(0, '_');
    }
    let truncated = truncate_utf16_units(&cleaned, max_units);
    let trimmed = truncated.trim_end_matches([' ', '.']);
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Derive a safe Windows export filename from an in-image slash-separated path.
pub fn export_filename(source_path: &str) -> String {
    let leaf = source_path.rsplit('/').next().unwrap_or(source_path);
    windows_filename(leaf, 255)
}

/// Derive the default case directory name from `(number, examiner, target)` (`core-contract.md` §3.1).
pub fn case_folder_name(number: &str, examiner: &str, target: &str) -> String {
    let parts = [number.trim(), examiner.trim(), target.trim()];
    let mut joined = parts.join("-");
    if utf16_unit_len(&joined) > 255 {
        joined = parts
            .iter()
            .map(|p| truncate_utf16_units(p, 84))
            .collect::<Vec<_>>()
            .join("-");
    }
    windows_filename(&joined, 255)
}

/// Suggest a non-colliding case folder path under `root`, appending ` (2)`, ` (3)`, ... if needed.
pub fn next_case_folder_path(root: &Path, base_name: &str) -> PathBuf {
    for index in 1usize.. {
        let suffix = if index == 1 {
            String::new()
        } else {
            format!(" ({index})")
        };
        let max_base = 255usize.saturating_sub(utf16_unit_len(&suffix));
        let candidate_name = format!("{}{}", windows_filename(base_name, max_base), suffix);
        let candidate = root.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("infinite loop")
}

/// Atomically create a non-colliding case folder under `root`, appending ` (2)`, ` (3)`, ... on conflict.
pub fn create_unique_case_folder(root: &Path, base_name: &str) -> CoreResult<PathBuf> {
    fs::create_dir_all(root)?;
    for index in 1usize.. {
        let suffix = if index == 1 {
            String::new()
        } else {
            format!(" ({index})")
        };
        let max_base = 255usize.saturating_sub(utf16_unit_len(&suffix));
        let candidate_name = format!("{}{}", windows_filename(base_name, max_base), suffix);
        let candidate = root.join(candidate_name);
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(CoreError::Io(e)),
        }
    }
    unreachable!("infinite loop")
}

/// Build the human-readable Chinese deleted-file export summary (`forensic/core/formatting.py`).
pub fn deleted_export_summary(record: &ExportRecord) -> String {
    if record.deleted != Some(true) {
        return String::new();
    }
    let recorded_size = record.recorded_size.unwrap_or(record.size);
    let result = if record.size < recorded_size {
        "部分导出"
    } else {
        "已导出"
    };
    let size_text = format!("{result} {} / {recorded_size} 字节", record.size);
    let source_note = if record.reallocated == Some(true) {
        "已删除 · inode 已重分配，数据来自该 inode 当前内容"
    } else if record.start_cluster_allocated == Some(true) {
        "已删除 · 起始簇已被占用，原内容可能已覆盖"
    } else {
        "已删除，原内容可能已覆盖"
    };
    let inode_text = format!("inode {}", record.inode);
    let mut parts: Vec<&str> = Vec::with_capacity(4);
    parts.push(source_note);
    parts.push(&inode_text);
    parts.push(&size_text);
    if let Some(note) = record.read_note.as_deref()
        && !note.is_empty()
    {
        parts.push(note);
    }
    parts.join(" · ")
}

/// Canonical JSON serialization byte-for-byte identical to Python:
/// `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))`.
///
/// Converts any [`Serialize`] value into [`serde_json::Value`] first so all nested object maps
/// use `BTreeMap` key ordering (requires `serde_json` WITHOUT `preserve_order`).
pub fn canonical_json<T: Serialize>(value: &T) -> CoreResult<String> {
    let val = serde_json::to_value(value)?;
    canonical_json_value(&val)
}

/// Canonical JSON serialization for an already-constructed [`serde_json::Value`].
pub fn canonical_json_value(value: &Value) -> CoreResult<String> {
    Ok(serde_json::to_string(value)?)
}

/// Lowercase hexadecimal encoding of raw bytes.
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Compute lowercase 64-character SHA-256 hex digest of an in-memory byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

/// Format an unsigned integer with comma thousand separators (e.g. `9437184` -> `"9,437,184"`).
pub fn format_commas(n: u64) -> String {
    let raw = n.to_string();
    let bytes = raw.as_bytes();
    let len = bytes.len();
    if len <= 3 {
        return raw;
    }
    let mut out = String::with_capacity(len + (len - 1) / 3);
    for (idx, &b) in bytes.iter().enumerate() {
        if idx > 0 && (len - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

/// Format a byte count with binary unit suffix matching `forensic/core/reporting.py::_format_size`.
pub fn format_size(size: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1u64 << 40),
        ("GiB", 1u64 << 30),
        ("MiB", 1u64 << 20),
        ("KiB", 1u64 << 10),
    ];
    for (unit, scale) in UNITS {
        if size >= scale {
            return format!(
                "{} 字节（{:.2} {unit}）",
                format_commas(size),
                size as f64 / scale as f64
            );
        }
    }
    format!("{} 字节", format_commas(size))
}
