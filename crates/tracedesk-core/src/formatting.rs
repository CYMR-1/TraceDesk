//! UTC+8 时间格式化、Windows 文件名净化、规范化 JSON 序列化
//! 与取证展示辅助函数（对应 `core-contract.md` §1.1、§3.1、§3.4）。

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

/// 固定 UTC+08:00 时区偏移（秒）。
pub const EAST_8_OFFSET_SECS: i32 = 8 * 3600;

static INVALID_WIN_CHARS_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"[<>:"/\\|?*\x00-\x1f]"#).expect("valid win char regex"));
static RESERVED_WIN_DEVICE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³])$")
        .expect("valid win device regex")
});

/// 返回固定的 UTC+08:00 时区偏移（`+08:00`）。
#[inline]
pub fn east_8() -> FixedOffset {
    FixedOffset::east_opt(EAST_8_OFFSET_SECS).expect("valid UTC+8 offset")
}

/// 当前挂钟时间的 UTC+08:00 ISO-8601 格式字符串（与 Python `datetime.now(EAST_8).isoformat()` 一致）。
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

/// [`display_time`] 接受的时间戳输入类型。
#[derive(Debug, Clone, Copy)]
pub enum TimeValue<'a> {
    Unix(i64),
    Iso(&'a str),
}

/// 将 Unix 时间戳（秒）转换为 UTC+8 展示文本。
/// 当 `unix_secs <= 0` 时返回 `"未记录"`。
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

/// 解析 ISO-8601 字符串（无时区的时间戳按 UTC 解释）并格式化为 UTC+8。
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

/// 将 ISO-8601 日期时间字符串（支持时区偏移、`Z`、空格分隔符或无时区 UTC）解析并转换为 UTC+8。
pub fn parse_iso_to_east8(raw: &str) -> Option<DateTime<FixedOffset>> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&east_8()));
    }
    // 支持带时区偏移的空格分隔格式（如 `2026-11-21 17:45:00+08:00` 或 `.123456+08:00`）。
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
    // 不带时区的 ISO 字符串按 UTC 解释，再转换为 UTC+8。
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

/// 统一的 UTC+8 时间格式化函数，同时支持 Unix 秒级时间戳与 ISO-8601 字符串。
pub fn display_time(value: TimeValue<'_>, compact: bool) -> String {
    match value {
        TimeValue::Unix(secs) => display_timestamp(secs, compact),
        TimeValue::Iso(s) => display_iso_time(s, compact),
    }
}

/// 零分配 UTC+8 ISO-8601 格式化函数（`YYYY-MM-DDTHH:MM:SS+08:00`，固定 25 字节 ASCII），
/// 用于并行 MACB 时间线过滤等高频热循环。
///
/// 采用 Howard Hinnant 的 civil-from-days 算法；年份超出 `0000..=9999` 范围时返回 `None`。
#[inline]
pub fn format_unix_east8_stack(unix_secs: i64) -> Option<[u8; 25]> {
    if unix_secs <= 0 {
        return None;
    }
    let local = unix_secs.checked_add(EAST_8_OFFSET_SECS as i64)?;
    let days = local.div_euclid(86_400);
    let secs_of_day = local.rem_euclid(86_400) as u32;

    // Howard Hinnant civil_from_days 算法（自 1970-01-01 起的天数）。
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

/// 将 UTF-8 字符串截断至不超过 `max_units` 个 UTF-16 代码单元，且不拆分代理对。
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

/// 计算 `s` 的 UTF-16 代码单元长度。
#[inline]
pub fn utf16_unit_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// 按 Windows NTFS/FAT 规则净化单个文件名组件（对应 `core-contract.md` §3.1）。
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

/// 从镜像内斜杠分隔的路径派生安全的 Windows 导出文件名。
pub fn export_filename(source_path: &str) -> String {
    let leaf = source_path.rsplit('/').next().unwrap_or(source_path);
    windows_filename(leaf, 255)
}

/// 根据 `(number, examiner, target)` 派生默认案件目录名（对应 `core-contract.md` §3.1）。
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

/// 在 `root` 下生成不冲突的案件目录路径，必要时依次追加 ` (2)`、` (3)` 等后缀。
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

/// 在 `root` 下原子创建不冲突的案件目录，遇到重名冲突时自动追加 ` (2)`、` (3)` 等后缀。
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

/// 构建已删除文件导出记录的可读中文摘要（对应 `forensic/core/formatting.py`）。
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

/// 与 Python 逐字节一致的规范化 JSON 序列化：
/// `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))`。
///
/// 先将任意 [`Serialize`] 值转为 [`serde_json::Value`]，以确保所有嵌套对象映射
/// 均采用 `BTreeMap` 键序（要求 `serde_json` 未启用 `preserve_order`）。
pub fn canonical_json<T: Serialize>(value: &T) -> CoreResult<String> {
    let val = serde_json::to_value(value)?;
    canonical_json_value(&val)
}

/// 对已构造的 [`serde_json::Value`] 执行规范化 JSON 序列化。
pub fn canonical_json_value(value: &Value) -> CoreResult<String> {
    Ok(serde_json::to_string(value)?)
}

/// 将原始字节编码为小写十六进制字符串。
pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 计算内存字节切片的小写 64 位十六进制 SHA-256 摘要。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

/// 将无符号整数格式化为带千位逗号分隔的字符串（如 `9437184` -> `"9,437,184"`）。
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

/// 按二进制单位后缀格式化字节数，与 `forensic/core/reporting.py::_format_size` 保持一致。
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
