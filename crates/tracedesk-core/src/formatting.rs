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
    let mut out = String::with_capacity(s.len().min(max_units.saturating_mul(3)));
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

/// 判断文件名是否命中 Windows 保留设备名（取首个 `.` 之前并去除末尾空格后忽略大小写比对）。
fn is_reserved_windows_name(candidate: &str) -> bool {
    let stem = candidate.split('.').next().unwrap_or(candidate);
    let device = stem.trim_end_matches(' ').to_uppercase();
    RESERVED_WIN_DEVICE_RE.is_match(&device)
}

/// 按 Windows NTFS/FAT 规则净化单个文件名组件（对应 `core-contract.md` §3.1）。
pub fn windows_filename(name: &str, max_units: usize) -> String {
    let mut cleaned = INVALID_WIN_CHARS_RE.replace_all(name, "_").into_owned();
    if is_reserved_windows_name(&cleaned) {
        cleaned.insert(0, '_');
    }
    let truncated = truncate_utf16_units(&cleaned, max_units);
    let mut trimmed = truncated.trim_end_matches([' ', '.']).to_string();
    // 截断后可能再次落入 Windows 保留设备名（例如 "CONSOLE" 截断为 3 单元变成 "CON"），需二次校验。
    if !trimmed.is_empty() && is_reserved_windows_name(&trimmed) {
        trimmed.insert(0, '_');
        trimmed = truncate_utf16_units(&trimmed, max_units)
            .trim_end_matches([' ', '.'])
            .to_string();
    }
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed
    }
}

/// 从镜像内斜杠分隔的路径派生安全的 Windows 导出文件名。
pub fn export_filename(source_path: &str) -> String {
    let leaf = source_path.rsplit('/').next().unwrap_or(source_path);
    windows_filename(leaf, 255)
}

/// 为导出文件生成带序号后缀的合法 Windows 文件名（对应 `core-contract.md` §3.1）。
///
/// - `index == 0`：返回净化后的原始文件名（不追加序号）；
/// - `index >= 1`：在文件主名后、扩展名前插入 `({index})`
///   （例如 `NOTES.TXT` -> `NOTES(1).TXT`、`archive.tar.gz` -> `archive.tar(1).gz`、
///   无扩展名 `README` -> `README(1)`、隐藏文件 `.gitignore` -> `.gitignore(1)`）；
/// - 严格遵守 255 UTF-16 代码单元上限与 Windows 合法文件名约束：超长时优先保留扩展名与
///   序号后缀，截断主名并确保截断后不以空格/点结尾且不命中 Windows 保留设备名。
pub fn numbered_export_filename(base_name: &str, index: usize) -> String {
    numbered_export_filename_with_limit(base_name, index, 255)
}

fn numbered_export_filename_with_limit(
    base_name: &str,
    index: usize,
    max_units: usize,
) -> String {
    let mut cleaned = INVALID_WIN_CHARS_RE.replace_all(base_name, "_").into_owned();
    // 若原始名称命中 Windows 保留设备名，先加 "_" 前缀，确保 index=0 与 index>=1 命名前缀一致。
    if is_reserved_windows_name(&cleaned) {
        cleaned.insert(0, '_');
    }
    let cleaned = cleaned.trim_end_matches([' ', '.']);
    let cleaned = if cleaned.is_empty() { "file" } else { cleaned };

    // 按最后一个 `.` 拆分主名与扩展名；隐藏文件（仅首字符为 `.`，如 `.gitignore`）整体视为主名。
    let (raw_stem, raw_ext) = match cleaned.rfind('.') {
        Some(dot) if dot > 0 && dot + 1 < cleaned.len() => (&cleaned[..dot], &cleaned[dot..]),
        _ => (cleaned, ""),
    };

    let suffix = if index == 0 {
        String::new()
    } else {
        format!("({index})")
    };
    let suffix_units = utf16_unit_len(&suffix);
    let raw_ext_units = utf16_unit_len(raw_ext);

    // 优先保留扩展名与序号后缀；仅在极端超长扩展名导致 `suffix + ext` 超出上限时截断扩展名。
    let ext = if suffix_units + raw_ext_units <= max_units {
        raw_ext.to_string()
    } else {
        let ext_budget = max_units.saturating_sub(suffix_units);
        let mut truncated_ext = truncate_utf16_units(raw_ext, ext_budget);
        while truncated_ext.ends_with([' ', '.']) {
            truncated_ext.pop();
        }
        truncated_ext
    };
    let ext_units = utf16_unit_len(&ext);
    let stem_budget = max_units.saturating_sub(suffix_units + ext_units);

    let raw_stem_units = utf16_unit_len(raw_stem);
    let mut stem = if raw_stem_units <= stem_budget {
        raw_stem.to_string()
    } else {
        truncate_utf16_units(raw_stem, stem_budget)
            .trim_end_matches([' ', '.'])
            .to_string()
    };

    // 当扩展名被超长截断为空且无序号后缀时，主名即为最终文件名末尾，必须剥离尾部空格与点。
    if suffix.is_empty() && ext.is_empty() {
        stem = stem.trim_end_matches([' ', '.']).to_string();
    }

    if stem.is_empty() && stem_budget >= 4 {
        stem = "file".to_string();
    } else if stem.is_empty() && suffix.is_empty() && ext.is_empty() {
        stem = truncate_utf16_units("file", max_units);
    }

    // 截断主名后可能再次命中 Windows 保留设备名（例如 "CONSOLE" 截断为 3 单元变成 "CON"），
    // 对主名及拼装后的完整文件名执行二次校验并在必要时补 "_" 前缀重截断。
    let candidate = format!("{stem}{suffix}{ext}");
    if (!stem.is_empty() && is_reserved_windows_name(&stem)) || is_reserved_windows_name(&candidate)
    {
        stem.insert(0, '_');
        if utf16_unit_len(&stem) > stem_budget {
            stem = truncate_utf16_units(&stem, stem_budget)
                .trim_end_matches([' ', '.'])
                .to_string();
        }
        format!("{stem}{suffix}{ext}")
    } else {
        candidate
    }
}

/// 根据 `(number, examiner, target)` 派生默认案件目录名（以 `_` 分隔编号、人员与对象）。
pub fn case_folder_name(number: &str, examiner: &str, target: &str) -> String {
    let parts = [number.trim(), examiner.trim(), target.trim()];
    let mut joined = parts.join("_");
    if utf16_unit_len(&joined) > 255 {
        joined = parts
            .iter()
            .map(|p| truncate_utf16_units(p, 84))
            .collect::<Vec<_>>()
            .join("_");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_export_filename_basic_and_edge_cases() {
        // 常规文件：index == 0 返回原名，index >= 1 在主名后、扩展名前插入序号。
        assert_eq!(numbered_export_filename("NOTES.TXT", 0), "NOTES.TXT");
        assert_eq!(numbered_export_filename("NOTES.TXT", 1), "NOTES(1).TXT");
        assert_eq!(numbered_export_filename("NOTES.TXT", 2), "NOTES(2).TXT");
        assert_eq!(numbered_export_filename("NOTES.TXT", 12), "NOTES(12).TXT");

        // 无扩展名文件。
        assert_eq!(numbered_export_filename("README", 0), "README");
        assert_eq!(numbered_export_filename("README", 1), "README(1)");
        assert_eq!(numbered_export_filename("README", 2), "README(2)");

        // 隐藏文件（仅首字符为 `.` 视作无扩展名；含后续 `.` 则按最后一个 `.` 拆分）。
        assert_eq!(numbered_export_filename(".gitignore", 0), ".gitignore");
        assert_eq!(numbered_export_filename(".gitignore", 1), ".gitignore(1)");
        assert_eq!(numbered_export_filename(".env.local", 0), ".env.local");
        assert_eq!(numbered_export_filename(".env.local", 1), ".env(1).local");

        // 多点扩展名：按最后一个 `.` 拆分。
        assert_eq!(
            numbered_export_filename("archive.tar.gz", 0),
            "archive.tar.gz"
        );
        assert_eq!(
            numbered_export_filename("archive.tar.gz", 1),
            "archive.tar(1).gz"
        );
        assert_eq!(
            numbered_export_filename("report.v1.final.pdf", 3),
            "report.v1.final(3).pdf"
        );

        // Windows 保留设备名：index == 0 与 index >= 1 保持一致前缀净化。
        assert_eq!(numbered_export_filename("CON.txt", 0), "_CON.txt");
        assert_eq!(numbered_export_filename("CON.txt", 1), "_CON(1).txt");
        assert_eq!(numbered_export_filename("nul", 1), "_nul(1)");

        // 超长文件名（恰好 255 UTF-16 码元）：优先保留扩展名与序号后缀并截断主名。
        let max_base = format!("{}.txt", "a".repeat(251));
        assert_eq!(utf16_unit_len(&max_base), 255);
        assert_eq!(numbered_export_filename(&max_base, 0), max_base);
        let n1 = numbered_export_filename(&max_base, 1);
        assert_eq!(utf16_unit_len(&n1), 255);
        assert!(n1.ends_with("(1).txt"));
        assert_eq!(n1, format!("{}(1).txt", "a".repeat(248)));

        // 超长截断后主名末尾出现空格或点：必须去除尾部空格/点再拼接序号与扩展名。
        let trailing_space_dot = format!("{} .  xyz.txt", "a".repeat(245));
        assert_eq!(utf16_unit_len(&trailing_space_dot), 256);
        let n_trim = numbered_export_filename(&trailing_space_dot, 1);
        assert!(utf16_unit_len(&n_trim) <= 255);
        assert_eq!(n_trim, format!("{}(1).txt", "a".repeat(245)));

        // 代理对（emoji 占 2 个 UTF-16 单元）截断时绝不能被拆分。
        let emoji_long = format!("{}😀.txt", "a".repeat(247)); // 247 + 2 + 4 = 253
        let emoji_n1 = numbered_export_filename(&emoji_long, 1); // stem_budget = 248 -> 只能放下 247 个 'a'
        assert!(utf16_unit_len(&emoji_n1) <= 255);
        assert_eq!(emoji_n1, format!("{}(1).txt", "a".repeat(247)));

        // 截断主名后落入 Windows 保留设备名（例如 "CONSOLE" 截断为 3 单元变成 "CON"）必须二次净化。
        let trunc_reserved = numbered_export_filename_with_limit("CONSOLE.txt", 1, 10);
        // max=10, suffix="(1)"(3), ext=".txt"(4) => stem_budget=3 => "CON" -> 二次净化为 "_CO"
        assert!(utf16_unit_len(&trunc_reserved) <= 10);
        assert_eq!(trunc_reserved, "_CO(1).txt");
        assert!(!is_reserved_windows_name(&trunc_reserved));

        // 极端超长扩展名场景仍严格满足 255 UTF-16 码元上限且不以点或空格结尾。
        let huge_ext = format!("a.{}", "x".repeat(253));
        assert_eq!(utf16_unit_len(&huge_ext), 255);
        let huge_n1 = numbered_export_filename(&huge_ext, 1);
        assert!(utf16_unit_len(&huge_n1) <= 255);
        assert!(huge_n1.starts_with("(1)."));
        assert!(!huge_n1.ends_with([' ', '.']));

        // 超长扩展名截断并剥离尾部空格/点后变为空时，index == 0 不得以空格/点结尾，且全空白主名回退为 "file"。
        let space_ext_with_trailing_space = format!("foo .{}x", " ".repeat(254));
        let fixed_foo = numbered_export_filename(&space_ext_with_trailing_space, 0);
        assert_eq!(fixed_foo, "foo");
        assert!(!fixed_foo.ends_with([' ', '.']));

        let space_ext_with_trailing_dot = format!("a..{}x", " ".repeat(254));
        let fixed_a = numbered_export_filename(&space_ext_with_trailing_dot, 0);
        assert_eq!(fixed_a, "a");
        assert!(!fixed_a.ends_with([' ', '.']));

        let space_ext_blank_stem = format!("   .{}x", " ".repeat(254));
        let fixed_blank = numbered_export_filename(&space_ext_blank_stem, 0);
        assert_eq!(fixed_blank, "file");
        assert!(!fixed_blank.ends_with([' ', '.']));
    }
}
