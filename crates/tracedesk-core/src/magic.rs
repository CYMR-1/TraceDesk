//! 只读文件头魔数（Magic Bytes）识别与扩展名伪装检测引擎。
//!
//! 严格遵守取证只读与安全边界：
//! - 单文件最多只读读取前 4096 字节（优先进程内 [`VolumeReader`] 直读，失败安全回退有界 `icat`）；
//! - 绝不修改源证据镜像，绝不创建解压缩输出，绝不对 ZIP/OOXML/GZIP/RAR 等归档执行解压缩（防 Zip Bomb）；
//! - OOXML（DOCX/XLSX/PPTX）仅在前 4 KiB 原始字节中执行只读子串扫描以识别内部目录结构。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use memchr::memmem;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracedesk_engines::{
    EngineError, InventoryEntry, MediaReader, TskCli, VolumeReader, can_export, open_media,
};

use crate::case::Case;
use crate::error::{CoreError, CoreResult};

/// 单个文件魔数识别最多读取的头部字节数（4 KiB）。
pub const MAGIC_HEADER_BYTES: usize = 4096;
/// 展示给界面的文件头十六进制预览字节数上限（16 字节）。
pub const MAGIC_HEX_PREVIEW_BYTES: usize = 16;
/// 有界 `icat` 回退并发上限（控制子进程数量）。
const MAGIC_ICAT_THREADS: usize = 4;

/// 识别出的真实文件头魔数类型元数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MagicTypeInfo {
    /// 细粒度类型标识（如 `"PE"`、`"ELF"`、`"PNG"`、`"DOCX"`、`"SQLITE"` 等）。
    pub type_id: String,
    /// 所属类型族（如 `"EXECUTABLE"`、`"DOCUMENT"`、`"DATABASE"`、`"ARCHIVE"`、`"IMAGE"`、`"AUDIO"`、`"VIDEO"`、`"SHORTCUT"`）。
    pub family: String,
    /// 中文类型名称（如 `"PNG 图像"`、`"Windows 可执行文件 (PE)"`）。
    pub label: String,
    /// 该真实文件头常规对应的合法扩展名列表（小写，含前导点号）。
    pub canonical_extensions: Vec<String>,
    /// 是否属于高危可执行/快捷方式类型（用于严重级别评估）。
    pub high_risk: bool,
}

/// 单个文件的魔数与扩展名比对结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MagicCheckItem {
    /// 检测到的真实魔数类型标识；若未命中已知二进制魔数则为 `None`。
    pub detected_type: Option<String>,
    /// 检测到的真实类型族；若未命中已知二进制魔数则为 `None`。
    pub detected_family: Option<String>,
    /// 检测到的真实类型中文名称；若未命中已知二进制魔数则为 `None`。
    pub detected_label: Option<String>,
    /// 文件路径声明的归一化小写扩展名（含前导点号，如 `".txt"`；无扩展名时为空串 `""`）。
    pub extension: String,
    /// 是否判定为扩展名伪装。
    pub mismatch: bool,
    /// 风险等级：`"high"`（高危可执行/快捷方式伪装）、`"medium"`（跨类型伪装）或 `"none"`（无伪装）。
    pub severity: String,
    /// 面向取证员的中文判定说明。
    pub reason: String,
    /// 前 16 字节的空格分隔大写十六进制字符串。
    pub magic_hex: String,
}

/// 全案魔数扫描中的单类文件数量统计项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MagicTypeCount {
    /// 检测到的真实魔数类型标识。
    pub detected_type: String,
    /// 检测到的真实类型族。
    pub detected_family: String,
    /// 中文类型名称。
    pub label: String,
    /// 检出文件数量。
    pub count: usize,
}

/// 全案魔数扫描中检出的单条扩展名伪装记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MagicMismatchEntry {
    /// 与桌面端 `resolve_entry` 兼容的条目定位键（格式：`"{offset}:{inode}:{0|1}:{path}"`）。
    pub entry_key: String,
    /// 所在分区起始扇区偏移。
    pub offset: u64,
    /// 文件系统 inode / MFT 编号。
    pub inode: String,
    /// 镜像内文件路径。
    pub path: String,
    /// 是否为已删除条目。
    pub deleted: bool,
    /// 目录记录文件大小（字节）。
    pub size: u64,
    /// 声明的归一化小写扩展名（含前导点号）。
    pub extension: String,
    /// 检测到的真实魔数类型标识。
    pub detected_type: String,
    /// 检测到的真实类型族。
    pub detected_family: String,
    /// 检测到的真实类型中文名称。
    pub detected_label: String,
    /// 风险等级：`"high"` 或 `"medium"`。
    pub severity: String,
    /// 中文伪装判定说明。
    pub reason: String,
    /// 前 16 字节大写十六进制展示。
    pub magic_hex: String,
}

/// 全案魔数与扩展名伪装扫描汇总报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MagicScanReport {
    /// 实际完成头部读取并参与魔数检测的文件数。
    pub scanned_count: usize,
    /// 跳过的条目数（目录、虚拟/系统区域、0 字节空文件或损坏不可读的已删除条目）。
    pub skipped_count: usize,
    /// 检出的扩展名伪装条目总数。
    pub mismatch_count: usize,
    /// 本次扫描耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 本次扫描是否因收到取消信号而提前终止。
    pub cancelled: bool,
    /// 按真实魔数类型聚合的文件数量统计（按数量降序排列）。
    pub type_counts: Vec<MagicTypeCount>,
    /// 检出的所有扩展名伪装条目列表（高危优先，其次按分区与路径确定性排序）。
    pub mismatches: Vec<MagicMismatchEntry>,
}

/// 静态魔数类型规格定义。
#[derive(Debug)]
struct MagicSpec {
    type_id: &'static str,
    family: &'static str,
    label: &'static str,
    canonical_extensions: &'static [&'static str],
    compatible_extensions: &'static [&'static str],
    high_risk: bool,
}

const SPEC_PE: MagicSpec = MagicSpec {
    type_id: "PE",
    family: "EXECUTABLE",
    label: "Windows 可执行文件 (PE)",
    canonical_extensions: &[".exe", ".dll", ".sys"],
    compatible_extensions: &[
        ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".efi", ".mui", ".pyd", ".ax",
        ".acm", ".com", ".tsp", ".ime",
    ],
    high_risk: true,
};

const SPEC_ELF: MagicSpec = MagicSpec {
    type_id: "ELF",
    family: "EXECUTABLE",
    label: "Linux/Unix 可执行文件 (ELF)",
    canonical_extensions: &[".elf", ".so"],
    compatible_extensions: &[".elf", ".so", ".o", ".out", ".ko", ".axf", ".prx"],
    high_risk: true,
};

const SPEC_MACHO: MagicSpec = MagicSpec {
    type_id: "MACHO",
    family: "EXECUTABLE",
    label: "macOS 可执行文件 (Mach-O)",
    canonical_extensions: &[".macho", ".dylib"],
    compatible_extensions: &[".macho", ".dylib", ".bundle", ".o", ".app"],
    high_risk: true,
};

const SPEC_LNK: MagicSpec = MagicSpec {
    type_id: "LNK",
    family: "SHORTCUT",
    label: "Windows 快捷方式 (LNK)",
    canonical_extensions: &[".lnk"],
    compatible_extensions: &[".lnk"],
    high_risk: true,
};

const SPEC_PDF: MagicSpec = MagicSpec {
    type_id: "PDF",
    family: "DOCUMENT",
    label: "PDF 文档",
    canonical_extensions: &[".pdf"],
    compatible_extensions: &[".pdf"],
    high_risk: false,
};

const SPEC_SQLITE: MagicSpec = MagicSpec {
    type_id: "SQLITE",
    family: "DATABASE",
    label: "SQLite 3 数据库",
    canonical_extensions: &[".sqlite", ".sqlite3", ".db"],
    compatible_extensions: &[
        ".sqlite",
        ".sqlite3",
        ".db",
        ".db3",
        ".s3db",
        ".sl3",
        ".sqlitedb",
    ],
    high_risk: false,
};

const SPEC_OLE2: MagicSpec = MagicSpec {
    type_id: "OLE2",
    family: "DOCUMENT",
    label: "MS Office 复合文档 (OLE2)",
    canonical_extensions: &[".doc", ".xls", ".ppt"],
    compatible_extensions: &[
        ".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot", ".msg", ".msi", ".msp", ".mst", ".wps",
        ".et", ".dps", ".vsd", ".pub", ".ole", ".cfb", ".db",
    ],
    high_risk: false,
};

const SPEC_DOCX: MagicSpec = MagicSpec {
    type_id: "DOCX",
    family: "DOCUMENT",
    label: "Word 文档 (DOCX)",
    canonical_extensions: &[".docx"],
    compatible_extensions: &[".docx", ".docm", ".dotx", ".dotm"],
    high_risk: false,
};

const SPEC_XLSX: MagicSpec = MagicSpec {
    type_id: "XLSX",
    family: "DOCUMENT",
    label: "Excel 工作簿 (XLSX)",
    canonical_extensions: &[".xlsx"],
    compatible_extensions: &[".xlsx", ".xlsm", ".xltx", ".xltm"],
    high_risk: false,
};

const SPEC_PPTX: MagicSpec = MagicSpec {
    type_id: "PPTX",
    family: "DOCUMENT",
    label: "PowerPoint 演示文稿 (PPTX)",
    canonical_extensions: &[".pptx"],
    compatible_extensions: &[".pptx", ".pptm", ".potx", ".potm", ".ppsx"],
    high_risk: false,
};

const SPEC_ZIP: MagicSpec = MagicSpec {
    type_id: "ZIP",
    family: "ARCHIVE",
    label: "ZIP 压缩归档",
    canonical_extensions: &[".zip"],
    compatible_extensions: &[
        ".zip", ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".pptx",
        ".pptm", ".potx", ".potm", ".ppsx", ".odt", ".ods", ".odp", ".epub", ".apk", ".jar", ".war",
        ".ear", ".aar", ".ipa", ".xpi", ".crx", ".vsix", ".nupkg", ".whl", ".kmz", ".cbz",
        ".sketch", ".pages", ".numbers", ".key",
    ],
    high_risk: false,
};

const SPEC_GZIP: MagicSpec = MagicSpec {
    type_id: "GZIP",
    family: "ARCHIVE",
    label: "GZIP 压缩归档",
    canonical_extensions: &[".gz", ".gzip"],
    compatible_extensions: &[".gz", ".gzip", ".tgz", ".svgz", ".wmz", ".emz"],
    high_risk: false,
};

const SPEC_RAR: MagicSpec = MagicSpec {
    type_id: "RAR",
    family: "ARCHIVE",
    label: "RAR 压缩归档",
    canonical_extensions: &[".rar"],
    compatible_extensions: &[".rar", ".cbr", ".rev"],
    high_risk: false,
};

const SPEC_7Z: MagicSpec = MagicSpec {
    type_id: "7Z",
    family: "ARCHIVE",
    label: "7-Zip 压缩归档",
    canonical_extensions: &[".7z"],
    compatible_extensions: &[".7z", ".cb7"],
    high_risk: false,
};

const SPEC_BZIP2: MagicSpec = MagicSpec {
    type_id: "BZIP2",
    family: "ARCHIVE",
    label: "BZIP2 压缩归档",
    canonical_extensions: &[".bz2"],
    compatible_extensions: &[".bz2", ".bzip2", ".tbz", ".tbz2", ".tz2"],
    high_risk: false,
};

const SPEC_XZ: MagicSpec = MagicSpec {
    type_id: "XZ",
    family: "ARCHIVE",
    label: "XZ 压缩归档",
    canonical_extensions: &[".xz"],
    compatible_extensions: &[".xz", ".txz"],
    high_risk: false,
};

const SPEC_PNG: MagicSpec = MagicSpec {
    type_id: "PNG",
    family: "IMAGE",
    label: "PNG 图像",
    canonical_extensions: &[".png"],
    compatible_extensions: &[".png", ".apng"],
    high_risk: false,
};

const SPEC_JPEG: MagicSpec = MagicSpec {
    type_id: "JPEG",
    family: "IMAGE",
    label: "JPEG 图像",
    canonical_extensions: &[".jpg", ".jpeg"],
    compatible_extensions: &[".jpg", ".jpeg", ".jpe", ".jfif", ".jif"],
    high_risk: false,
};

const SPEC_GIF: MagicSpec = MagicSpec {
    type_id: "GIF",
    family: "IMAGE",
    label: "GIF 图像",
    canonical_extensions: &[".gif"],
    compatible_extensions: &[".gif"],
    high_risk: false,
};

const SPEC_BMP: MagicSpec = MagicSpec {
    type_id: "BMP",
    family: "IMAGE",
    label: "BMP 位图图像",
    canonical_extensions: &[".bmp"],
    compatible_extensions: &[".bmp", ".dib"],
    high_risk: false,
};

const SPEC_WEBP: MagicSpec = MagicSpec {
    type_id: "WEBP",
    family: "IMAGE",
    label: "WebP 图像",
    canonical_extensions: &[".webp"],
    compatible_extensions: &[".webp"],
    high_risk: false,
};

const SPEC_WAV: MagicSpec = MagicSpec {
    type_id: "WAV",
    family: "AUDIO",
    label: "WAV 音频",
    canonical_extensions: &[".wav"],
    compatible_extensions: &[".wav", ".wave"],
    high_risk: false,
};

const SPEC_AVI: MagicSpec = MagicSpec {
    type_id: "AVI",
    family: "VIDEO",
    label: "AVI 视频",
    canonical_extensions: &[".avi"],
    compatible_extensions: &[".avi"],
    high_risk: false,
};

const SPEC_MP4: MagicSpec = MagicSpec {
    type_id: "MP4",
    family: "VIDEO",
    label: "MP4/MOV 媒体文件",
    canonical_extensions: &[".mp4", ".mov"],
    compatible_extensions: &[
        ".mp4", ".mov", ".m4v", ".m4a", ".m4b", ".3gp", ".3g2", ".qt", ".f4v", ".heic", ".heif",
        ".avif",
    ],
    high_risk: false,
};

const SPEC_MP3: MagicSpec = MagicSpec {
    type_id: "MP3",
    family: "AUDIO",
    label: "MP3 音频 (ID3)",
    canonical_extensions: &[".mp3"],
    compatible_extensions: &[".mp3", ".mp2", ".aac"],
    high_risk: false,
};

impl MagicSpec {
    fn to_info(&self) -> MagicTypeInfo {
        MagicTypeInfo {
            type_id: self.type_id.to_string(),
            family: self.family.to_string(),
            label: self.label.to_string(),
            canonical_extensions: self
                .canonical_extensions
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            high_risk: self.high_risk,
        }
    }

    fn is_compatible_extension(&self, ext: &str) -> bool {
        self.compatible_extensions.contains(&ext)
    }
}

/// 将文件头前 16 字节格式化为空格分隔的大写十六进制字符串（如 `"89 50 4E 47"`）。
pub fn format_magic_hex(header: &[u8]) -> String {
    let slice = &header[..header.len().min(MAGIC_HEX_PREVIEW_BYTES)];
    if slice.is_empty() {
        return String::new();
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(slice.len() * 3 - 1);
    for (idx, &b) in slice.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// 从镜像内路径提取归一化小写扩展名（含前导点号，如 `".txt"`）；无扩展名或纯隐藏文件（如 `.gitignore`）返回 `""`。
pub fn extract_extension(path: &str) -> String {
    let leaf = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .trim_end_matches(' ');
    let Some(dot_idx) = leaf.rfind('.') else {
        return String::new();
    };
    // 点号位于开头（如 `.env`）或末尾（如 `file.`）均视为无有效扩展名。
    if dot_idx == 0 || dot_idx + 1 >= leaf.len() {
        return String::new();
    }
    let ext = &leaf[dot_idx..];
    if !ext.is_ascii() || ext.len() > 24 {
        return String::new();
    }
    ext.to_ascii_lowercase()
}

/// 生成与桌面端 `resolve_entry` 兼容的条目唯一键（格式：`"{offset}:{inode}:{0|1}:{path}"`）。
pub fn magic_entry_key(entry: &InventoryEntry) -> String {
    format!(
        "{}:{}:{}:{}",
        entry.offset,
        entry.inode,
        u8::from(entry.deleted),
        entry.path
    )
}

/// 判断字节前缀是否属于合法的 Windows PE/MZ 二进制头，避免对以 `"MZ"` 开头的纯文本误报。
fn is_pe_header(header: &[u8]) -> bool {
    if header.len() < 2 || &header[..2] != b"MZ" {
        return false;
    }
    if header.len() >= 0x40 {
        let e_lfanew =
            u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]]) as usize;
        // 完整命中 PE\0\0 签名（常规 Windows 可执行文件均在 4 KiB 内）。
        if e_lfanew >= 0x40
            && e_lfanew.saturating_add(4) <= header.len()
            && &header[e_lfanew..e_lfanew + 4] == b"PE\0\0"
        {
            return true;
        }
        // e_lfanew 指向头部窗口之后（或紧凑 DOS/PE 存根），要求 DOS 头具备明确二进制特征（含 NUL 或标准 MZ 90 00）。
        let standard_dos_bytes = header[2] == 0x90 && header[3] == 0x00;
        let has_nul_in_dos = header[2..0x40].contains(&0);
        if (standard_dos_bytes || has_nul_in_dos) && (0x40..=0x10_0000).contains(&e_lfanew) {
            return true;
        }
        return false;
    }
    // 长度不足 64 字节的截断/最小样本：必须具备明确二进制 DOS/PE 特征，排除纯 ASCII 文本。
    if header.len() >= 4 && header[2] == 0x90 && header[3] == 0x00 {
        return true;
    }
    memmem::find(header, b"PE\0\0").is_some()
}

/// 判断字节前缀是否为 Mach-O（含 32/64 位大小端及 Universal Fat 二进制），同时排除 Java `.class` 碰撞。
fn is_macho_header(header: &[u8]) -> bool {
    if header.len() < 4 {
        return false;
    }
    match &header[..4] {
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCF, 0xFA, 0xED, 0xFE]
        | [0xCA, 0xFE, 0xBA, 0xBF] => true,
        // `CA FE BA BE` 同时为 Java `.class` 与 32 位 Mach-O Fat 头：
        // Mach-O Fat 在偏移 4..8 为小整数架构计数 `nfat_arch`（通常 1..=20），而 Java `.class` 主版本号 >= 45。
        [0xCA, 0xFE, 0xBA, 0xBE] if header.len() >= 8 => {
            let nfat_arch = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
            (1..=20).contains(&nfat_arch)
        }
        _ => false,
    }
}

/// 判断字节前缀是否为合法 BMP 位图头，避免对以 `"BM"` 开头的纯文本误报。
fn is_bmp_header(header: &[u8]) -> bool {
    if header.len() < 6 || &header[..2] != b"BM" {
        return false;
    }
    if header.len() >= 14 {
        let file_size = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
        let reserved = &header[6..10];
        let pixel_offset = u32::from_le_bytes([header[10], header[11], header[12], header[13]]);
        return reserved == [0, 0, 0, 0]
            && file_size >= 14
            && (14..=0x0100_0000).contains(&pixel_offset);
    }
    // 截短样本（6..14 字节）：仅在包含 NUL 二进制特征时识别为 BMP。
    header[2..].contains(&0)
}

/// 判断字节前缀是否为 ISO BMFF（MP4/MOV）`ftyp` 盒头。
fn is_mp4_ftyp_header(header: &[u8]) -> bool {
    if header.len() < 12 || &header[4..8] != b"ftyp" {
        return false;
    }
    let box_size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let size_plausible = box_size == 0 || (12..=4096).contains(&box_size);
    let brand_plausible = header[8..12]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_'));
    size_plausible && brand_plausible
}

/// 判断字节前缀是否为 ID3v2 标记的 MP3 音频，避免误报 `"ID3001"` 等纯文本。
fn is_mp3_id3_header(header: &[u8]) -> bool {
    if header.len() < 3 || &header[..3] != b"ID3" {
        return false;
    }
    if header.len() >= 5 {
        return header[3] <= 4 && header[4] != 0xFF;
    }
    true
}

/// 仅扫描前 4 KiB 原始字节（绝不解压）区分 OOXML（DOCX/XLSX/PPTX）与通用 ZIP。
fn detect_zip_or_ooxml(header: &[u8]) -> &'static MagicSpec {
    if header.starts_with(b"PK\x03\x04") {
        let scan_slice = &header[..header.len().min(MAGIC_HEADER_BYTES)];
        if memmem::find(scan_slice, b"[Content_Types].xml").is_some() {
            if memmem::find(scan_slice, b"word/").is_some() {
                return &SPEC_DOCX;
            }
            if memmem::find(scan_slice, b"xl/").is_some() {
                return &SPEC_XLSX;
            }
            if memmem::find(scan_slice, b"ppt/").is_some() {
                return &SPEC_PPTX;
            }
        }
    }
    &SPEC_ZIP
}

/// 内部魔数规格匹配核心（纯只读字节切片，零解压、零磁盘 I/O）。
fn detect_magic_spec(header: &[u8]) -> Option<&'static MagicSpec> {
    if header.len() < 2 {
        return None;
    }

    // 1. 可执行文件与 Windows 快捷方式（高危优先检查）。
    if is_pe_header(header) {
        return Some(&SPEC_PE);
    }
    if header.starts_with(b"\x7fELF") {
        return Some(&SPEC_ELF);
    }
    if is_macho_header(header) {
        return Some(&SPEC_MACHO);
    }
    if header.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return Some(&SPEC_LNK);
    }

    // 2. 文档与数据库。
    if header.starts_with(b"%PDF-") {
        return Some(&SPEC_PDF);
    }
    if header.starts_with(b"SQLite format 3\0") {
        return Some(&SPEC_SQLITE);
    }
    if header.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return Some(&SPEC_OLE2);
    }

    // 3. OOXML 与压缩归档（严禁解压缩）。
    if header.starts_with(b"PK\x03\x04")
        || header.starts_with(b"PK\x05\x06")
        || header.starts_with(b"PK\x07\x08")
    {
        return Some(detect_zip_or_ooxml(header));
    }
    if header.starts_with(&[0x1F, 0x8B]) && (header.len() == 2 || header[2] == 0x08) {
        return Some(&SPEC_GZIP);
    }
    if header.starts_with(b"Rar!\x1a\x07") {
        return Some(&SPEC_RAR);
    }
    if header.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(&SPEC_7Z);
    }
    if header.starts_with(b"BZh") && (header.len() == 3 || matches!(header[3], b'1'..=b'9')) {
        return Some(&SPEC_BZIP2);
    }
    if header.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(&SPEC_XZ);
    }

    // 4. 图片与音视频。
    if header.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(&SPEC_PNG);
    }
    if header.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(&SPEC_JPEG);
    }
    if header.starts_with(b"GIF87a") || header.starts_with(b"GIF89a") {
        return Some(&SPEC_GIF);
    }
    if is_bmp_header(header) {
        return Some(&SPEC_BMP);
    }
    if header.len() >= 12 && &header[..4] == b"RIFF" {
        match &header[8..12] {
            b"WEBP" => return Some(&SPEC_WEBP),
            b"WAVE" => return Some(&SPEC_WAV),
            b"AVI " => return Some(&SPEC_AVI),
            _ => {}
        }
    }
    if is_mp4_ftyp_header(header) {
        return Some(&SPEC_MP4);
    }
    if is_mp3_id3_header(header) {
        return Some(&SPEC_MP3);
    }

    None
}

/// 纯字节文件头魔数识别：基于前 `<= 4096` 字节判断真实二进制文件类型。
///
/// 若文件头不命中任何已知二进制魔数（如纯文本、日志、CSV、JSON、XML 等），返回 `None`。
pub fn detect_magic_bytes(header: &[u8]) -> Option<MagicTypeInfo> {
    detect_magic_spec(header).map(MagicSpec::to_info)
}

/// 内部评估辅助函数：结合已匹配的 [`MagicSpec`] 与路径后缀生成 [`MagicCheckItem`]。
fn evaluate_with_spec(
    path: &str,
    spec: Option<&'static MagicSpec>,
    magic_hex: String,
) -> MagicCheckItem {
    let extension = extract_extension(path);
    let Some(spec) = spec else {
        return MagicCheckItem {
            detected_type: None,
            detected_family: None,
            detected_label: None,
            extension,
            mismatch: false,
            severity: "none".to_string(),
            reason: "未检测到已知二进制文件头，不判定为扩展名伪装".to_string(),
            magic_hex,
        };
    };

    if extension.is_empty() {
        return MagicCheckItem {
            detected_type: Some(spec.type_id.to_string()),
            detected_family: Some(spec.family.to_string()),
            detected_label: Some(spec.label.to_string()),
            extension,
            mismatch: false,
            severity: "none".to_string(),
            reason: format!("文件未声明扩展名（实际文件头为 {}），不判定为伪装", spec.label),
            magic_hex,
        };
    }

    if spec.is_compatible_extension(&extension) {
        return MagicCheckItem {
            detected_type: Some(spec.type_id.to_string()),
            detected_family: Some(spec.family.to_string()),
            detected_label: Some(spec.label.to_string()),
            extension: extension.clone(),
            mismatch: false,
            severity: "none".to_string(),
            reason: format!("声明后缀 {extension} 与实际文件头 {} 一致", spec.label),
            magic_hex,
        };
    }

    let severity = if spec.high_risk { "high" } else { "medium" };
    let reason = format!("声明后缀 {extension}，实际文件头为 {}", spec.label);

    MagicCheckItem {
        detected_type: Some(spec.type_id.to_string()),
        detected_family: Some(spec.family.to_string()),
        detected_label: Some(spec.label.to_string()),
        extension,
        mismatch: true,
        severity: severity.to_string(),
        reason,
        magic_hex,
    }
}

/// 对比文件路径声明的扩展名与原始文件头字节，判定是否存在扩展名伪装。
pub fn evaluate_magic_mismatch(path: &str, header: &[u8]) -> MagicCheckItem {
    let spec = detect_magic_spec(header);
    let magic_hex = format_magic_hex(header);
    evaluate_with_spec(path, spec, magic_hex)
}

/// 严格有界地通过 `icat` 读取单个条目最多前 `want` 字节，读满后立即终止子进程。
fn read_header_via_bounded_icat(
    tool: &TskCli,
    image: &Path,
    entry: &InventoryEntry,
    want: usize,
    cancel: Option<&AtomicBool>,
) -> CoreResult<Vec<u8>> {
    if want == 0 {
        return Ok(Vec::new());
    }
    let mut header = Vec::with_capacity(want);
    let mut reached_cap = false;

    let stream_res = tool.stream_entry(image, entry, cancel, |chunk| {
        let remaining = want.saturating_sub(header.len());
        let take = chunk.len().min(remaining);
        if take > 0 {
            header.extend_from_slice(&chunk[..take]);
        }
        if header.len() >= want {
            reached_cap = true;
            return Err(EngineError::Cancelled("magic_header_cap".to_string()));
        }
        Ok(())
    });

    match stream_res {
        Ok(_) => Ok(header),
        Err(EngineError::Cancelled(_)) if reached_cap => Ok(header),
        Err(err) if err.is_cancelled() => Err(CoreError::Cancelled("已取消魔数识别".to_string())),
        Err(err) => {
            if !header.is_empty() && entry.deleted {
                Ok(header)
            } else {
                Err(err.into())
            }
        }
    }
}

/// 从给定镜像中只读读取单个文件的前 4096 字节并执行魔数与扩展名比对（支持传入可选复用的 `TskCli`）。
pub fn inspect_entry_magic_at_image(
    image: &Path,
    entry: &InventoryEntry,
    tsk: Option<&TskCli>,
) -> CoreResult<MagicCheckItem> {
    if entry.directory || entry.mode.starts_with("V/") || entry.mode.starts_with("v/") {
        return Err(CoreError::InvalidInput(format!(
            "{} 不是普通文件，无法执行文件头魔数检测。",
            entry.path
        )));
    }
    if !image.is_file() {
        return Err(CoreError::NotFound(format!(
            "案件记录的镜像不存在：{}",
            image.display()
        )));
    }
    if entry.size == 0 {
        return Ok(evaluate_magic_mismatch(&entry.path, &[]));
    }

    let want = (entry.size as usize).min(MAGIC_HEADER_BYTES);

    // 优先通过进程内 VolumeReader 直读前 <= 4096 字节（零子进程、零临时文件）。
    if let Ok(mut vol) = VolumeReader::open(image) {
        let mut buf = vec![0u8; want];
        if vol.read_entry_into(entry, 0, &mut buf).is_ok() {
            return Ok(evaluate_magic_mismatch(&entry.path, &buf));
        }
    }

    // 无法直读时安全回退到有界 icat，仅读取前 <= 4096 字节后立即结束子进程。
    let discovered;
    let tool = match tsk {
        Some(t) => t,
        None => {
            discovered = TskCli::discover(None)?;
            &discovered
        }
    };
    let header = read_header_via_bounded_icat(tool, image, entry, want, None)?;
    Ok(evaluate_magic_mismatch(&entry.path, &header))
}

/// 只读检测案件内单个文件的前 4096 字节魔数与扩展名伪装情况。
pub fn inspect_entry_magic(case: &Case, entry: &InventoryEntry) -> CoreResult<MagicCheckItem> {
    let image = case.image_path()?;
    inspect_entry_magic_at_image(&image, entry, None)
}

/// 解析 TSK inode 主编号（用于按 `(offset, inode_num)` 排序以提升 MFT/磁盘读取局部性）。
fn parse_inode_sort_num(inode: &str) -> u64 {
    inode
        .split('-')
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SharedHeaderKey {
    offset: u64,
    inode: String,
    size: u64,
}

#[derive(Debug, Clone)]
struct ProbedHeader {
    spec: Option<&'static MagicSpec>,
    magic_hex: String,
}

#[derive(Debug)]
enum DirectProbeResult {
    Probed(ProbedHeader),
    NeedsIcat,
    Cancelled,
}

/// 基于镜像路径与条目切片执行高速批量魔数与扩展名伪装扫描（支持脱离 `Case` 锁在后台线程调用）。
pub fn scan_entries_magic_mismatches(
    image: &Path,
    entries: &[InventoryEntry],
    partition_offsets: &[u64],
    cancel: Option<&AtomicBool>,
) -> CoreResult<MagicScanReport> {
    if !image.is_file() {
        return Err(CoreError::NotFound(format!(
            "案件记录的镜像不存在：{}",
            image.display()
        )));
    }

    let started = Instant::now();
    let mut skipped_count: usize = 0;

    // 1. 筛选所有可读且 `size > 0` 的常规/已删除文件（自动跳过目录、虚拟目录与系统区域）。
    let mut candidates: Vec<&InventoryEntry> = Vec::new();
    let mut distinct_offsets: HashSet<u64> = partition_offsets.iter().copied().collect();
    for entry in entries {
        if !can_export(entry) || entry.size == 0 || entry.extents.is_some() {
            skipped_count += 1;
            continue;
        }
        distinct_offsets.insert(entry.offset);
        candidates.push(entry);
    }

    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Ok(MagicScanReport {
            scanned_count: 0,
            skipped_count: skipped_count + candidates.len(),
            mismatch_count: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
            cancelled: true,
            type_counts: Vec::new(),
            mismatches: Vec::new(),
        });
    }

    // 2. 为未删除常规文件做硬链接去重读取（相同 `(offset, inode, size)` 仅读取一次文件头，但每条路径仍独立比对扩展名）。
    let mut unique_shared: HashMap<SharedHeaderKey, usize> = HashMap::new();
    let mut read_targets: Vec<&InventoryEntry> = Vec::new();
    let mut candidate_target_idx: Vec<usize> = Vec::with_capacity(candidates.len());

    for &entry in &candidates {
        if !entry.deleted && entry.mode.starts_with("r/") {
            let key = SharedHeaderKey {
                offset: entry.offset,
                inode: entry.inode.clone(),
                size: entry.size,
            };
            if let Some(&existing_target) = unique_shared.get(&key) {
                candidate_target_idx.push(existing_target);
            } else {
                let target_idx = read_targets.len();
                unique_shared.insert(key, target_idx);
                read_targets.push(entry);
                candidate_target_idx.push(target_idx);
            }
        } else {
            let target_idx = read_targets.len();
            read_targets.push(entry);
            candidate_target_idx.push(target_idx);
        }
    }

    // 3. 打开并预热共享只读 MediaReader 与 VolumeReader（NTFS $MFT 仅解析一次并跨线程共享）。
    let media: Option<Arc<dyn MediaReader>> = open_media(image).ok();
    let mut probe_vol: Option<VolumeReader> = media
        .as_ref()
        .map(|m| VolumeReader::open_with_media(Arc::clone(m)));
    if let Some(ref mut pv) = probe_vol {
        let mut sorted_offsets: Vec<u64> = distinct_offsets.into_iter().collect();
        sorted_offsets.sort_unstable();
        for off in sorted_offsets {
            pv.prime_partition(off);
        }
    }

    let mut probed_results: Vec<Option<ProbedHeader>> = vec![None; read_targets.len()];
    let mut icat_fallback_indices: Vec<usize> = Vec::new();
    let mut cancelled = false;

    if let Some(ref pv_ref) = probe_vol {
        // 按 `(offset, inode_num)` 排序直读顺序以最大化磁盘与 MFT 局部性。
        let mut ordered_targets: Vec<usize> = (0..read_targets.len()).collect();
        ordered_targets.sort_unstable_by_key(|&t_idx| {
            let entry = read_targets[t_idx];
            (entry.offset, parse_inode_sort_num(&entry.inode))
        });

        let outcomes: Vec<(usize, DirectProbeResult)> = ordered_targets
            .into_par_iter()
            .map_init(
                || (pv_ref.fork_worker(), vec![0u8; MAGIC_HEADER_BYTES]),
                |(vol, buf), t_idx| {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        return (t_idx, DirectProbeResult::Cancelled);
                    }
                    let entry = read_targets[t_idx];
                    let want = (entry.size as usize).min(MAGIC_HEADER_BYTES);
                    match vol.read_entry_into(entry, 0, &mut buf[..want]) {
                        Ok(()) => {
                            let slice = &buf[..want];
                            let spec = detect_magic_spec(slice);
                            let magic_hex = format_magic_hex(slice);
                            (t_idx, DirectProbeResult::Probed(ProbedHeader { spec, magic_hex }))
                        }
                        Err(_) => (t_idx, DirectProbeResult::NeedsIcat),
                    }
                },
            )
            .collect();

        for (t_idx, outcome) in outcomes {
            match outcome {
                DirectProbeResult::Probed(probed) => {
                    probed_results[t_idx] = Some(probed);
                }
                DirectProbeResult::NeedsIcat => {
                    icat_fallback_indices.push(t_idx);
                }
                DirectProbeResult::Cancelled => {
                    cancelled = true;
                }
            }
        }
    } else {
        icat_fallback_indices.extend(0..read_targets.len());
    }

    // 4. 对无法通过 VolumeReader 直读的条目按需回退到有界 icat（仅读前 4096 字节后立即结束子进程）。
    if !cancelled && !icat_fallback_indices.is_empty() {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            cancelled = true;
        } else if let Ok(tool) = TskCli::discover(None) {
            let thread_count = icat_fallback_indices.len().clamp(1, MAGIC_ICAT_THREADS);
            let run_icat_one = |t_idx: usize| -> (usize, Option<ProbedHeader>, bool) {
                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return (t_idx, None, true);
                }
                let entry = read_targets[t_idx];
                let want = (entry.size as usize).min(MAGIC_HEADER_BYTES);
                match read_header_via_bounded_icat(&tool, image, entry, want, cancel) {
                    Ok(header) => {
                        let spec = detect_magic_spec(&header);
                        let magic_hex = format_magic_hex(&header);
                        (t_idx, Some(ProbedHeader { spec, magic_hex }), false)
                    }
                    Err(err) if err.is_cancelled() => (t_idx, None, true),
                    Err(_) => (t_idx, None, false),
                }
            };

            let icat_results: Vec<(usize, Option<ProbedHeader>, bool)> = if thread_count == 1 {
                let mut out = Vec::with_capacity(icat_fallback_indices.len());
                for t_idx in icat_fallback_indices {
                    let res = run_icat_one(t_idx);
                    let was_cancelled = res.2;
                    out.push(res);
                    if was_cancelled {
                        break;
                    }
                }
                out
            } else if let Ok(pool) = rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build()
            {
                pool.install(|| {
                    icat_fallback_indices
                        .into_par_iter()
                        .map(run_icat_one)
                        .collect()
                })
            } else {
                let mut out = Vec::with_capacity(icat_fallback_indices.len());
                for t_idx in icat_fallback_indices {
                    let res = run_icat_one(t_idx);
                    let was_cancelled = res.2;
                    out.push(res);
                    if was_cancelled {
                        break;
                    }
                }
                out
            };

            for (t_idx, maybe_probed, was_cancelled) in icat_results {
                if was_cancelled {
                    cancelled = true;
                }
                if let Some(probed) = maybe_probed {
                    probed_results[t_idx] = Some(probed);
                }
            }
        }
    }

    // 5. 汇总扫描统计、各类文件计数与扩展名伪装明细。
    let mut scanned_count: usize = 0;
    let mut type_counter: BTreeMap<&'static str, (&'static MagicSpec, usize)> = BTreeMap::new();
    let mut mismatches: Vec<MagicMismatchEntry> = Vec::new();

    for (cand_pos, &entry) in candidates.iter().enumerate() {
        let target_idx = candidate_target_idx[cand_pos];
        let Some(ref probed) = probed_results[target_idx] else {
            skipped_count += 1;
            continue;
        };
        scanned_count += 1;

        if let Some(spec) = probed.spec {
            let slot = type_counter.entry(spec.type_id).or_insert((spec, 0));
            slot.1 += 1;
        }

        let check = evaluate_with_spec(&entry.path, probed.spec, probed.magic_hex.clone());
        if check.mismatch {
            mismatches.push(MagicMismatchEntry {
                entry_key: magic_entry_key(entry),
                offset: entry.offset,
                inode: entry.inode.clone(),
                path: entry.path.clone(),
                deleted: entry.deleted,
                size: entry.size,
                extension: check.extension,
                detected_type: check.detected_type.unwrap_or_default(),
                detected_family: check.detected_family.unwrap_or_default(),
                detected_label: check.detected_label.unwrap_or_default(),
                severity: check.severity,
                reason: check.reason,
                magic_hex: check.magic_hex,
            });
        }
    }

    // 各类文件统计按检出数量降序、类型标识升序稳定排序。
    let mut type_counts: Vec<MagicTypeCount> = type_counter
        .into_values()
        .map(|(spec, count)| MagicTypeCount {
            detected_type: spec.type_id.to_string(),
            detected_family: spec.family.to_string(),
            label: spec.label.to_string(),
            count,
        })
        .collect();
    type_counts.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.detected_type.cmp(&b.detected_type))
    });

    // 伪装结果按高危优先，其次按分区偏移、路径、inode 确定性排序。
    mismatches.sort_by(|a, b| {
        let rank = |sev: &str| match sev {
            "high" => 0u8,
            "medium" => 1u8,
            _ => 2u8,
        };
        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then_with(|| a.offset.cmp(&b.offset))
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.inode.cmp(&b.inode))
    });

    let mismatch_count = mismatches.len();
    let elapsed_ms = started.elapsed().as_millis() as u64;

    Ok(MagicScanReport {
        scanned_count,
        skipped_count,
        mismatch_count,
        elapsed_ms,
        cancelled,
        type_counts,
        mismatches,
    })
}

/// 扫描案件清单中所有可读且 `size > 0` 的文件，批量识别真实文件头并检出扩展名伪装。
pub fn scan_case_magic_mismatches(
    case: &Case,
    cancel: Option<&AtomicBool>,
) -> CoreResult<MagicScanReport> {
    let image = case.image_path()?;
    let partition_offsets: Vec<u64> = case
        .data()
        .evidence
        .as_ref()
        .map(|ev| ev.partitions.iter().map(|p| p.offset).collect())
        .unwrap_or_default();
    let entries = case.displayed_entries();
    scan_entries_magic_mismatches(&image, entries, &partition_offsets, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::AuditOrigin;
    use crate::paths::AppPaths;

    /// 构造标准最小 Windows PE 头（带 `e_lfanew = 0x40` 与 `PE\0\0`）。
    fn sample_pe_header() -> Vec<u8> {
        let mut buf = vec![0u8; 0x50];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[2] = 0x90;
        buf[3] = 0x00;
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        buf
    }

    /// 构造标准最小 BMP 文件头（14 字节头 + 40 字节 DIB 头标记）。
    fn sample_bmp_header() -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0..2].copy_from_slice(b"BM");
        buf[2..6].copy_from_slice(&128u32.to_le_bytes());
        buf[6..10].copy_from_slice(&[0, 0, 0, 0]);
        buf[10..14].copy_from_slice(&54u32.to_le_bytes());
        buf[14..18].copy_from_slice(&40u32.to_le_bytes());
        buf
    }

    /// 构造模拟 OOXML ZIP 原始字节头（不压缩，仅含本地文件头魔数与 XML/目录特征）。
    fn sample_ooxml_header(sub_dir: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x08\x00");
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(b"[Content_Types].xml");
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x08\x00");
        buf.extend_from_slice(sub_dir);
        buf.extend_from_slice(b"document.xml");
        buf
    }

    #[test]
    fn detect_all_major_binary_magic_signatures() {
        // 可执行文件与快捷方式
        let pe = detect_magic_bytes(&sample_pe_header()).expect("PE");
        assert_eq!(pe.type_id, "PE");
        assert_eq!(pe.family, "EXECUTABLE");
        assert!(pe.high_risk);

        let elf = detect_magic_bytes(b"\x7fELF\x02\x01\x01\x00").expect("ELF");
        assert_eq!(elf.type_id, "ELF");
        assert_eq!(elf.family, "EXECUTABLE");
        assert!(elf.high_risk);

        let macho_le = detect_magic_bytes(&[0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01])
            .expect("Mach-O 64 LE");
        assert_eq!(macho_le.type_id, "MACHO");
        assert!(macho_le.high_risk);

        let macho_fat = detect_magic_bytes(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02])
            .expect("Mach-O Fat");
        assert_eq!(macho_fat.type_id, "MACHO");
        // Java .class（major version 52 = 0x34）不应误判为 Mach-O。
        assert!(detect_magic_bytes(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34]).is_none());

        let lnk = detect_magic_bytes(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00])
            .expect("LNK");
        assert_eq!(lnk.type_id, "LNK");
        assert_eq!(lnk.family, "SHORTCUT");
        assert!(lnk.high_risk);

        // 文档与数据库
        assert_eq!(detect_magic_bytes(b"%PDF-1.7\n").expect("PDF").type_id, "PDF");
        assert_eq!(
            detect_magic_bytes(b"SQLite format 3\0\x10\x00").expect("SQLite").type_id,
            "SQLITE"
        );
        assert_eq!(
            detect_magic_bytes(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00])
                .expect("OLE2")
                .type_id,
            "OLE2"
        );
        assert_eq!(
            detect_magic_bytes(&sample_ooxml_header(b"word/")).expect("DOCX").type_id,
            "DOCX"
        );
        assert_eq!(
            detect_magic_bytes(&sample_ooxml_header(b"xl/")).expect("XLSX").type_id,
            "XLSX"
        );
        assert_eq!(
            detect_magic_bytes(&sample_ooxml_header(b"ppt/")).expect("PPTX").type_id,
            "PPTX"
        );

        // 压缩与归档
        assert_eq!(detect_magic_bytes(b"PK\x03\x04hello").expect("ZIP").type_id, "ZIP");
        assert_eq!(detect_magic_bytes(b"PK\x05\x06\x00\x00").expect("Empty ZIP").type_id, "ZIP");
        assert_eq!(detect_magic_bytes(&[0x1F, 0x8B, 0x08, 0x00]).expect("GZIP").type_id, "GZIP");
        assert_eq!(detect_magic_bytes(b"Rar!\x1a\x07\x01\x00").expect("RAR").type_id, "RAR");
        assert_eq!(
            detect_magic_bytes(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00])
                .expect("7Z")
                .type_id,
            "7Z"
        );
        assert_eq!(detect_magic_bytes(b"BZh91AY&SY").expect("BZIP2").type_id, "BZIP2");
        assert_eq!(
            detect_magic_bytes(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00])
                .expect("XZ")
                .type_id,
            "XZ"
        );

        // 图片与音视频
        assert_eq!(
            detect_magic_bytes(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
                .expect("PNG")
                .type_id,
            "PNG"
        );
        assert_eq!(
            detect_magic_bytes(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
                .expect("JPEG")
                .type_id,
            "JPEG"
        );
        assert_eq!(detect_magic_bytes(b"GIF87a\x01\x00").expect("GIF87a").type_id, "GIF");
        assert_eq!(detect_magic_bytes(b"GIF89a\x01\x00").expect("GIF89a").type_id, "GIF");
        assert_eq!(detect_magic_bytes(&sample_bmp_header()).expect("BMP").type_id, "BMP");
        assert_eq!(
            detect_magic_bytes(b"RIFF\x24\x00\x00\x00WEBP").expect("WebP").type_id,
            "WEBP"
        );
        assert_eq!(
            detect_magic_bytes(b"RIFF\x24\x00\x00\x00WAVE").expect("WAV").type_id,
            "WAV"
        );
        assert_eq!(
            detect_magic_bytes(b"RIFF\x24\x00\x00\x00AVI ").expect("AVI").type_id,
            "AVI"
        );
        assert_eq!(
            detect_magic_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00")
                .expect("MP4")
                .type_id,
            "MP4"
        );
        assert_eq!(
            detect_magic_bytes(b"ID3\x03\x00\x00\x00\x00\x00\x10").expect("MP3").type_id,
            "MP3"
        );
    }

    #[test]
    fn no_false_positives_on_plain_text_or_same_family_extensions() {
        // 纯文本（含易撞头的 MZ/BM/ID3/BZh 前缀文本）不应误判为二进制。
        for (path, content) in [
            ("notes.txt", b"MZ report summary 2026\n".as_slice()),
            ("readme.md", b"BM architecture guide\n".as_slice()),
            ("events.csv", b"ID3001,2026-01-01,login\n".as_slice()),
            ("app.log", b"BZh_text_marker_not_bzip2\n".as_slice()),
            ("config.json", b"{\"version\": 1}\n".as_slice()),
            ("manifest.xml", b"<?xml version=\"1.0\"?>\n".as_slice()),
            ("settings.ini", b"[general]\nmode=readonly\n".as_slice()),
        ] {
            let item = evaluate_magic_mismatch(path, content);
            assert!(
                !item.mismatch && item.detected_type.is_none() && item.severity == "none",
                "纯文本不应误报：{path} -> {item:?}"
            );
        }

        // 同族合法后缀不误报：.jpg/.jpeg、.docx/.xlsx/.pptx/.apk/.jar + ZIP、.exe/.dll/.sys + PE。
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert!(!evaluate_magic_mismatch("photo.jpg", &jpeg).mismatch);
        assert!(!evaluate_magic_mismatch("photo.JPEG", &jpeg).mismatch);

        let zip = b"PK\x03\x04\x14\x00\x00\x00\x08\x00random_zip_content";
        for path in [
            "archive.zip",
            "report.docx",
            "sheet.xlsx",
            "slides.pptx",
            "app.apk",
            "lib.jar",
        ] {
            let item = evaluate_magic_mismatch(path, zip);
            assert!(!item.mismatch, "ZIP 族容器不应误报：{path} -> {item:?}");
            assert_eq!(item.severity, "none");
        }

        let pe = sample_pe_header();
        for path in ["tool.exe", "kernel.dll", "driver.sys"] {
            let item = evaluate_magic_mismatch(path, &pe);
            assert!(!item.mismatch, "PE 同族后缀不应误报：{path} -> {item:?}");
            assert_eq!(item.severity, "none");
        }

        // 明确 OOXML DOCX 与 .docx 匹配。
        let docx = sample_ooxml_header(b"word/");
        assert!(!evaluate_magic_mismatch("evidence/report.docx", &docx).mismatch);
    }

    #[test]
    fn detects_typical_extension_spoofing_cases() {
        // 1. PNG 伪装成 .txt
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00];
        let png_as_txt = evaluate_magic_mismatch("DOCS/secret.txt", &png);
        assert!(png_as_txt.mismatch);
        assert_eq!(png_as_txt.detected_type.as_deref(), Some("PNG"));
        assert_eq!(png_as_txt.detected_family.as_deref(), Some("IMAGE"));
        assert_eq!(png_as_txt.extension, ".txt");
        assert_eq!(png_as_txt.severity, "medium");
        assert!(png_as_txt.reason.contains(".txt") && png_as_txt.reason.contains("PNG"));
        assert_eq!(png_as_txt.magic_hex, "89 50 4E 47 0D 0A 1A 0A 00 00");

        // 2. PE 可执行文件伪装成 .jpg（高危）
        let pe_as_jpg = evaluate_magic_mismatch("DCIM/holiday.jpg", &sample_pe_header());
        assert!(pe_as_jpg.mismatch);
        assert_eq!(pe_as_jpg.detected_type.as_deref(), Some("PE"));
        assert_eq!(pe_as_jpg.detected_family.as_deref(), Some("EXECUTABLE"));
        assert_eq!(pe_as_jpg.extension, ".jpg");
        assert_eq!(pe_as_jpg.severity, "high");
        assert!(pe_as_jpg.reason.contains(".jpg") && pe_as_jpg.reason.contains("PE"));

        // 3. PDF 伪装成 .log
        let pdf_as_log = evaluate_magic_mismatch("logs/audit.log", b"%PDF-1.5\n%\xE2\xE3\xCF\xD3");
        assert!(pdf_as_log.mismatch);
        assert_eq!(pdf_as_log.detected_type.as_deref(), Some("PDF"));
        assert_eq!(pdf_as_log.detected_family.as_deref(), Some("DOCUMENT"));
        assert_eq!(pdf_as_log.extension, ".log");
        assert_eq!(pdf_as_log.severity, "medium");

        // 4. SQLite 数据库伪装成 .dat
        let sqlite_as_dat =
            evaluate_magic_mismatch("cache/state.dat", b"SQLite format 3\0\x10\x00\x01\x01");
        assert!(sqlite_as_dat.mismatch);
        assert_eq!(sqlite_as_dat.detected_type.as_deref(), Some("SQLITE"));
        assert_eq!(sqlite_as_dat.detected_family.as_deref(), Some("DATABASE"));
        assert_eq!(sqlite_as_dat.extension, ".dat");
        assert_eq!(sqlite_as_dat.severity, "medium");

        // 5. .docx 后缀实际为 PE 或 PNG 均应报伪装
        let pe_as_docx = evaluate_magic_mismatch("contract.docx", &sample_pe_header());
        assert!(pe_as_docx.mismatch);
        assert_eq!(pe_as_docx.severity, "high");
        let png_as_docx = evaluate_magic_mismatch("contract.docx", &png);
        assert!(png_as_docx.mismatch);
        assert_eq!(png_as_docx.severity, "medium");

        // 6. 边界测试：扩展名提取、空/截断头与无扩展名文件
        assert_eq!(extract_extension("dir/sub/PHOTO.JPG"), ".jpg");
        assert_eq!(extract_extension("C:\\Users\\a\\.gitignore"), "");
        assert_eq!(extract_extension("Makefile"), "");
        assert_eq!(extract_extension("trailing."), "");
        assert!(detect_magic_bytes(&[]).is_none());
        assert!(detect_magic_bytes(&[0x4D]).is_none());
        assert!(!evaluate_magic_mismatch("Makefile", &sample_pe_header()).mismatch);
    }

    #[test]
    fn end_to_end_scan_on_demo_dd_and_single_entry_inspect() {
        let paths = AppPaths::discover();
        let demo_dd = paths.evidence_dir.join("demo.dd");
        assert!(demo_dd.is_file(), "缺少测试镜像 demo.dd：{}", demo_dd.display());

        let tmp = tempfile::tempdir().expect("创建临时案件目录");
        let mut case = Case::create(
            tmp.path(),
            "MAGIC-E2E-001",
            "测试取证员",
            "demo.dd 魔数识别与伪装检测端到端测试",
            None,
            None,
            AuditOrigin::Manual,
        )
        .expect("创建案件");
        case.load_image(&demo_dd, None, None, None)
            .expect("加载 demo.dd");
        let inv = case
            .scan_partitions(None, None, None)
            .expect("扫描 demo.dd 分区");
        assert!(!inv.is_empty(), "demo.dd 清单不应为空");

        // 单文件检测：README.TXT 应为纯文本且无伪装。
        let readme = inv
            .iter()
            .find(|e| e.path == "README.TXT")
            .expect("应存在 README.TXT");
        let check = inspect_entry_magic(&case, readme).expect("单文件魔数检测");
        assert_eq!(check.extension, ".txt");
        assert!(!check.mismatch);
        assert_eq!(check.severity, "none");
        assert!(!check.magic_hex.is_empty());

        // 全案扫描：demo.dd 应完成所有常规可读文件扫描且支持 JSON 序列化。
        let report = scan_case_magic_mismatches(&case, None).expect("全案魔数扫描");
        assert!(!report.cancelled);
        assert!(
            report.scanned_count >= 5,
            "demo.dd 至少应扫描 5 个常规文件，实际：{}",
            report.scanned_count
        );
        assert_eq!(report.mismatch_count, report.mismatches.len());

        // 验证预置取消信号能够即时返回 cancelled = true。
        let cancel_flag = AtomicBool::new(true);
        let cancelled_report =
            scan_case_magic_mismatches(&case, Some(&cancel_flag)).expect("取消扫描");
        assert!(cancelled_report.cancelled);
        assert_eq!(cancelled_report.scanned_count, 0);

        // 验证 camelCase JSON 序列化字段完整。
        let json_val = serde_json::to_value(&report).expect("序列化 MagicScanReport");
        assert!(json_val.get("scannedCount").is_some());
        assert!(json_val.get("skippedCount").is_some());
        assert!(json_val.get("mismatchCount").is_some());
        assert!(json_val.get("elapsedMs").is_some());
        assert!(json_val.get("typeCounts").is_some());
        assert!(json_val.get("mismatches").is_some());
    }
}
