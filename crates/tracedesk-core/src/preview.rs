//! 只读分页文件预览：支持 9 种文本编码及跨页多字节边界对齐
//! （UTF-16 代理对 + GBK/GB18030/Big5 安全锚点重同步）、16 字节 HEX 格式化、
//! extent/VolumeReader/icat 路由以及安全图片预览
//! （对应 `core-contract.md` §3.7，与 `forensic/core/preview.py` 和 `forensic/ui/preview.py` 保持一致）。

use std::fs::File;
#[cfg(feature = "image-preview")]
use std::io::Cursor;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(feature = "image-preview")]
use base64::Engine as _;
#[cfg(feature = "image-preview")]
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
#[cfg(feature = "image-preview")]
use image::imageops::FilterType;
#[cfg(feature = "image-preview")]
use image::{AnimationDecoder, ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use tracedesk_engines::{InventoryEntry, TskCli, VolumeReader, deleted_source_note};

use crate::error::{CoreError, CoreResult};

/// 每行 HEX 预览显示的字节数。
pub const ROW_BYTES: usize = 16;
/// 每页预览的默认字节数。
pub const PAGE_BYTES: usize = 4096;
/// 允许完整图片解码的最大文件大小（32 MiB）。
pub const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024;
/// 允许图片预览的最大像素总数（4000 万像素）。
pub const MAX_IMAGE_PIXELS: u64 = 40_000_000;
/// 缩放前单边允许的最大显示尺寸（像素）。
pub const MAX_IMAGE_DIM: u32 = 4096;
/// 未删除常规文件优先使用 `VolumeReader` 随机读取的大小阈值。
pub const RANDOM_READ_MIN_BYTES: u64 = 8 << 20;

/// 支持的图片文件扩展名（含前导点号的小写形式）。
pub const IMAGE_SUFFIXES: [&str; 9] = [
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff", ".ico",
];

/// 全部 9 种受支持预览编码的规范名称。
pub const PREVIEW_ENCODINGS: [&str; 9] = [
    "ASCII",
    "UTF-8",
    "UTF-16LE",
    "UTF-16BE",
    "GBK",
    "GB18030",
    "Big5",
    "Windows-1252",
    "ISO-8859-1",
];

/// 受支持的预览文本编码枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PreviewEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Gbk,
    Gb18030,
    Big5,
    Windows1252,
    Iso8859_1,
}

impl PreviewEncoding {
    /// 解析规范编码名称（精确或大小写不敏感）。
    pub fn parse(name: &str) -> CoreResult<Self> {
        match name.trim().to_ascii_uppercase().as_str() {
            "ASCII" => Ok(Self::Ascii),
            "UTF-8" | "UTF8" => Ok(Self::Utf8),
            "UTF-16LE" | "UTF16LE" => Ok(Self::Utf16Le),
            "UTF-16BE" | "UTF16BE" => Ok(Self::Utf16Be),
            "GBK" => Ok(Self::Gbk),
            "GB18030" => Ok(Self::Gb18030),
            "BIG5" => Ok(Self::Big5),
            "WINDOWS-1252" | "CP1252" => Ok(Self::Windows1252),
            "ISO-8859-1" | "LATIN-1" | "LATIN1" => Ok(Self::Iso8859_1),
            other => Err(CoreError::InvalidInput(format!(
                "不支持的编码 {other}；可选编码：{}",
                PREVIEW_ENCODINGS.join(", ")
            ))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16LE",
            Self::Utf16Be => "UTF-16BE",
            Self::Gbk => "GBK",
            Self::Gb18030 => "GB18030",
            Self::Big5 => "Big5",
            Self::Windows1252 => "Windows-1252",
            Self::Iso8859_1 => "ISO-8859-1",
        }
    }

    pub const fn is_legacy_multibyte(self) -> bool {
        matches!(self, Self::Gbk | Self::Gb18030 | Self::Big5)
    }

    pub const fn is_utf16(self) -> bool {
        matches!(self, Self::Utf16Le | Self::Utf16Be)
    }
}

/// 原始字节窗口 `[max(0, start - 3), min(size, start + page_bytes + 3))` 以及
/// 来自 `start` 之前字节的传统多字节进位偏移。
#[derive(Debug, Clone)]
pub struct PageWindow {
    pub bytes: Vec<u8>,
    pub carry: usize,
    pub encoding: PreviewEncoding,
}

/// HEX 预览表中的单个 16 字节行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HexRow {
    pub offset_hex: String,
    pub bytes_hex: String,
    pub chars: String,
}

/// 完整渲染的预览页结果（文本 + HEX 行 + 元数据）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewPageResult {
    pub page: usize,
    pub total_pages: usize,
    pub page_bytes: usize,
    pub byte_start: u64,
    pub byte_end: u64,
    pub readable_size: u64,
    pub recorded_size: u64,
    pub read_note: String,
    pub source_note: String,
    pub encoding: String,
    pub text: String,
    pub hex_rows: Vec<HexRow>,
    pub is_image_candidate: bool,
}

/// 适用于桌面端 / Web 端渲染的解码图片预览结果。
#[cfg(feature = "image-preview")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImagePreviewResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_url: Option<String>,
    #[serde(skip_serializing)]
    pub png_bytes: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_height: Option<u32>,
    pub animated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub read_note: String,
    pub source_note: String,
}

/// 按 Python `str.isprintable()` 语义判断字符在预览展示中是否可打印。
#[inline]
fn is_preview_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    if c.is_control() {
        return false;
    }
    if matches!(
        c,
        '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    ) {
        return false;
    }
    true
}

fn decode_legacy_unit(encoding: PreviewEncoding, slice: &[u8]) -> Option<char> {
    let enc = match encoding {
        PreviewEncoding::Gbk => encoding_rs::GBK,
        PreviewEncoding::Gb18030 => encoding_rs::GB18030,
        PreviewEncoding::Big5 => encoding_rs::BIG5,
        _ => return None,
    };
    let decoded = enc.decode_without_bom_handling_and_without_replacement(slice)?;
    let mut chars = decoded.chars();
    let ch = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    Some(ch)
}

fn decode_windows_1252_byte(byte: u8) -> char {
    if byte < 0x80 {
        return char::from(byte);
    }
    // Python cp1252 拒绝这 5 个未定义码位，统一映射为替换字符。
    if matches!(byte, 0x81 | 0x8D | 0x8F | 0x90 | 0x9D) {
        return '\u{FFFD}';
    }
    let slice = [byte];
    let (cow, _) = encoding_rs::WINDOWS_1252.decode_without_bom_handling(&slice);
    cow.chars().next().unwrap_or('\u{FFFD}')
}

/// 解码从字节偏移 `start` 开始的 [`PageWindow`] 中的字符，返回
/// `(offset_within_page, decoded_char)` 对（对应 `forensic/core/preview.py::page_characters`）。
pub fn page_characters(
    window: &PageWindow,
    start: u64,
    size: u64,
    encoding: PreviewEncoding,
    page_bytes: usize,
) -> Vec<(usize, char)> {
    let raw = &window.bytes;
    let prefix = start.min(3) as usize;
    let length = size.saturating_sub(start).min(page_bytes as u64) as usize;
    if length == 0 || raw.is_empty() {
        return Vec::new();
    }

    let mut index: usize = if encoding.is_utf16() {
        let left = start - (prefix as u64);
        if left.is_multiple_of(2) { 0 } else { 1 }
    } else if encoding.is_legacy_multibyte() {
        let effective_carry = if window.encoding == encoding {
            window.carry.min(prefix)
        } else {
            0
        };
        prefix - effective_carry
    } else {
        0
    };

    let mut out = Vec::with_capacity(length);
    while index < raw.len() && (index as isize - prefix as isize) < (length as isize) {
        let byte = raw[index];
        let mut step: usize = 1;
        let ch: char = match encoding {
            PreviewEncoding::Ascii => {
                if byte < 128 {
                    char::from(byte)
                } else {
                    '·'
                }
            }
            PreviewEncoding::Iso8859_1 => char::from(byte),
            PreviewEncoding::Windows1252 => decode_windows_1252_byte(byte),
            PreviewEncoding::Utf16Le | PreviewEncoding::Utf16Be => {
                if index + 2 > raw.len() {
                    step = 2;
                    '\u{FFFD}'
                } else {
                    let unit = if encoding == PreviewEncoding::Utf16Le {
                        u16::from_le_bytes([raw[index], raw[index + 1]])
                    } else {
                        u16::from_be_bytes([raw[index], raw[index + 1]])
                    };
                    if (0xD800..=0xDBFF).contains(&unit) {
                        if index + 4 <= raw.len() {
                            let low = if encoding == PreviewEncoding::Utf16Le {
                                u16::from_le_bytes([raw[index + 2], raw[index + 3]])
                            } else {
                                u16::from_be_bytes([raw[index + 2], raw[index + 3]])
                            };
                            match char::decode_utf16([unit, low]).next() {
                                Some(Ok(c)) => {
                                    step = 4;
                                    c
                                }
                                _ => {
                                    step = 2;
                                    '\u{FFFD}'
                                }
                            }
                        } else {
                            step = 2;
                            '\u{FFFD}'
                        }
                    } else {
                        step = 2;
                        match char::decode_utf16([unit]).next() {
                            Some(Ok(c)) => c,
                            _ => '\u{FFFD}',
                        }
                    }
                }
            }
            PreviewEncoding::Utf8 => {
                if byte < 0x80 {
                    char::from(byte)
                } else if byte >= 0xC2 {
                    let cand_step = if byte < 0xE0 {
                        2
                    } else if byte < 0xF0 {
                        3
                    } else {
                        4
                    };
                    if index + cand_step <= raw.len()
                        && let Ok(s) = std::str::from_utf8(&raw[index..index + cand_step])
                        && let Some(c) = s.chars().next()
                    {
                        step = cand_step;
                        c
                    } else {
                        step = 1;
                        '\u{FFFD}'
                    }
                } else {
                    step = 1;
                    '\u{FFFD}'
                }
            }
            PreviewEncoding::Gbk | PreviewEncoding::Gb18030 | PreviewEncoding::Big5 => {
                if byte < 0x80 {
                    char::from(byte)
                } else if (0x81..=0xFE).contains(&byte) {
                    let cand_step = if encoding == PreviewEncoding::Gb18030
                        && index + 1 < raw.len()
                        && (0x30..=0x39).contains(&raw[index + 1])
                    {
                        4
                    } else {
                        2
                    };
                    if index + cand_step <= raw.len()
                        && let Some(c) = decode_legacy_unit(encoding, &raw[index..index + cand_step])
                    {
                        step = cand_step;
                        c
                    } else {
                        step = 1;
                        '\u{FFFD}'
                    }
                } else {
                    step = 1;
                    '\u{FFFD}'
                }
            }
        };

        if index >= prefix {
            out.push((index - prefix, ch));
        }
        index += step;
    }

    out
}

fn render_text_from_chars(chars: &[(usize, char)]) -> String {
    let mut out = String::with_capacity(chars.len());
    for &(_, ch) in chars {
        if is_preview_printable(ch) || matches!(ch, '\r' | '\n' | '\t') {
            out.push(ch);
        } else {
            out.push('·');
        }
    }
    out
}

/// 将 [`PageWindow`] 格式化为预览文本（保留 `\r`、`\n`、`\t`，其余不可打印字符替换为 `·`）。
pub fn preview_text(
    window: &PageWindow,
    start: u64,
    size: u64,
    encoding: PreviewEncoding,
    page_bytes: usize,
) -> String {
    let chars = page_characters(window, start, size, encoding, page_bytes);
    render_text_from_chars(&chars)
}

fn render_rows_from_chars(
    window: &PageWindow,
    start: u64,
    size: u64,
    page_bytes: usize,
    chars: &[(usize, char)],
) -> Vec<HexRow> {
    let prefix = start.min(3) as usize;
    let avail = size.saturating_sub(start).min(page_bytes as u64) as usize;
    if avail == 0 || prefix > window.bytes.len() {
        return Vec::new();
    }
    let data_end = (prefix + avail).min(window.bytes.len());
    let data = &window.bytes[prefix..data_end];
    let row_count = data.len().div_ceil(ROW_BYTES);
    let mut char_rows: Vec<String> = vec![String::new(); row_count];

    for &(offset, ch) in chars {
        let row_idx = offset / ROW_BYTES;
        if row_idx < char_rows.len() {
            char_rows[row_idx].push(if is_preview_printable(ch) { ch } else { '·' });
        }
    }

    let mut rows = Vec::with_capacity(row_count);
    for (row_idx, chars_row) in char_rows.into_iter().enumerate() {
        let i = row_idx * ROW_BYTES;
        let slice = &data[i..(i + ROW_BYTES).min(data.len())];
        let mut bytes_hex = String::with_capacity(slice.len().saturating_mul(3));
        for (j, &b) in slice.iter().enumerate() {
            if j > 0 {
                bytes_hex.push(' ');
            }
            const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
            bytes_hex.push(HEX_UPPER[(b >> 4) as usize] as char);
            bytes_hex.push(HEX_UPPER[(b & 0x0F) as usize] as char);
        }
        rows.push(HexRow {
            offset_hex: format!("{:08X}", start + i as u64),
            bytes_hex,
            chars: chars_row,
        });
    }
    rows
}

/// 将 [`PageWindow`] 格式化为 16 字节 HEX 预览行（`offsetHex`、`bytesHex`、`chars`）。
pub fn preview_rows(
    window: &PageWindow,
    start: u64,
    size: u64,
    encoding: PreviewEncoding,
    page_bytes: usize,
) -> Vec<HexRow> {
    let chars = page_characters(window, start, size, encoding, page_bytes);
    render_rows_from_chars(window, start, size, page_bytes, &chars)
}

/// 使用 `0x00..=0x2F` 安全锚点重同步，计算字节偏移 `start` 紧邻之前的传统多字节编码
/// （`GBK` / `GB18030` / `Big5`）进位长度（0..=3 字节）（对应 `core-contract.md` §3.7）。
pub fn compute_legacy_carry<F>(
    start: u64,
    encoding: PreviewEncoding,
    checkpoint: Option<(PreviewEncoding, u64, Vec<u8>)>,
    mut read_at: F,
) -> CoreResult<(usize, Vec<u8>)>
where
    F: FnMut(u64, usize) -> CoreResult<Vec<u8>>,
{
    if start == 0 || !encoding.is_legacy_multibyte() {
        return Ok((0, Vec::new()));
    }

    let mut lower: u64 = 0;
    let mut pending: Vec<u8> = Vec::new();
    if let Some((cp_enc, cp_off, cp_pending)) = checkpoint
        && cp_enc == encoding
        && cp_off <= start
    {
        lower = cp_off;
        pending = cp_pending;
    }

    // 以 64 KiB 为步长向前回溯，查找最右侧落在 0x00..=0x2F 的字节；该范围字节在 GBK/GB18030/Big5 中绝不会作为尾字节出现。
    let mut pos = start;
    while pos > lower {
        let left = pos.saturating_sub(65536).max(lower);
        let len = (pos - left) as usize;
        let block = read_at(left, len)?;
        if let Some(rel) = block.iter().rposition(|&b| b <= 0x2F) {
            lower = left + (rel as u64) + 1;
            pending.clear();
            break;
        }
        pos = left;
    }

    // 从 `lower` 向前推进到 `start`，按 64 KiB 分块延续未闭合的前导字节。
    let mut carry_bytes = pending;
    while lower < start {
        let want = (start - lower).min(65536) as usize;
        let chunk = read_at(lower, want)?;
        if chunk.is_empty() {
            return Err(CoreError::Preview("无法读取预览页前的编码边界".to_string()));
        }
        let mut buf = Vec::with_capacity(carry_bytes.len() + chunk.len());
        buf.extend_from_slice(&carry_bytes);
        buf.extend_from_slice(&chunk);
        carry_bytes = step_legacy_carry(encoding, &buf);
        lower += chunk.len() as u64;
    }

    Ok((carry_bytes.len(), carry_bytes))
}

fn step_legacy_carry(encoding: PreviewEncoding, buf: &[u8]) -> Vec<u8> {
    let mut i = 0usize;
    let n = buf.len();
    while i < n {
        let b = buf[i];
        if b < 0x80 {
            i += 1;
            continue;
        }
        if (0x81..=0xFE).contains(&b) {
            if i + 1 == n {
                return buf[i..].to_vec();
            }
            if encoding == PreviewEncoding::Gb18030 && (0x30..=0x39).contains(&buf[i + 1]) {
                if i + 4 <= n {
                    if decode_legacy_unit(encoding, &buf[i..i + 4]).is_some() {
                        i += 4;
                    } else {
                        i += 1;
                    }
                } else {
                    // 可能是 4 字节 GB18030 序列末尾残留的 2 或 3 个字节。
                    let rem = n - i;
                    if rem == 2 || (rem == 3 && (0x81..=0xFE).contains(&buf[i + 2])) {
                        return buf[i..].to_vec();
                    }
                    i += 1;
                }
            } else if decode_legacy_unit(encoding, &buf[i..i + 2]).is_some() {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    Vec::new()
}

/// 通过扩展名白名单或魔数头嗅探判断文件是否属于图片预览候选对象（对应 `core-contract.md` §3.7）。
/// 未启用 `image-preview` 特性时仅按扩展名白名单判断。
pub fn is_image_candidate(path: &str, head_bytes: &[u8]) -> bool {
    let lower = path.to_ascii_lowercase();
    if IMAGE_SUFFIXES.iter().any(|ext| lower.ends_with(ext)) {
        return true;
    }
    #[cfg(feature = "image-preview")]
    {
        !head_bytes.is_empty() && image::guess_format(head_bytes).is_ok()
    }
    #[cfg(not(feature = "image-preview"))]
    {
        let _ = head_bytes;
        false
    }
}

/// 在严格的 32 MiB / 4000 万像素安全上限下解码图片载荷，支持 4096 px 降采样、
/// 动图首帧处理及 PNG base64 Data URL 生成（对应 `core-contract.md` §3.7）。
#[cfg(feature = "image-preview")]
pub fn decode_image_preview(
    raw_bytes: &[u8],
    entry: &InventoryEntry,
    read_note: &str,
) -> ImagePreviewResult {
    let source_note = deleted_source_note(entry).to_string();
    let fail = |msg: String| ImagePreviewResult {
        ok: false,
        data_url: None,
        png_bytes: Vec::new(),
        width: None,
        height: None,
        display_width: None,
        display_height: None,
        animated: false,
        error: Some(msg),
        read_note: read_note.to_string(),
        source_note: source_note.clone(),
    };

    if entry.size > MAX_IMAGE_BYTES || (raw_bytes.len() as u64) > MAX_IMAGE_BYTES {
        return fail("图片超过 32 MiB 预览上限，可导出后查看".to_string());
    }

    let reader = match ImageReader::new(Cursor::new(raw_bytes)).with_guessed_format() {
        Ok(r) => r,
        Err(_) => return fail("图片损坏或格式不受支持".to_string()),
    };
    let format = reader.format();
    let (w, h) = match reader.into_dimensions() {
        Ok((w, h)) if w > 0 && h > 0 => (w, h),
        _ => return fail("图片损坏或格式不受支持".to_string()),
    };

    if (w as u64).saturating_mul(h as u64) > MAX_IMAGE_PIXELS {
        return fail("图片超过 4000 万像素预览上限，可导出后查看".to_string());
    }

    let animated = detect_animated(raw_bytes, format);

    let decoded = match ImageReader::new(Cursor::new(raw_bytes))
        .with_guessed_format()
        .and_then(|r| r.decode().map_err(std::io::Error::other))
    {
        Ok(img) => img,
        Err(err) => return fail(format!("图片解码失败：{err}")),
    };

    let display_img = if w.max(h) > MAX_IMAGE_DIM {
        decoded.resize(MAX_IMAGE_DIM, MAX_IMAGE_DIM, FilterType::Triangle)
    } else {
        decoded
    };
    let (dw, dh) = (display_img.width(), display_img.height());

    let mut png_bytes = Vec::new();
    if let Err(err) = display_img.write_to(&mut Cursor::new(&mut png_bytes), ImageFormat::Png) {
        return fail(format!("图片转码 PNG 失败：{err}"));
    }
    let data_url = format!("data:image/png;base64,{}", BASE64_STANDARD.encode(&png_bytes));

    ImagePreviewResult {
        ok: true,
        data_url: Some(data_url),
        png_bytes,
        width: Some(w),
        height: Some(h),
        display_width: Some(dw),
        display_height: Some(dh),
        animated,
        error: None,
        read_note: read_note.to_string(),
        source_note,
    }
}

#[cfg(feature = "image-preview")]
fn detect_animated(raw_bytes: &[u8], format: Option<ImageFormat>) -> bool {
    match format {
        Some(ImageFormat::Gif) => {
            if let Ok(dec) = image::codecs::gif::GifDecoder::new(Cursor::new(raw_bytes)) {
                return dec.into_frames().take(2).count() > 1;
            }
            false
        }
        Some(ImageFormat::WebP) => {
            if let Ok(dec) = image::codecs::webp::WebPDecoder::new(Cursor::new(raw_bytes)) {
                return dec.has_animation();
            }
            false
        }
        Some(ImageFormat::Png) => {
            if let Ok(dec) = image::codecs::png::PngDecoder::new(Cursor::new(raw_bytes)) {
                return dec.is_apng().unwrap_or(false);
            }
            false
        }
        _ => false,
    }
}

enum PreviewBackend {
    Extents {
        file: File,
        extents: Vec<(u64, u64)>,
        cum_offsets: Vec<u64>,
        total_size: u64,
    },
    Volume {
        reader: VolumeReader,
        total_size: u64,
    },
    Cached {
        cache: File,
        total_size: u64,
        read_note: String,
    },
}

/// 有状态的预览读取器，按文件特性路由至 FAT 空间区域 extents、进程内 [`VolumeReader`]
/// 随机读取（`>= 8 MiB` 常规文件）或 `icat` 流式临时缓存（并在顺序翻页时复用传统多字节进位检查点）。
pub struct PreviewSession {
    entry: InventoryEntry,
    backend: PreviewBackend,
    checkpoint: Option<(PreviewEncoding, u64, Vec<u8>)>,
}

impl PreviewSession {
    /// 为镜像 `image` 内的 `entry` 打开一个 [`PreviewSession`]。
    pub fn open(image: &Path, entry: &InventoryEntry, tsk: Option<&TskCli>) -> CoreResult<Self> {
        if entry.directory || entry.mode.starts_with("V/") {
            return Err(CoreError::InvalidInput(format!(
                "{} 是目录，无法按文件内容预览。",
                entry.path
            )));
        }
        if !image.is_file() {
            return Err(CoreError::NotFound(format!(
                "案件记录的镜像不存在：{}",
                image.display()
            )));
        }

        // 路由 1：FAT 空间区域 extents。
        if let Some(ref extents) = entry.extents {
            let file = File::open(image)?;
            let mut cum = Vec::with_capacity(extents.len() + 1);
            cum.push(0u64);
            let mut acc = 0u64;
            for &(_, len) in extents {
                acc = acc.saturating_add(len);
                cum.push(acc);
            }
            return Ok(Self {
                entry: entry.clone(),
                backend: PreviewBackend::Extents {
                    file,
                    extents: extents.clone(),
                    cum_offsets: cum,
                    total_size: acc,
                },
                checkpoint: None,
            });
        }

        // 路由 2：未删除的大体积常规文件优先使用 `VolumeReader` 随机读取。
        if entry.size >= RANDOM_READ_MIN_BYTES
            && !entry.deleted
            && entry.mode.starts_with("r/")
            && let Ok(mut vol) = VolumeReader::open(image)
            && vol.read_entry_at(entry, 0, 1).is_ok()
        {
            return Ok(Self {
                entry: entry.clone(),
                backend: PreviewBackend::Volume {
                    reader: vol,
                    total_size: entry.size,
                },
                checkpoint: None,
            });
        }

        // 路由 3：其余文件与已删除条目通过 `icat` 流式写入临时缓存文件。
        let mut cache = tempfile::tempfile()?;
        if entry.size == 0 {
            return Ok(Self {
                entry: entry.clone(),
                backend: PreviewBackend::Cached {
                    cache,
                    total_size: 0,
                    read_note: String::new(),
                },
                checkpoint: None,
            });
        }

        let discovered;
        let tool = match tsk {
            Some(t) => t,
            None => {
                discovered = TskCli::discover(None)?;
                &discovered
            }
        };
        let (written, raw_note) = tool.stream_entry(image, entry, None, |chunk| {
            cache.write_all(chunk)?;
            Ok(())
        })?;
        cache.flush()?;
        let read_note = if entry.deleted && written < entry.size {
            if raw_note.is_empty() {
                format!("可读 {written} / {} 字节", entry.size)
            } else {
                format!("可读 {written} / {} 字节 · {raw_note}", entry.size)
            }
        } else {
            raw_note
        };

        Ok(Self {
            entry: entry.clone(),
            backend: PreviewBackend::Cached {
                cache,
                total_size: written,
                read_note,
            },
            checkpoint: None,
        })
    }

    pub fn readable_size(&self) -> u64 {
        match &self.backend {
            PreviewBackend::Extents { total_size, .. } => *total_size,
            PreviewBackend::Volume { total_size, .. } => *total_size,
            PreviewBackend::Cached { total_size, .. } => *total_size,
        }
    }

    pub fn read_note(&self) -> &str {
        match &self.backend {
            PreviewBackend::Cached { read_note, .. } => read_note,
            _ => "",
        }
    }

    /// 精确读取 `[offset, offset + len)` 范围内的字节（自动截断至 `readable_size`）。
    pub fn read_at(&mut self, offset: u64, len: usize) -> CoreResult<Vec<u8>> {
        let total = self.readable_size();
        if offset >= total || len == 0 {
            return Ok(Vec::new());
        }
        let want = (total - offset).min(len as u64) as usize;
        match &mut self.backend {
            PreviewBackend::Extents {
                file,
                extents,
                cum_offsets,
                ..
            } => {
                let mut cur = offset;
                let end = offset + want as u64;
                let mut idx = cum_offsets
                    .partition_point(|&off| off <= cur)
                    .saturating_sub(1);
                let mut out = vec![0u8; want];
                let mut out_pos = 0usize;
                while cur < end {
                    let seg_end = cum_offsets[idx + 1];
                    let take = (end.min(seg_end) - cur) as usize;
                    if take > 0 {
                        let phys = extents[idx].0 + (cur - cum_offsets[idx]);
                        file.seek(SeekFrom::Start(phys))?;
                        file.read_exact(&mut out[out_pos..out_pos + take]).map_err(|_| {
                            CoreError::Preview("空间区域超出当前镜像，请重新读取文件树".to_string())
                        })?;
                        out_pos += take;
                        cur += take as u64;
                    }
                    idx += 1;
                }
                Ok(out)
            }
            PreviewBackend::Volume { reader, .. } => {
                Ok(reader.read_entry_at(&self.entry, offset, want)?)
            }
            PreviewBackend::Cached { cache, .. } => {
                cache.seek(SeekFrom::Start(offset))?;
                let mut buf = vec![0u8; want];
                let mut filled = 0usize;
                while filled < want {
                    let n = cache.read(&mut buf[filled..])?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                buf.truncate(filled);
                Ok(buf)
            }
        }
    }

    /// 按给定的 `page_bytes` 与 `encoding` 读取并渲染从 0 开始的第 `page` 页。
    pub fn read_page(
        &mut self,
        page: usize,
        page_bytes: usize,
        encoding: PreviewEncoding,
    ) -> CoreResult<PreviewPageResult> {
        let pb = page_bytes.max(1);
        let size = self.readable_size();
        let total_pages = if size == 0 {
            1
        } else {
            size.div_ceil(pb as u64) as usize
        };
        let clamped_page = page.min(total_pages - 1);
        let start = (clamped_page as u64).saturating_mul(pb as u64);
        let left = start.saturating_sub(3);
        let right = start.saturating_add(pb as u64).saturating_add(3).min(size);
        let bytes = self.read_at(left, (right - left) as usize)?;

        let carry = if start > 0 && encoding.is_legacy_multibyte() {
            let cp = self.checkpoint.clone();
            let (c_len, c_bytes) =
                compute_legacy_carry(start, encoding, cp, |off, len| self.read_at(off, len))?;
            self.checkpoint = Some((encoding, start, c_bytes));
            c_len
        } else {
            0
        };

        let window = PageWindow {
            bytes,
            carry,
            encoding,
        };
        let head_slice = if clamped_page == 0 {
            &window.bytes[..]
        } else {
            &[]
        };
        let is_image = is_image_candidate(&self.entry.path, head_slice);
        // 仅解码一次字符流并同时用于正文与 HEX 行渲染，避免多字节编码重复解码。
        let chars = page_characters(&window, start, size, encoding, pb);
        let text = render_text_from_chars(&chars);
        let hex_rows = render_rows_from_chars(&window, start, size, pb, &chars);

        Ok(PreviewPageResult {
            page: clamped_page,
            total_pages,
            page_bytes: pb,
            byte_start: start,
            byte_end: (start + pb as u64).min(size),
            readable_size: size,
            recorded_size: self.entry.size,
            read_note: self.read_note().to_string(),
            source_note: deleted_source_note(&self.entry).to_string(),
            encoding: encoding.as_str().to_string(),
            text,
            hex_rows,
            is_image_candidate: is_image,
        })
    }

    /// 将完整条目解码为图片预览（受 32 MiB / 4000 万像素 / 4096 px 安全上限约束）。
    #[cfg(feature = "image-preview")]
    pub fn read_image(&mut self) -> CoreResult<ImagePreviewResult> {
        let size = self.readable_size();
        if self.entry.size > MAX_IMAGE_BYTES || size > MAX_IMAGE_BYTES {
            return Ok(decode_image_preview(&[], &self.entry, self.read_note()));
        }
        let raw = self.read_at(0, size as usize)?;
        Ok(decode_image_preview(&raw, &self.entry, self.read_note()))
    }
}

/// 一次性便捷函数：预览 `image` 内单个条目的指定页。
pub fn preview_entry_page(
    image: &Path,
    entry: &InventoryEntry,
    page: usize,
    page_bytes: usize,
    encoding: PreviewEncoding,
    tsk: Option<&TskCli>,
) -> CoreResult<PreviewPageResult> {
    let mut session = PreviewSession::open(image, entry, tsk)?;
    session.read_page(page, page_bytes, encoding)
}

/// 一次性便捷函数：解码 `image` 内 `entry` 的图片预览。
#[cfg(feature = "image-preview")]
pub fn preview_entry_image(
    image: &Path,
    entry: &InventoryEntry,
    tsk: Option<&TskCli>,
) -> CoreResult<ImagePreviewResult> {
    let mut session = PreviewSession::open(image, entry, tsk)?;
    session.read_image()
}

/// 为需要同时校验镜像存在性的外部调用方返回镜像路径。
pub fn validate_preview_image_path(image: &Path) -> CoreResult<PathBuf> {
    if !image.is_file() {
        return Err(CoreError::NotFound(format!(
            "案件记录的镜像不存在：{}",
            image.display()
        )));
    }
    Ok(image.to_path_buf())
}
