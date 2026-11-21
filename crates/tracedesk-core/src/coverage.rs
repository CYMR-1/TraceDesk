//! Declared volume coverage assessment and evidence provenance validation
//! (`core-contract.md` §3.2, matching `forensic/core/coverage.py`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracedesk_engines::{PartitionInfo, SECTOR_SIZE};

use crate::case::EvidenceInfo;
use crate::error::{CoreError, CoreResult};

static MMLS_RANGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*\d+:\s+\d+(?::\d+)?\s+(\d+)\s+(\d+)\s+\d+").expect("valid mmls range re")
});
static HEX_SHA256_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{64}$").expect("valid sha256 regex"));

/// Ordered 5 provenance metadata fields (`key`, `Chinese label`).
pub const SOURCE_FIELDS: [(&str, &str); 5] = [
    ("evidence_id", "证据编号"),
    ("source", "来源 / 交付方"),
    ("acquired", "采集时间与时区"),
    ("tool", "采集工具与版本"),
    ("expected_sha256", "交付方 SHA-256"),
];

/// Evidence provenance fields stored under `evidence.provenance` in `case.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default)]
    pub evidence_id: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub acquired: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub expected_sha256: String,
}

impl Provenance {
    /// Construct from a key/value map (such as `ewf::acquisition_info`).
    pub fn from_map(map: &HashMap<String, String>) -> Self {
        Self {
            evidence_id: map.get("evidence_id").cloned().unwrap_or_default(),
            source: map.get("source").cloned().unwrap_or_default(),
            acquired: map.get("acquired").cloned().unwrap_or_default(),
            tool: map.get("tool").cloned().unwrap_or_default(),
            expected_sha256: map.get("expected_sha256").cloned().unwrap_or_default(),
        }
    }

    /// Returns `true` when all 5 fields are empty.
    pub fn is_empty(&self) -> bool {
        self.evidence_id.is_empty()
            && self.source.is_empty()
            && self.acquired.is_empty()
            && self.tool.is_empty()
            && self.expected_sha256.is_empty()
    }

    /// Trim all fields and validate `expected_sha256` (must be 64 hex chars when non-empty).
    pub fn normalized_and_validated(&self) -> CoreResult<Self> {
        let clean = Self {
            evidence_id: self.evidence_id.trim().to_string(),
            source: self.source.trim().to_string(),
            acquired: self.acquired.trim().to_string(),
            tool: self.tool.trim().to_string(),
            expected_sha256: self.expected_sha256.trim().to_string(),
        };
        if !clean.expected_sha256.is_empty() && !HEX_SHA256_RE.is_match(&clean.expected_sha256) {
            return Err(CoreError::InvalidInput(
                "交付方 SHA-256 应为 64 位十六进制字符".to_string(),
            ));
        }
        Ok(clean)
    }

    /// Look up one of the 5 standard `SOURCE_FIELDS` keys.
    pub fn get_field(&self, key: &str) -> &str {
        match key {
            "evidence_id" => &self.evidence_id,
            "source" => &self.source,
            "acquired" => &self.acquired,
            "tool" => &self.tool,
            "expected_sha256" => &self.expected_sha256,
            _ => "",
        }
    }
}

/// Coverage assessment for a single partition / volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeCoverage {
    pub offset: u64,
    pub filesystem: String,
    pub partition_end: Option<u64>,
    pub volume_end: Option<u64>,
    pub missing_bytes: u64,
    pub status: String,
}

/// Image-wide declared coverage report stored under `evidence.coverage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub bytes: u64,
    pub volumes: Vec<VolumeCoverage>,
}

/// Assess declared partition & filesystem volume boundaries against actual/logical image size.
///
/// Mirrors `forensic/core/coverage.py::assess` byte-for-byte.
pub fn assess_coverage<F>(
    image: &Path,
    partitions: &[PartitionInfo],
    layout: &str,
    logical_size: Option<u64>,
    mut boot_reader: Option<F>,
) -> CoreResult<CoverageReport>
where
    F: FnMut(u64) -> Option<Vec<u8>>,
{
    let size = match logical_size {
        Some(sz) => sz,
        None => std::fs::metadata(image)?.len(),
    };

    let mut ends: HashMap<u64, u64> = HashMap::new();
    for caps in MMLS_RANGE_RE.captures_iter(layout) {
        if let (Ok(start), Ok(end)) = (caps[1].parse::<u64>(), caps[2].parse::<u64>())
            && let Some(end_bytes) = end.checked_add(1).and_then(|v| v.checked_mul(SECTOR_SIZE))
        {
            ends.insert(start, end_bytes);
        }
    }

    let mut source = if boot_reader.is_none() {
        Some(File::open(image)?)
    } else {
        None
    };

    let mut rows = Vec::with_capacity(partitions.len());
    for part in partitions {
        let offset = part.offset;
        let start = offset.saturating_mul(SECTOR_SIZE);
        let boot: Vec<u8> = if let Some(ref mut reader) = boot_reader {
            if start < size {
                reader(offset).unwrap_or_default()
            } else {
                Vec::new()
            }
        } else if let Some(ref mut file) = source {
            if start < size && file.seek(SeekFrom::Start(start)).is_ok() {
                let mut buf = vec![0u8; 512];
                let mut filled = 0usize;
                while filled < 512 {
                    match file.read(&mut buf[filled..]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(_) => break,
                    }
                }
                buf.truncate(filled);
                buf
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let mut volume_end: Option<u64> = None;
        let mut kind = "未知";
        if boot.len() == 512 && boot[510] == 0x55 && boot[511] == 0xaa {
            let sector = u16::from_le_bytes([boot[11], boot[12]]) as u64;
            let mut sectors: u64 = 0;
            if &boot[3..11] == b"NTFS    " {
                kind = "NTFS";
                sectors = u64::from_le_bytes([
                    boot[40], boot[41], boot[42], boot[43], boot[44], boot[45], boot[46], boot[47],
                ]);
            } else if &boot[54..62] == b"FAT12   "
                || &boot[54..62] == b"FAT16   "
                || &boot[82..90] == b"FAT32   "
            {
                kind = "FAT";
                let s16 = u16::from_le_bytes([boot[19], boot[20]]) as u64;
                sectors = if s16 != 0 {
                    s16
                } else {
                    u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]) as u64
                };
            }
            if sectors > 0 && matches!(sector, 512 | 1024 | 2048 | 4096) {
                volume_end = sectors
                    .checked_mul(sector)
                    .and_then(|bytes| start.checked_add(bytes));
            }
        }

        let partition_end = ends.get(&offset).copied();
        let declared = partition_end.unwrap_or(0).max(volume_end.unwrap_or(0));
        let status = if start >= size || declared > size {
            "声明范围超出镜像"
        } else if let (Some(pe), Some(ve)) = (partition_end, volume_end)
            && ve > pe
        {
            "卷声明超出分区边界"
        } else if volume_end.is_some() {
            "声明范围已覆盖"
        } else {
            "无法判定卷范围"
        };

        rows.push(VolumeCoverage {
            offset,
            filesystem: kind.to_string(),
            partition_end,
            volume_end,
            missing_bytes: declared.saturating_sub(size),
            status: status.to_string(),
        });
    }

    Ok(CoverageReport {
        bytes: size,
        volumes: rows,
    })
}

/// Format a [`CoverageReport`] into the standard Chinese summary text.
pub fn coverage_text(result: Option<&CoverageReport>) -> String {
    let Some(report) = result else {
        return "尚未评估；请运行完整性校验".to_string();
    };
    let joined = report
        .volumes
        .iter()
        .map(|r| {
            let declared = r.volume_end.unwrap_or(0).max(r.partition_end.unwrap_or(0));
            let decl_str = if declared > 0 {
                declared.to_string()
            } else {
                "未知".to_string()
            };
            format!(
                "偏移 {} 扇区：{}（{}，声明结束字节位置 {}，镜像 {} 字节）",
                r.offset, r.status, r.filesystem, decl_str, report.bytes
            )
        })
        .collect::<Vec<_>>()
        .join("；");
    format!(
        "{joined}。仅判断可识别的声明范围，不能证明原盘无坏扇区或已完整采集。"
    )
}

/// Compare the local baseline SHA-256 against the provider's expected SHA-256 (`core-contract.md` §3.2).
pub fn source_status(evidence: &EvidenceInfo) -> &'static str {
    let expected = evidence
        .provenance
        .as_ref()
        .map(|p| p.expected_sha256.as_str())
        .unwrap_or("");
    let Some(local_hash) = evidence.sha256.as_deref().filter(|s| !s.is_empty()) else {
        return "本机整镜像 SHA-256 待固定";
    };
    if expected.is_empty() {
        return "未提供交付方摘要，仅有本机固定值";
    }
    if expected.eq_ignore_ascii_case(local_hash) {
        "交付方摘要与本机固定值一致"
    } else {
        "警告：交付方摘要与本机固定值不一致"
    }
}
