use serde::{Deserialize, Serialize};

/// Snapshot of a source file's identity and metadata for tamper/change detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStamp {
    pub name: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
}

impl FileStamp {
    /// Tuple representation matching legacy Python `case.json` `source_stamp` entries.
    pub fn as_tuple(&self) -> (&str, u64, i64, u64) {
        (&self.name, self.size, self.mtime_ns, self.ino)
    }
}

/// Partition entry parsed from `mmls` (or offset 0 fallback via `fsstat`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub offset: u64,
    pub description: String,
}

/// Physical segment digest for EWF images.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentDigest {
    pub name: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
}

/// Half-open byte interval `[start, end)` within a logical file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteInterval {
    pub start: u64,
    pub end: u64,
}

/// Read plan produced by [`crate::VolumeReader::plan_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryReadPlan {
    Direct {
        intervals: Vec<ByteInterval>,
        total_size: u64,
    },
    FallbackToIcat,
}

/// Single inventory record matching `core-contract.md` §2.2 byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub path: String,
    pub inode: String,
    pub mode: String,
    pub size: u64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub reallocated: bool,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub crtime: i64,
    pub directory: bool,
    pub offset: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub filesystem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_cluster_allocated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extents: Option<Vec<(u64, u64)>>,
}

/// Returns the Chinese display status label for an inventory entry (`core-contract.md` §3.4).
pub fn entry_status(entry: &InventoryEntry) -> &'static str {
    if entry.deleted {
        if entry.reallocated {
            "已删除·重分配"
        } else {
            "已删除"
        }
    } else if entry.mode.starts_with("V/") {
        "虚拟目录"
    } else if entry.mode.starts_with("v/") {
        "系统区域"
    } else {
        "现存"
    }
}

/// Whether the entry can be exported or content-searched (`core-contract.md` §3.4).
pub fn can_export(entry: &InventoryEntry) -> bool {
    !entry.directory
        && (entry.mode.starts_with("r/") || (entry.deleted && entry.mode.starts_with("-/r")))
}

/// Explanation note for deleted entries (`core-contract.md` §3.4).
pub fn deleted_source_note(entry: &InventoryEntry) -> &'static str {
    if entry.reallocated {
        "已删除 · inode 已重分配，数据来自该 inode 当前内容"
    } else if entry.start_cluster_allocated == Some(true) {
        "已删除 · 起始簇已被占用，原内容可能已覆盖"
    } else if entry.deleted {
        "已删除，原内容可能已覆盖"
    } else {
        ""
    }
}

/// Display name for an entry, including special system names (`$MBR`, `$FATn`).
pub fn entry_name(entry: &InventoryEntry) -> String {
    let name = entry.path.rsplit('/').next().unwrap_or(&entry.path);
    if entry.mode.starts_with("v/") {
        if name == "$MBR" {
            return "引导扇区 ($MBR)".to_string();
        }
        if let Some(digits) = name.strip_prefix("$FAT")
            && !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
        {
            return format!("FAT {digits} ({name})");
        }
    }
    name.to_string()
}
