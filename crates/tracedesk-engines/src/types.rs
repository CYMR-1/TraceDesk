use serde::{Deserialize, Serialize};

/// 用于篡改与变更检测的源文件标识及元数据快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStamp {
    pub name: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
}

impl FileStamp {
    /// 与旧版 Python `case.json` 中 `source_stamp` 条目对齐的元组表示。
    pub fn as_tuple(&self) -> (&str, u64, i64, u64) {
        (&self.name, self.size, self.mtime_ns, self.ino)
    }
}

/// 从 `mmls` 解析得到的分区信息（或经由 `fsstat` 回退到偏移 0）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub offset: u64,
    pub description: String,
}

/// EWF 镜像的物理分段摘要信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentDigest {
    pub name: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
}

/// 逻辑文件内的左闭右开字节区间 `[start, end)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteInterval {
    pub start: u64,
    pub end: u64,
}

/// 由 [`crate::VolumeReader::plan_entry`] 生成的读取计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryReadPlan {
    Direct {
        intervals: Vec<ByteInterval>,
        total_size: u64,
    },
    FallbackToIcat,
}

/// 与 `core-contract.md` §2.2 逐字节一致的单条目录清单记录。
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

/// 返回目录清单条目的中文状态显示标签（见 `core-contract.md` §3.4）。
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

/// 判断条目是否支持导出或内容检索（见 `core-contract.md` §3.4）。
pub fn can_export(entry: &InventoryEntry) -> bool {
    !entry.directory
        && (entry.mode.starts_with("r/") || (entry.deleted && entry.mode.starts_with("-/r")))
}

/// 返回已删除条目的来源说明（见 `core-contract.md` §3.4）。
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

/// 返回条目的显示名称，包含特殊系统项（`$MBR`、`$FATn`）的友好名称。
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
