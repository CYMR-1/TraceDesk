//! TraceDesk 底层取证引擎：
//! - Windows 原生源证据保护（`SourceGuard`）、跨进程 `CaseFileLock` 以及 CP_ACP 解码
//! - 带操作前后文件标识校验的 4 MiB 流式 SHA-256 计算（`sha256_file`）
//! - 严格白名单约束的只读 Sleuth Kit CLI 适配器（`TskCli`）
//! - 纯 Rust 多核 EWF1 并行解码器与随机读取器（`ewf`）
//! - 高速原生 FAT12/16/32 区域映射器（`map_fat_regions`）与簇读取器
//! - 线程安全的 64 位 `MediaReader` 以及进程内 NTFS/FAT `VolumeReader`

pub mod error;
pub mod ewf;
pub mod fat;
pub mod hash;
pub mod media;
pub mod ntfs;
pub mod tsk;
pub mod types;
pub mod volume;
pub mod win;

/// 标准取证磁盘扇区大小（单位：字节）。
pub const SECTOR_SIZE: u64 = 512;

pub use error::{EngineError, EngineResult};
pub use fat::map_fat_regions;
pub use hash::sha256_file;
pub use media::{MediaReader, RawMediaReader, open_media};
pub use tsk::{TskCli, TskCommand};
pub use types::{
    ByteInterval, EntryReadPlan, FileStamp, InventoryEntry, PartitionInfo, SegmentDigest,
    can_export, deleted_source_note, entry_name, entry_status,
};
pub use volume::VolumeReader;
pub use win::{CaseFileLock, SourceGuard, decode_acp_lossy, decode_acp_strict};
