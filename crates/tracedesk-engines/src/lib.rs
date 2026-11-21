//! TraceDesk low-level forensic engines:
//! - Windows native source protection (`SourceGuard`), cross-process `CaseFileLock`, and CP_ACP decoding
//! - Streaming 4 MiB SHA-256 with pre/post identity verification (`sha256_file`)
//! - Strictly whitelisted read-only Sleuth Kit CLI adapter (`TskCli`)
//! - Pure Rust multi-core EWF1 parallel decoder & random reader (`ewf`)
//! - Ultra-fast native FAT12/16/32 region mapper (`map_fat_regions`) and cluster reader
//! - Thread-safe 64-bit `MediaReader` and in-process NTFS/FAT `VolumeReader`

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

/// Standard forensic disk sector size in bytes.
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
