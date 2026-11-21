use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use crate::error::{EngineError, EngineResult};

/// Thread-safe 64-bit read-only random-access interface over a logical forensic media image
/// (RAW `.dd`/`.img` or multi-segment EWF1 `.E01`).
pub trait MediaReader: Send + Sync {
    /// Total logical size of the media in bytes.
    fn media_size(&self) -> u64;

    /// Read exactly `buf.len()` bytes starting at logical byte `offset`.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> EngineResult<()>;
}

/// Platform-portable positional exact read using `&File` without mutating user-space seek state.
pub(crate) fn file_read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> EngineResult<()> {
    #[cfg(windows)]
    use std::os::windows::fs::FileExt;
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;

    while !buf.is_empty() {
        #[cfg(windows)]
        let n = file.seek_read(buf, offset)?;
        #[cfg(unix)]
        let n = file.read_at(buf, offset)?;

        if n == 0 {
            return Err(EngineError::RandomRead(format!(
                "原始介质在偏移 {offset} 处发生短读"
            )));
        }
        offset = offset.checked_add(n as u64).ok_or_else(|| {
            EngineError::RandomRead("介质读取偏移溢出".to_string())
        })?;
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Thread-safe 64-bit random reader for raw forensic disk/volume images.
pub struct RawMediaReader {
    file: File,
    size: u64,
}

impl RawMediaReader {
    pub fn open(path: &Path) -> EngineResult<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self { file, size })
    }
}

impl MediaReader for RawMediaReader {
    fn media_size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> EngineResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| EngineError::RandomRead("读取范围溢出".to_string()))?;
        if end > self.size {
            return Err(EngineError::RandomRead(format!(
                "读取范围 [{offset}, {end}) 超出镜像大小 {}",
                self.size
            )));
        }
        file_read_exact_at(&self.file, offset, buf)
    }
}

/// Open a RAW or EWF1 (`.E01`) image as a thread-safe [`MediaReader`].
pub fn open_media(image: &Path) -> EngineResult<Arc<dyn MediaReader>> {
    let is_e01 = image
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("e01"));
    if is_e01 {
        Ok(Arc::new(crate::ewf::EwfMediaReader::open(image)?))
    } else {
        Ok(Arc::new(RawMediaReader::open(image)?))
    }
}
