use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use crate::error::{EngineError, EngineResult};
use crate::win::{file_identity_from_file, file_identity_from_path};

const STREAM_BUF_MAX: usize = 4 << 20; // 4 MiB

/// Convert raw SHA-256 bytes into a 64-character lowercase hexadecimal string.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Streaming SHA-256 with a reusable 4 MiB buffer, pre/post metadata identity verification,
/// cooperative cancellation, and progress callback `(bytes_done, total_bytes)`.
pub fn sha256_file(
    path: &Path,
    cancel: Option<&AtomicBool>,
    progress: Option<&(dyn Fn(u64, u64) + Sync)>,
) -> EngineResult<String> {
    let mut file = File::open(path)?;
    let before = file_identity_from_file(&file)?;
    let buf_len = (before.size.max(1) as usize).min(STREAM_BUF_MAX);
    let mut buf = vec![0u8; buf_len];

    let mut hasher = Sha256::new();
    let mut done: u64 = 0;

    loop {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消计算文件哈希".to_string()));
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        done += n as u64;
        if let Some(cb) = progress {
            cb(done, before.size);
        }
    }

    let after = file_identity_from_file(&file)?;
    drop(file);
    let current = file_identity_from_path(path)?;
    if before != after || before != current {
        return Err(EngineError::SourceChanged(
            "哈希计算期间证据发生变化，请停止分析".to_string(),
        ));
    }

    Ok(hex_lower(&hasher.finalize()))
}
