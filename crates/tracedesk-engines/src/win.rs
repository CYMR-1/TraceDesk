use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::error::{EngineError, EngineResult};
use crate::types::FileStamp;

/// Internal file identity snapshot used to verify a file was not modified or replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
    pub dev: u64,
}

/// Strip Windows verbatim prefix (`\\?\` or `\\?\UNC\`) so 32-bit TSK CLI tools accept paths.
pub(crate) fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(s) = path.to_str() {
            if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
                return PathBuf::from(format!(r"\\{unc}"));
            }
            if let Some(rest) = s.strip_prefix(r"\\?\") {
                return PathBuf::from(rest);
            }
        }
    }
    path.to_path_buf()
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::OsStr;
    use std::iter::once;
    use std::mem::zeroed;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Globalization::{CP_ACP, MB_ERR_INVALID_CHARS, MultiByteToWideChar};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, OPEN_ALWAYS,
        OPEN_EXISTING, UnlockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    /// Windows 100-nanosecond ticks between 1601-01-01 and 1970-01-01 UTC.
    const WINDOWS_EPOCH_OFFSET_100NS: i128 = 116_444_736_000_000_000;

    fn to_wide_null(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(once(0)).collect()
    }

    fn filetime_to_unix_ns(low: u32, high: u32) -> i64 {
        let ticks = ((high as u64) << 32) | (low as u64);
        let ns = (ticks as i128 - WINDOWS_EPOCH_OFFSET_100NS) * 100;
        ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }

    fn info_to_identity(info: &BY_HANDLE_FILE_INFORMATION) -> FileIdentity {
        FileIdentity {
            size: ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64),
            mtime_ns: filetime_to_unix_ns(
                info.ftLastWriteTime.dwLowDateTime,
                info.ftLastWriteTime.dwHighDateTime,
            ),
            ino: ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64),
            dev: info.dwVolumeSerialNumber as u64,
        }
    }

    /// RAII wrapper around a Win32 HANDLE that is safe to transfer across threads.
    pub(super) struct GuardHandle(HANDLE);

    // SAFETY: Win32 file handles are kernel objects whose lifetime is exclusively owned
    // by `GuardHandle` and closed once on `Drop`.
    unsafe impl Send for GuardHandle {}
    unsafe impl Sync for GuardHandle {}

    impl Drop for GuardHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` is an exclusively owned valid handle.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn query_handle_identity(handle: HANDLE) -> EngineResult<FileIdentity> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            return Err(EngineError::Io(io::Error::last_os_error()));
        }
        Ok(info_to_identity(&info))
    }

    pub(crate) fn file_identity_from_file(file: &File) -> EngineResult<FileIdentity> {
        query_handle_identity(file.as_raw_handle() as HANDLE)
    }

    pub(crate) fn file_identity_from_path(path: &Path) -> EngineResult<FileIdentity> {
        let wide = to_wide_null(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(EngineError::Io(io::Error::last_os_error()));
        }
        let guard = GuardHandle(handle);
        query_handle_identity(guard.0)
    }

    pub(super) fn open_source_guard_handle(path: &Path) -> EngineResult<GuardHandle> {
        let wide = to_wide_null(path.as_os_str());
        // FILE_SHARE_READ only: denies concurrent write and delete opens at the OS kernel level.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            return Err(EngineError::SourceGuard(format!(
                "无法取得镜像只读共享句柄，请关闭占用文件的写入程序：{}（{}）",
                path.display(),
                err
            )));
        }
        Ok(GuardHandle(handle))
    }

    pub(super) struct LockHandle {
        handle: HANDLE,
    }

    // SAFETY: `LockHandle` exclusively owns the Win32 file handle and unlocks/closes on Drop.
    unsafe impl Send for LockHandle {}
    unsafe impl Sync for LockHandle {}

    impl LockHandle {
        pub(super) fn acquire(lock_path: &Path) -> EngineResult<Self> {
            let wide = to_wide_null(lock_path.as_os_str());
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                let err = io::Error::last_os_error();
                return Err(EngineError::Locked(format!(
                    "案件已被占用或无法加锁：{err}"
                )));
            }
            let mut overlapped: OVERLAPPED = unsafe { zeroed() };
            let locked = unsafe {
                LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            };
            if locked == 0 {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(EngineError::Locked("案件已被占用或无法加锁".to_string()));
            }
            Ok(Self { handle })
        }
    }

    impl Drop for LockHandle {
        fn drop(&mut self) {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
                let mut overlapped: OVERLAPPED = unsafe { zeroed() };
                unsafe {
                    UnlockFileEx(self.handle, 0, 1, 0, &mut overlapped);
                    CloseHandle(self.handle);
                }
            }
        }
    }

    pub fn decode_acp_strict(bytes: &[u8]) -> EngineResult<String> {
        if bytes.is_empty() {
            return Ok(String::new());
        }
        let len = i32::try_from(bytes.len()).map_err(|_| {
            EngineError::Encoding("待解码的 CP_ACP 字节长度超过系统限制".to_string())
        })?;
        let wide_len = unsafe {
            MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                len,
                null_mut(),
                0,
            )
        };
        if wide_len <= 0 {
            let err = io::Error::last_os_error();
            return Err(EngineError::Encoding(format!(
                "CP_ACP 严格解码失败：包含无效字符序列（{err}）"
            )));
        }
        let mut wide = vec![0u16; wide_len as usize];
        let written = unsafe {
            MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                len,
                wide.as_mut_ptr(),
                wide_len,
            )
        };
        if written <= 0 {
            let err = io::Error::last_os_error();
            return Err(EngineError::Encoding(format!("CP_ACP 严格解码失败：{err}")));
        }
        wide.truncate(written as usize);
        String::from_utf16(&wide)
            .map_err(|e| EngineError::Encoding(format!("CP_ACP UTF-16 转换失败：{e}")))
    }

    pub fn decode_acp_lossy(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        // Chunk if extremely large so we never overflow i32.
        const MAX_CHUNK: usize = 64 * 1024 * 1024;
        if bytes.len() > MAX_CHUNK {
            let mut out = String::new();
            for chunk in bytes.chunks(MAX_CHUNK) {
                out.push_str(&decode_acp_lossy(chunk));
            }
            return out;
        }
        let len = bytes.len() as i32;
        let wide_len =
            unsafe { MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), len, null_mut(), 0) };
        if wide_len <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; wide_len as usize];
        let written = unsafe {
            MultiByteToWideChar(CP_ACP, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), wide_len)
        };
        if written <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        wide.truncate(written as usize);
        String::from_utf16_lossy(&wide)
    }

    pub(crate) fn create_buffered_pipe(buffer_size: u32) -> io::Result<(File, Stdio)> {
        let mut read_raw: HANDLE = null_mut();
        let mut write_raw: HANDLE = null_mut();
        let ok = unsafe { CreatePipe(&mut read_raw, &mut write_raw, null(), buffer_size) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `CreatePipe` succeeded and returned newly created exclusively owned handles.
        let read_owned = unsafe { OwnedHandle::from_raw_handle(read_raw as _) };
        let write_owned = unsafe { OwnedHandle::from_raw_handle(write_raw as _) };
        Ok((File::from(read_owned), Stdio::from(write_owned)))
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::time::UNIX_EPOCH;

    pub(super) struct GuardHandle(#[allow(dead_code)] File);
    pub(super) struct LockHandle(#[allow(dead_code)] File);

    fn meta_to_identity(meta: &fs::Metadata) -> FileIdentity {
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        FileIdentity {
            size: meta.len(),
            mtime_ns,
            ino: 0,
            dev: 0,
        }
    }

    pub(crate) fn file_identity_from_file(file: &File) -> EngineResult<FileIdentity> {
        Ok(meta_to_identity(&file.metadata()?))
    }

    pub(crate) fn file_identity_from_path(path: &Path) -> EngineResult<FileIdentity> {
        Ok(meta_to_identity(&fs::metadata(path)?))
    }

    pub(super) fn open_source_guard_handle(path: &Path) -> EngineResult<GuardHandle> {
        let file = File::open(path).map_err(|e| {
            EngineError::SourceGuard(format!("无法取得镜像只读共享句柄：{}（{}）", path.display(), e))
        })?;
        Ok(GuardHandle(file))
    }

    impl LockHandle {
        pub(super) fn acquire(lock_path: &Path) -> EngineResult<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .map_err(|e| EngineError::Locked(format!("案件已被占用或无法加锁：{e}")))?;
            Ok(Self(file))
        }
    }

    pub fn decode_acp_strict(bytes: &[u8]) -> EngineResult<String> {
        String::from_utf8(bytes.to_vec())
            .map_err(|e| EngineError::Encoding(format!("UTF-8 严格解码失败：{e}")))
    }

    pub fn decode_acp_lossy(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    pub(crate) fn create_buffered_pipe(_buffer_size: u32) -> io::Result<(File, Stdio)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "buffered pipe helper is Windows-only",
        ))
    }
}

pub(crate) use platform::{
    create_buffered_pipe, file_identity_from_file, file_identity_from_path,
};
pub use platform::{decode_acp_lossy, decode_acp_strict};

/// Holds read-only shared handles (`FILE_SHARE_READ` on Windows) to all source image files
/// so concurrent writers and deleters are rejected by the OS kernel while analysis runs.
pub struct SourceGuard {
    #[allow(dead_code)]
    handles: Vec<platform::GuardHandle>,
    paths: Vec<PathBuf>,
    initial_stamps: Vec<FileStamp>,
}

impl SourceGuard {
    /// Acquire `FILE_SHARE_READ` handles for every path and capture the initial [`FileStamp`] snapshot.
    pub fn acquire(paths: &[PathBuf]) -> EngineResult<Self> {
        let mut handles = Vec::with_capacity(paths.len());
        for path in paths {
            handles.push(platform::open_source_guard_handle(path)?);
        }
        let initial_stamps = Self::snapshot(paths)?;
        Ok(Self {
            handles,
            paths: paths.to_vec(),
            initial_stamps,
        })
    }

    /// Capture `(name, size, mtime_ns, ino)` stamps for all source paths.
    pub fn snapshot(paths: &[PathBuf]) -> EngineResult<Vec<FileStamp>> {
        let mut stamps = Vec::with_capacity(paths.len());
        for path in paths {
            let ident = file_identity_from_path(path)?;
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            stamps.push(FileStamp {
                name,
                size: ident.size,
                mtime_ns: ident.mtime_ns,
                ino: ident.ino,
            });
        }
        Ok(stamps)
    }

    /// Verify that the given paths still exist with the exact same stamps recorded on `acquire`.
    pub fn verify_unchanged(&self, paths: &[PathBuf]) -> EngineResult<()> {
        if paths.len() != self.paths.len() {
            return Err(EngineError::SourceChanged(
                "镜像分段清单已变化".to_string(),
            ));
        }
        let current = Self::snapshot(paths)?;
        if current != self.initial_stamps {
            return Err(EngineError::SourceChanged(
                "镜像身份、大小或修改时间与加载记录不一致".to_string(),
            ));
        }
        Ok(())
    }

    /// Initial stamps captured when the guard was acquired.
    pub fn stamps(&self) -> &[FileStamp] {
        &self.initial_stamps
    }

    /// Paths currently protected by this guard.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

/// Exclusive non-blocking byte-0 lock on `<case_dir>/case.lock`, interoperable with Python `msvcrt.locking`.
pub struct CaseFileLock {
    #[allow(dead_code)]
    handle: platform::LockHandle,
    path: PathBuf,
}

impl CaseFileLock {
    /// Open or create `lock_path` and acquire an exclusive non-blocking 1-byte lock at offset 0.
    pub fn acquire(lock_path: &Path) -> EngineResult<Self> {
        let handle = platform::LockHandle::acquire(lock_path)?;
        Ok(Self {
            handle,
            path: lock_path.to_path_buf(),
        })
    }

    /// Path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly release the lock (identical to dropping `self`).
    pub fn unlock(self) {
        drop(self);
    }
}
