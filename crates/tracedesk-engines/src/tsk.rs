use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;

use crate::error::{EngineError, EngineResult};
use crate::types::{InventoryEntry, PartitionInfo};
use crate::win::{
    create_buffered_pipe, decode_acp_lossy, decode_acp_strict, strip_verbatim_prefix,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static MMLS_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*\d+:\s+\d+(?::\d+)?\s+(\d+)\s+\d+\s+\d+\s+(.+)").expect("valid mmls regex")
});
static INODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d+(?:-\d+)*$").expect("valid inode regex"));
static IMG_STAT_SIZE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Size of data in bytes:\s*(\d+)").expect("valid img_stat regex"));
static IMG_STAT_SECTOR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Sector size:\s*(\d+)").expect("valid img_stat sector regex"));

/// Strictly whitelisted read-only Sleuth Kit CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TskCommand {
    Mmls,
    Fsstat,
    Fls,
    Icat,
    ImgStat,
    ImgCat,
}

impl TskCommand {
    /// Canonical lowercase tool name without file extension.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mmls => "mmls",
            Self::Fsstat => "fsstat",
            Self::Fls => "fls",
            Self::Icat => "icat",
            Self::ImgStat => "img_stat",
            Self::ImgCat => "img_cat",
        }
    }

    /// Platform executable filename (`.exe` on Windows).
    pub const fn executable_name(self) -> &'static str {
        #[cfg(windows)]
        {
            match self {
                Self::Mmls => "mmls.exe",
                Self::Fsstat => "fsstat.exe",
                Self::Fls => "fls.exe",
                Self::Icat => "icat.exe",
                Self::ImgStat => "img_stat.exe",
                Self::ImgCat => "img_cat.exe",
            }
        }
        #[cfg(not(windows))]
        {
            self.as_str()
        }
    }

    /// Parse a command name against the strict 6-command read-only whitelist.
    pub fn parse_whitelisted(name: &str) -> EngineResult<Self> {
        match name {
            "mmls" => Ok(Self::Mmls),
            "fsstat" => Ok(Self::Fsstat),
            "fls" => Ok(Self::Fls),
            "icat" => Ok(Self::Icat),
            "img_stat" => Ok(Self::ImgStat),
            "img_cat" => Ok(Self::ImgCat),
            _ => Err(EngineError::TskCommandDenied(format!(
                "仅允许只读 TSK 命令（拒绝：{name}）"
            ))),
        }
    }
}

fn has_fls(dir: &Path) -> bool {
    dir.join("fls.exe").is_file() || dir.join("fls").is_file()
}

fn find_tools_bin_under(tools_dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth == 0 || !tools_dir.is_dir() {
        return;
    }
    if tools_dir.file_name().is_some_and(|n| n == "bin") && has_fls(tools_dir) {
        out.push(tools_dir.to_path_buf());
        return;
    }
    let Ok(read_dir) = fs::read_dir(tools_dir) else {
        return;
    };
    let mut subdirs: Vec<PathBuf> = read_dir
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();
    for sub in subdirs {
        find_tools_bin_under(&sub, depth - 1, out);
    }
}

fn candidate_tool_bins() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(exe) = env::current_exe() {
        let mut cur = exe.parent();
        for _ in 0..6 {
            if let Some(dir) = cur {
                roots.push(dir.to_path_buf());
                cur = dir.parent();
            } else {
                break;
            }
        }
    }
    if let Ok(cwd) = env::current_dir() {
        let mut cur = Some(cwd.as_path());
        for _ in 0..6 {
            if let Some(dir) = cur {
                if !roots.iter().any(|r| r == dir) {
                    roots.push(dir.to_path_buf());
                }
                cur = dir.parent();
            } else {
                break;
            }
        }
    }
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest_dir);
        let mut cur = Some(p.as_path());
        for _ in 0..4 {
            if let Some(dir) = cur {
                if !roots.iter().any(|r| r == dir) {
                    roots.push(dir.to_path_buf());
                }
                cur = dir.parent();
            } else {
                break;
            }
        }
    }

    let mut found = Vec::new();
    for root in roots {
        let tools = root.join("tools");
        if tools.is_dir() {
            find_tools_bin_under(&tools, 3, &mut found);
            if !found.is_empty() {
                break;
            }
        }
    }
    found
}

fn find_fls_on_path() -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    env::split_paths(&path_var).find(|dir| has_fls(dir))
}

fn decode_tsk_stderr(bytes: &[u8]) -> String {
    let decoded = decode_acp_lossy(bytes);
    let trimmed = decoded.trim();
    trimmed.chars().take(2000).collect()
}

fn read_stderr_snippet(file: &mut File) -> String {
    let _ = file.seek(SeekFrom::Start(0));
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf).unwrap_or(0);
    buf.truncate(n);
    decode_tsk_stderr(&buf)
}

fn is_e01_path(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("e01"))
}

fn validate_inode(inode: &str, msg: &str) -> EngineResult<()> {
    if !INODE_RE.is_match(inode) {
        return Err(EngineError::InvalidArgument(msg.to_string()));
    }
    Ok(())
}

/// Prepare command arguments and optional working directory for RAW or EWF images.
///
/// Mirrors `forensic/engines/tsk.py::TSK.image_args`:
/// - When an image ends with `.e01` (case-insensitive), sets `cwd = image.parent()`,
///   replaces the image path with just its filename (avoiding 32-bit `libewf` path issues),
///   and switches `-i raw` to `-i ewf`.
/// - Always strips Windows verbatim `\\?\` prefix so 32-bit TSK binaries accept the path.
fn prepare_image_args(mut args: Vec<OsString>) -> (Vec<OsString>, Option<PathBuf>) {
    for idx in 0..args.len() {
        let p = PathBuf::from(&args[idx]);
        if is_e01_path(&p) {
            let resolved = fs::canonicalize(&p).unwrap_or(p);
            let clean = strip_verbatim_prefix(&resolved);
            if let (Some(parent), Some(name)) = (clean.parent(), clean.file_name())
                && !parent.as_os_str().is_empty()
            {
                args[idx] = name.to_os_string();
                for i in 0..args.len().saturating_sub(1) {
                    if args[i] == "-i" {
                        args[i + 1] = OsString::from("ewf");
                        break;
                    }
                }
                return (args, Some(parent.to_path_buf()));
            }
        }
    }
    (args, None)
}

fn clean_image_arg(image: &Path) -> OsString {
    strip_verbatim_prefix(image).into_os_string()
}

/// Watchdog that terminates a blocking child process if `cancel` is triggered or `deadline` passes.
struct ChildWatchdog {
    done: Arc<AtomicBool>,
    reason: Arc<AtomicU8>,
    handle: Option<thread::JoinHandle<()>>,
}

const KILL_NONE: u8 = 0;
const KILL_CANCELLED: u8 = 1;
const KILL_TIMEOUT: u8 = 2;

impl ChildWatchdog {
    fn start(child: &Child, timeout: Duration, cancel: Option<&AtomicBool>) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let reason = Arc::new(AtomicU8::new(KILL_NONE));

        #[cfg(windows)]
        let dup_handle = {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, PROCESS_TERMINATE};

            let mut dup: HANDLE = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    child.as_raw_handle() as HANDLE,
                    GetCurrentProcess(),
                    &mut dup,
                    PROCESS_TERMINATE,
                    0,
                    0,
                )
            };
            if ok != 0 { Some(dup as usize) } else { None }
        };

        #[cfg(not(windows))]
        let child_pid = child.id();

        let done_bg = Arc::clone(&done);
        let reason_bg = Arc::clone(&reason);
        // SAFETY: `ChildWatchdog::stop` joins this thread before `cancel` can be invalidated,
        // and `Drop` always calls `stop()`. Still, to avoid any lifetime unsafety we poll via
        // raw pointer ONLY if we guarantee join before return — wait: better yet, take an
        // `Option<*const AtomicBool>`? No! Even safer: only store a `usize`? No, Rust's
        // `thread::scope` handles borrowed `&AtomicBool` with 100% safe zero-unsafe lifetimes!
        // Here we only need timeout when `cancel` is None; when `cancel` is Some we use
        // `thread::scope` directly in `stream_entry` / `img_cat_ewf_stream`!
        let _ = cancel;
        let deadline = Instant::now() + timeout;

        let handle = thread::spawn(move || {
            #[cfg(windows)]
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            #[cfg(windows)]
            use windows_sys::Win32::System::Threading::TerminateProcess;

            while !done_bg.load(Ordering::Acquire) {
                if Instant::now() >= deadline {
                    reason_bg.store(KILL_TIMEOUT, Ordering::Release);
                    #[cfg(windows)]
                    if let Some(h) = dup_handle {
                        unsafe {
                            TerminateProcess(h as HANDLE, 1);
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        let _ = child_pid;
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
            #[cfg(windows)]
            if let Some(h) = dup_handle {
                unsafe {
                    CloseHandle(h as HANDLE);
                }
            }
        });

        Self {
            done,
            reason,
            handle: Some(handle),
        }
    }

    fn kill_reason(&self) -> u8 {
        self.reason.load(Ordering::Acquire)
    }

    fn stop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ChildWatchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Safe Windows process terminator for scoped threads (duplicated `PROCESS_TERMINATE` handle).
struct ProcessTerminator {
    #[cfg(windows)]
    raw_handle: Option<usize>,
}

impl ProcessTerminator {
    fn from_child(child: &Child) -> Self {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, PROCESS_TERMINATE};

            let mut dup: HANDLE = std::ptr::null_mut();
            let ok = unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    child.as_raw_handle() as HANDLE,
                    GetCurrentProcess(),
                    &mut dup,
                    PROCESS_TERMINATE,
                    0,
                    0,
                )
            };
            Self {
                raw_handle: if ok != 0 { Some(dup as usize) } else { None },
            }
        }
        #[cfg(not(windows))]
        {
            let _ = child;
            Self {}
        }
    }

    fn terminate(&self) {
        #[cfg(windows)]
        if let Some(h) = self.raw_handle {
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::System::Threading::TerminateProcess;
            unsafe {
                TerminateProcess(h as HANDLE, 1);
            }
        }
    }
}

impl Drop for ProcessTerminator {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(h) = self.raw_handle.take() {
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            unsafe {
                CloseHandle(h as HANDLE);
            }
        }
    }
}

/// Read-only Sleuth Kit CLI adapter (strictly whitelisted to 6 commands, no shell, CP_ACP decoded).
#[derive(Debug, Clone)]
pub struct TskCli {
    bin_dir: PathBuf,
}

impl TskCli {
    /// Discover Sleuth Kit binaries in strict priority order:
    /// `override_dir` -> `TSK_BIN` -> `<app_root>/tools/**/bin` -> `PATH`.
    pub fn discover(override_dir: Option<&Path>) -> EngineResult<Self> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(dir) = override_dir {
            candidates.push(dir.to_path_buf());
        }
        if let Ok(env_bin) = env::var("TSK_BIN")
            && !env_bin.trim().is_empty()
        {
            candidates.push(PathBuf::from(env_bin));
        }
        candidates.extend(candidate_tool_bins());

        if let Some(dir) = candidates.into_iter().find(|p| has_fls(p)) {
            return Ok(Self { bin_dir: dir });
        }
        if let Some(dir) = find_fls_on_path() {
            return Ok(Self { bin_dir: dir });
        }
        Err(EngineError::TskNotFound(
            "未找到 Sleuth Kit。请运行 scripts/install_tsk.ps1，或设置 TSK_BIN 为 bin 目录。"
                .to_string(),
        ))
    }

    /// Construct directly from an explicit `bin` directory (primarily for tests).
    pub fn from_bin_dir(bin_dir: PathBuf) -> Self {
        Self { bin_dir }
    }

    /// Resolved Sleuth Kit `bin` directory.
    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// Resolve an executable path for a whitelisted command.
    pub fn resolve_executable(&self, cmd: TskCommand) -> EngineResult<PathBuf> {
        let exe = self.bin_dir.join(cmd.executable_name());
        if !exe.is_file() {
            return Err(EngineError::TskNotFound(format!(
                "缺少 Sleuth Kit 工具 {}，请检查 TSK_BIN",
                cmd.as_str()
            )));
        }
        Ok(exe)
    }

    fn build_command(&self, cmd: TskCommand, raw_args: Vec<OsString>) -> EngineResult<Command> {
        let exe = self.resolve_executable(cmd)?;
        let (args, cwd) = prepare_image_args(raw_args);
        let mut command = Command::new(&exe);
        command.args(&args);
        if let Some(dir) = cwd {
            command.current_dir(dir);
        }
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);
        Ok(command)
    }

    fn run_captured(
        &self,
        cmd: TskCommand,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> EngineResult<Vec<u8>> {
        let mut stdout_tmp = tempfile::tempfile()?;
        let mut stderr_tmp = tempfile::tempfile()?;

        let mut command = self.build_command(cmd, args)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_tmp.try_clone()?))
            .stderr(Stdio::from(stderr_tmp.try_clone()?));

        let mut child = command.spawn().map_err(|e| EngineError::TskFailed {
            command: cmd.as_str().to_string(),
            message: format!("无法启动 {}：{e}", cmd.as_str()),
        })?;

        let mut watchdog = ChildWatchdog::start(&child, timeout, None);
        let status = child.wait()?;
        watchdog.stop();

        if watchdog.kill_reason() == KILL_TIMEOUT {
            return Err(EngineError::Timeout(format!(
                "{} 执行超时（{} 秒）",
                cmd.as_str(),
                timeout.as_secs()
            )));
        }
        if !status.success() {
            let msg = read_stderr_snippet(&mut stderr_tmp);
            return Err(EngineError::TskFailed {
                command: cmd.as_str().to_string(),
                message: if msg.is_empty() {
                    format!("退出码 {:?}", status.code())
                } else {
                    msg
                },
            });
        }

        stdout_tmp.seek(SeekFrom::Start(0))?;
        let mut out = Vec::new();
        stdout_tmp.read_to_end(&mut out)?;
        Ok(out)
    }

    fn run_text(&self, cmd: TskCommand, args: Vec<OsString>, timeout: Duration) -> EngineResult<String> {
        let bytes = self.run_captured(cmd, args, timeout)?;
        if cmd == TskCommand::Fls {
            decode_acp_strict(&bytes)
        } else {
            Ok(decode_acp_lossy(&bytes))
        }
    }

    /// Query Sleuth Kit version via `fls -V`.
    pub fn version(&self) -> EngineResult<String> {
        let bytes = self.run_captured(
            TskCommand::Fls,
            vec![OsString::from("-V")],
            Duration::from_secs(30),
        )?;
        Ok(decode_acp_lossy(&bytes).trim().to_string())
    }

    /// Inspect partition table via `mmls`, falling back to offset 0 verification via `fsstat -t`.
    pub fn inspect(&self, image: &Path) -> EngineResult<(String, Vec<PartitionInfo>)> {
        let mmls_args = vec![
            OsString::from("-i"),
            OsString::from("raw"),
            clean_image_arg(image),
        ];
        match self.run_text(TskCommand::Mmls, mmls_args, Duration::from_secs(300)) {
            Ok(raw) => {
                let partitions = parse_mmls_output(&raw);
                if !partitions.is_empty() {
                    return Ok((raw, partitions));
                }
                self.inspect_offset_zero_fallback(image, "分区表中未发现可分析分区")
            }
            Err(err) => self.inspect_offset_zero_fallback(image, &err.to_string()),
        }
    }

    fn inspect_offset_zero_fallback(
        &self,
        image: &Path,
        mmls_err: &str,
    ) -> EngineResult<(String, Vec<PartitionInfo>)> {
        let fsstat_args = vec![
            OsString::from("-t"),
            OsString::from("-i"),
            OsString::from("raw"),
            OsString::from("-o"),
            OsString::from("0"),
            clean_image_arg(image),
        ];
        self.run_text(TskCommand::Fsstat, fsstat_args, Duration::from_secs(300))?;
        Ok((
            format!("无可解析分区表，fsstat 确认偏移 0 的文件系统。\n{mmls_err}"),
            vec![PartitionInfo {
                offset: 0,
                description: "分区镜像 / 文件系统位于偏移 0".to_string(),
            }],
        ))
    }

    /// Run `fsstat` (full or `-t` type-only) for the partition at `offset` (in 512-byte sectors).
    pub fn fsstat(&self, image: &Path, offset: u64, type_only: bool) -> EngineResult<String> {
        let mut args = Vec::with_capacity(6);
        if type_only {
            args.push(OsString::from("-t"));
        }
        args.push(OsString::from("-i"));
        args.push(OsString::from("raw"));
        args.push(OsString::from("-o"));
        args.push(OsString::from(offset.to_string()));
        args.push(clean_image_arg(image));
        self.run_text(TskCommand::Fsstat, args, Duration::from_secs(300))
    }

    /// Run `fsstat` and stream raw stdout directly to `dest`.
    pub fn fsstat_to_file(&self, image: &Path, offset: u64, dest: &Path) -> EngineResult<()> {
        let args = vec![
            OsString::from("-i"),
            OsString::from("raw"),
            OsString::from("-o"),
            OsString::from(offset.to_string()),
            clean_image_arg(image),
        ];
        let mut stderr_tmp = tempfile::tempfile()?;
        let out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;

        let mut command = self.build_command(TskCommand::Fsstat, args)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(stderr_tmp.try_clone()?));

        let mut child = command.spawn().map_err(|e| {
            let _ = fs::remove_file(dest);
            EngineError::TskFailed {
                command: "fsstat".to_string(),
                message: format!("无法启动 fsstat：{e}"),
            }
        })?;

        let mut watchdog = ChildWatchdog::start(&child, Duration::from_secs(300), None);
        let status = child.wait()?;
        watchdog.stop();

        if watchdog.kill_reason() == KILL_TIMEOUT {
            let _ = fs::remove_file(dest);
            return Err(EngineError::Timeout("fsstat 执行超时（300 秒）".to_string()));
        }
        if !status.success() {
            let _ = fs::remove_file(dest);
            let msg = read_stderr_snippet(&mut stderr_tmp);
            return Err(EngineError::TskFailed {
                command: "fsstat".to_string(),
                message: if msg.is_empty() {
                    format!("退出码 {:?}", status.code())
                } else {
                    msg
                },
            });
        }
        Ok(())
    }

    /// List allocated (`-u`) and deleted (`-d`) entries concurrently, merging results strictly
    /// in original order: all `-u` entries first, followed by all `-d` entries.
    pub fn list_entries(
        &self,
        image: &Path,
        offset: u64,
        recursive: bool,
        dir_inode: Option<&str>,
        prefix_path: &str,
        cancel: Option<&AtomicBool>,
    ) -> EngineResult<Vec<InventoryEntry>> {
        if let Some(ino) = dir_inode {
            validate_inode(ino, "非法目录 inode")?;
        }
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消建立索引".to_string()));
        }

        let image_size = fs::metadata(image).map(|m| m.len()).unwrap_or(0);
        let gib = image_size.div_ceil(1 << 30);
        let timeout = Duration::from_secs(300u64.max(120 * gib));

        let abort = AtomicBool::new(false);

        let (alloc_res, del_res) = thread::scope(|s| {
            let alloc_handle = s.spawn(|| {
                self.run_fls_pass(image, offset, recursive, dir_inode, "-u", false, timeout, cancel, &abort)
            });
            let del_handle = s.spawn(|| {
                self.run_fls_pass(image, offset, recursive, dir_inode, "-d", true, timeout, cancel, &abort)
            });

            let a = alloc_handle
                .join()
                .unwrap_or_else(|_| Err(EngineError::TskFailed {
                    command: "fls".to_string(),
                    message: "fls (-u) 工作线程异常退出".to_string(),
                }));
            let d = del_handle
                .join()
                .unwrap_or_else(|_| Err(EngineError::TskFailed {
                    command: "fls".to_string(),
                    message: "fls (-d) 工作线程异常退出".to_string(),
                }));
            (a, d)
        });

        // If cancelled by caller, surface cancellation deterministically.
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消建立索引".to_string()));
        }

        // If one side failed and aborted the sibling, surface the real root error instead of the sibling abort.
        let (mut allocated, mut deleted) = match (alloc_res, del_res) {
            (Ok(a), Ok(d)) => (a, d),
            (Err(e1), Err(e2)) => {
                if e1.is_cancelled() && !e2.is_cancelled() {
                    return Err(e2);
                }
                return Err(e1);
            }
            (Err(e), Ok(_)) | (Ok(_), Err(e)) => return Err(e),
        };

        allocated.reserve(deleted.len());
        allocated.append(&mut deleted);

        if !prefix_path.is_empty() {
            for entry in &mut allocated {
                entry.path = format!("{prefix_path}/{}", entry.path);
            }
        }
        Ok(allocated)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_fls_pass(
        &self,
        image: &Path,
        offset: u64,
        recursive: bool,
        dir_inode: Option<&str>,
        flag: &str,
        deleted: bool,
        timeout: Duration,
        cancel: Option<&AtomicBool>,
        abort: &AtomicBool,
    ) -> EngineResult<Vec<InventoryEntry>> {
        let mut args = Vec::with_capacity(12);
        if recursive {
            args.push(OsString::from("-r"));
        }
        args.push(OsString::from("-i"));
        args.push(OsString::from("raw"));
        args.push(OsString::from("-o"));
        args.push(OsString::from(offset.to_string()));
        args.push(OsString::from("-z"));
        args.push(OsString::from("UTC"));
        args.push(OsString::from(flag));
        args.push(OsString::from("-p"));
        args.push(OsString::from("-m"));
        args.push(OsString::from("/"));
        args.push(clean_image_arg(image));
        if let Some(ino) = dir_inode {
            args.push(OsString::from(ino));
        }

        let mut stdout_tmp = tempfile::tempfile()?;
        let mut stderr_tmp = tempfile::tempfile()?;

        let mut command = self.build_command(TskCommand::Fls, args)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_tmp.try_clone()?))
            .stderr(Stdio::from(stderr_tmp.try_clone()?));

        let mut child = command.spawn().map_err(|e| {
            abort.store(true, Ordering::Release);
            EngineError::TskFailed {
                command: "fls".to_string(),
                message: format!("无法启动 fls：{e}"),
            }
        })?;

        let deadline = Instant::now() + timeout;
        let exit_status = loop {
            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                abort.store(true, Ordering::Release);
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineError::Cancelled("已取消建立索引".to_string()));
            }
            if abort.load(Ordering::Acquire) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineError::Cancelled("同行 fls 任务失败，已中止".to_string()));
            }
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                abort.store(true, Ordering::Release);
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineError::Timeout("fls 执行超时".to_string()));
            }
            thread::sleep(Duration::from_millis(20));
        };

        if !exit_status.success() {
            abort.store(true, Ordering::Release);
            let msg = read_stderr_snippet(&mut stderr_tmp);
            return Err(EngineError::TskFailed {
                command: "fls".to_string(),
                message: if msg.is_empty() {
                    format!("退出码 {:?}", exit_status.code())
                } else {
                    msg
                },
            });
        }

        stdout_tmp.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::with_capacity(256 * 1024, stdout_tmp);
        let mut entries = Vec::new();
        let mut raw_line = Vec::with_capacity(512);
        let mut line_index: usize = 0;

        loop {
            if line_index.is_multiple_of(2048) && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(EngineError::Cancelled("已取消建立索引".to_string()));
            }
            raw_line.clear();
            let n = reader.read_until(b'\n', &mut raw_line)?;
            if n == 0 {
                break;
            }
            while matches!(raw_line.last(), Some(b'\n' | b'\r')) {
                raw_line.pop();
            }
            let decoded = decode_acp_strict(&raw_line)?;
            entries.push(parse_bodyfile_line(&decoded, offset, deleted)?);
            line_index += 1;
        }

        Ok(entries)
    }

    /// Build `icat` arguments for a specific `(offset, inode)` pair.
    pub fn file_args(
        &self,
        image: &Path,
        offset: u64,
        inode: &str,
        recover: bool,
    ) -> EngineResult<Vec<OsString>> {
        validate_inode(inode, "非法 inode")?;
        let mut args = Vec::with_capacity(7);
        if recover {
            args.push(OsString::from("-r"));
        }
        args.push(OsString::from("-i"));
        args.push(OsString::from("raw"));
        args.push(OsString::from("-o"));
        args.push(OsString::from(offset.to_string()));
        args.push(clean_image_arg(image));
        args.push(OsString::from(inode));
        Ok(args)
    }

    /// Build `icat` arguments for an [`InventoryEntry`] (adds `-r` for non-reallocated deleted entries).
    pub fn entry_args(&self, image: &Path, entry: &InventoryEntry) -> EngineResult<Vec<OsString>> {
        self.file_args(
            image,
            entry.offset,
            &entry.inode,
            entry.deleted && !entry.reallocated,
        )
    }

    /// Export a regular file via `icat` directly to `dest` (fails if `dest` already exists).
    pub fn export_file(
        &self,
        image: &Path,
        offset: u64,
        inode: &str,
        size: u64,
        dest: &Path,
    ) -> EngineResult<()> {
        let args = self.file_args(image, offset, inode, false)?;
        let timeout = Duration::from_secs(300u64.max(size / (1 << 20)));
        let mut stderr_tmp = tempfile::tempfile()?;

        let out_file = OpenOptions::new().write(true).create_new(true).open(dest)?;
        let mut command = self.build_command(TskCommand::Icat, args)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(stderr_tmp.try_clone()?));

        let mut child = command.spawn().map_err(|e| {
            let _ = fs::remove_file(dest);
            EngineError::TskFailed {
                command: "icat".to_string(),
                message: format!("无法启动 icat：{e}"),
            }
        })?;

        let mut watchdog = ChildWatchdog::start(&child, timeout, None);
        let status = child.wait()?;
        watchdog.stop();

        if watchdog.kill_reason() == KILL_TIMEOUT {
            let _ = fs::remove_file(dest);
            return Err(EngineError::Timeout(format!(
                "icat 执行超时（{} 秒）",
                timeout.as_secs()
            )));
        }
        if !status.success() {
            let _ = fs::remove_file(dest);
            let msg = read_stderr_snippet(&mut stderr_tmp);
            return Err(EngineError::TskFailed {
                command: "icat".to_string(),
                message: if msg.is_empty() {
                    format!("退出码 {:?}", status.code())
                } else {
                    msg
                },
            });
        }
        Ok(())
    }

    /// Stream entry bytes via `icat` (with 1 MiB kernel pipe on Windows and cooperative cancellation).
    /// Returns `(bytes_written, read_note)`, preserving recoverable prefix for deleted entries.
    pub fn stream_entry<F>(
        &self,
        image: &Path,
        entry: &InventoryEntry,
        cancel: Option<&AtomicBool>,
        mut consume: F,
    ) -> EngineResult<(u64, String)>
    where
        F: FnMut(&[u8]) -> EngineResult<()>,
    {
        let limit = entry.size;
        let deleted = entry.deleted;
        if limit == 0 && deleted {
            return Ok((0, String::new()));
        }
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消读取文件".to_string()));
        }

        let args = self.entry_args(image, entry)?;
        let timeout = Duration::from_secs(300u64.max(limit / (1 << 20)));
        let mut stderr_tmp = tempfile::tempfile()?;

        let mut command = self.build_command(TskCommand::Icat, args)?;
        let pipe_size = limit.clamp(4096, 1 << 20) as u32;
        let mut stdout_reader: Box<dyn Read>;
        let mut child = match create_buffered_pipe(pipe_size) {
            Ok((read_file, write_stdio)) => {
                command
                    .stdin(Stdio::null())
                    .stdout(write_stdio)
                    .stderr(Stdio::from(stderr_tmp.try_clone()?));
                let child = command.spawn().map_err(|e| EngineError::TskFailed {
                    command: "icat".to_string(),
                    message: format!("无法启动 icat：{e}"),
                })?;
                // Dropping `command` closes our copy of the write handle so EOF arrives when child exits.
                drop(command);
                stdout_reader = Box::new(read_file);
                child
            }
            Err(_) => {
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::from(stderr_tmp.try_clone()?));
                let mut child = command.spawn().map_err(|e| EngineError::TskFailed {
                    command: "icat".to_string(),
                    message: format!("无法启动 icat：{e}"),
                })?;
                let pipe = child.stdout.take().ok_or_else(|| {
                    EngineError::Io(std::io::Error::other("无法获取 icat 标准输出管道"))
                })?;
                stdout_reader = Box::new(pipe);
                child
            }
        };

        let terminator = ProcessTerminator::from_child(&child);
        let done = AtomicBool::new(false);
        let kill_reason = AtomicU8::new(KILL_NONE);
        let deadline = Instant::now() + timeout;

        thread::scope(|s| {
            let watchdog = s.spawn(|| {
                while !done.load(Ordering::Acquire) {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        kill_reason.store(KILL_CANCELLED, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    if Instant::now() >= deadline {
                        kill_reason.store(KILL_TIMEOUT, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            });

            let outcome = (|| -> EngineResult<(u64, String)> {
                let buf_cap = (limit.max(1) as usize).min(1 << 20);
                let mut buf = vec![0u8; buf_cap];
                let mut written: u64 = 0;

                while written < limit {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        return Err(EngineError::Cancelled("已取消读取文件".to_string()));
                    }
                    let want = ((limit - written) as usize).min(buf.len());
                    let n = stdout_reader.read(&mut buf[..want])?;
                    if n == 0 {
                        break;
                    }
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        return Err(EngineError::Cancelled("已取消读取文件".to_string()));
                    }
                    consume(&buf[..n])?;
                    written += n as u64;
                }

                // Check for unexpected trailing byte if we hit `limit`.
                if written == limit {
                    let mut extra = [0u8; 1];
                    let extra_read = stdout_reader.read(&mut extra)?;
                    if extra_read > 0 {
                        let _ = child.kill();
                        let _ = child.wait();
                        if deleted {
                            return Ok((written, "已按目录记录大小截取".to_string()));
                        }
                        return Err(EngineError::InvalidArgument(
                            "实际读取长度超过文件记录".to_string(),
                        ));
                    }
                }

                let status = child.wait()?;

                match kill_reason.load(Ordering::Acquire) {
                    KILL_CANCELLED => {
                        return Err(EngineError::Cancelled("已取消读取文件".to_string()));
                    }
                    KILL_TIMEOUT => {
                        return Err(EngineError::Timeout(format!(
                            "icat 执行超时（{} 秒）",
                            timeout.as_secs()
                        )));
                    }
                    _ => {}
                }

                if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return Err(EngineError::Cancelled("已取消读取文件".to_string()));
                }

                if !status.success() {
                    let msg = read_stderr_snippet(&mut stderr_tmp);
                    let note = if msg.is_empty() {
                        "icat 未正常完成读取".to_string()
                    } else {
                        msg
                    };
                    if deleted && written > 0 {
                        return Ok((written, note));
                    }
                    return Err(EngineError::TskFailed {
                        command: "icat".to_string(),
                        message: note,
                    });
                }

                if written != limit && !deleted {
                    return Err(EngineError::InvalidArgument(
                        "实际读取长度与文件记录不符".to_string(),
                    ));
                }
                if deleted && written == 0 {
                    return Err(EngineError::TskFailed {
                        command: "icat".to_string(),
                        message: "未能从该删除记录读取数据".to_string(),
                    });
                }
                Ok((written, String::new()))
            })();

            done.store(true, Ordering::Release);
            let _ = child.kill();
            let _ = child.wait();
            let _ = watchdog.join();
            outcome
        })
    }

    /// Query EWF logical media size and sector size via `img_stat -i ewf`.
    pub fn img_stat_ewf(&self, e01: &Path) -> EngineResult<(u64, u32)> {
        let args = vec![
            OsString::from("-i"),
            OsString::from("ewf"),
            clean_image_arg(e01),
        ];
        let info = self.run_text(TskCommand::ImgStat, args, Duration::from_secs(300))?;
        parse_img_stat_ewf(&info)
    }

    /// Read a single 512-byte logical sector from an EWF image via `img_cat -i ewf`.
    ///
    /// Note: Sleuth Kit 4.15 `img_cat` rejects `-s 0` / `-e 0` ("must be positive"), so for
    /// sector 0 we invoke `-e 1` (sectors 0..=1) and return the first 512 bytes.
    pub fn read_ewf_sector(&self, e01: &Path, sector: u64) -> EngineResult<Vec<u8>> {
        if sector == 0 {
            let args = vec![
                OsString::from("-i"),
                OsString::from("ewf"),
                OsString::from("-e"),
                OsString::from("1"),
                clean_image_arg(e01),
            ];
            let mut data = self.run_captured(TskCommand::ImgCat, args, Duration::from_secs(300))?;
            if data.len() > 512 {
                data.truncate(512);
            }
            return Ok(data);
        }
        let s = sector.to_string();
        let args = vec![
            OsString::from("-i"),
            OsString::from("ewf"),
            OsString::from("-s"),
            OsString::from(&s),
            OsString::from("-e"),
            OsString::from(&s),
            clean_image_arg(e01),
        ];
        self.run_captured(TskCommand::ImgCat, args, Duration::from_secs(300))
    }

    /// Stream the full logical contents of an EWF image via `img_cat -i ewf` (fallback path).
    pub(crate) fn img_cat_ewf_stream<F>(
        &self,
        e01: &Path,
        logical_size: u64,
        cancel: Option<&AtomicBool>,
        mut consume: F,
    ) -> EngineResult<u64>
    where
        F: FnMut(&[u8]) -> EngineResult<()>,
    {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消 EWF 解码".to_string()));
        }
        let args = vec![
            OsString::from("-i"),
            OsString::from("ewf"),
            clean_image_arg(e01),
        ];
        let timeout = Duration::from_secs(600u64.max(logical_size / (2 << 20)));
        let mut stderr_tmp = tempfile::tempfile()?;

        let mut command = self.build_command(TskCommand::ImgCat, args)?;
        let pipe_size = logical_size.clamp(4096, 1 << 20) as u32;
        let mut stdout_reader: Box<dyn Read>;
        let mut child = match create_buffered_pipe(pipe_size) {
            Ok((read_file, write_stdio)) => {
                command
                    .stdin(Stdio::null())
                    .stdout(write_stdio)
                    .stderr(Stdio::from(stderr_tmp.try_clone()?));
                let child = command.spawn().map_err(|e| EngineError::TskFailed {
                    command: "img_cat".to_string(),
                    message: format!("无法启动 img_cat：{e}"),
                })?;
                drop(command);
                stdout_reader = Box::new(read_file);
                child
            }
            Err(_) => {
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::from(stderr_tmp.try_clone()?));
                let mut child = command.spawn().map_err(|e| EngineError::TskFailed {
                    command: "img_cat".to_string(),
                    message: format!("无法启动 img_cat：{e}"),
                })?;
                let pipe = child.stdout.take().ok_or_else(|| {
                    EngineError::Io(std::io::Error::other("无法获取 img_cat 标准输出管道"))
                })?;
                stdout_reader = Box::new(pipe);
                child
            }
        };

        let terminator = ProcessTerminator::from_child(&child);
        let done_flag = AtomicBool::new(false);
        let kill_reason = AtomicU8::new(KILL_NONE);
        let deadline = Instant::now() + timeout;

        thread::scope(|s| {
            let watchdog = s.spawn(|| {
                while !done_flag.load(Ordering::Acquire) {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        kill_reason.store(KILL_CANCELLED, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    if Instant::now() >= deadline {
                        kill_reason.store(KILL_TIMEOUT, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            });

            let outcome = (|| -> EngineResult<u64> {
                let mut buf = vec![0u8; 4 << 20];
                let mut total: u64 = 0;
                loop {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        return Err(EngineError::Cancelled("已取消 EWF 解码".to_string()));
                    }
                    let n = stdout_reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    consume(&buf[..n])?;
                    total += n as u64;
                }
                let status = child.wait()?;
                match kill_reason.load(Ordering::Acquire) {
                    KILL_CANCELLED => {
                        return Err(EngineError::Cancelled("已取消 EWF 解码".to_string()));
                    }
                    KILL_TIMEOUT => {
                        return Err(EngineError::Timeout("img_cat 执行超时".to_string()));
                    }
                    _ => {}
                }
                if !status.success() || total != logical_size {
                    let msg = read_stderr_snippet(&mut stderr_tmp);
                    let snippet: String = msg.chars().take(512).collect();
                    return Err(EngineError::Ewf(format!(
                        "EWF 解码失败，读取 {total}/{logical_size} 字节：{snippet}"
                    )));
                }
                Ok(total)
            })();

            done_flag.store(true, Ordering::Release);
            let _ = child.kill();
            let _ = child.wait();
            let _ = watchdog.join();
            outcome
        })
    }
}

/// Parse `mmls` text output into [`PartitionInfo`] entries (filtering out Unallocated/Extended).
pub fn parse_mmls_output(raw: &str) -> Vec<PartitionInfo> {
    let mut partitions = Vec::new();
    for line in raw.lines() {
        if let Some(caps) = MMLS_LINE_RE.captures(line) {
            let offset_str = &caps[1];
            let desc = caps[2].trim_end();
            let desc_lower = desc.to_ascii_lowercase();
            if desc_lower.contains("unallocated") || desc_lower.contains("extended") {
                continue;
            }
            if let Ok(offset) = offset_str.parse::<u64>() {
                partitions.push(PartitionInfo {
                    offset,
                    description: desc.to_string(),
                });
            }
        }
    }
    partitions
}

/// Parse a single `fls -m /` bodyfile line, matching `forensic/engines/tsk.py::_body_entries`.
pub fn parse_bodyfile_line(
    line: &str,
    offset: u64,
    deleted: bool,
) -> EngineResult<InventoryEntry> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() < 11 {
        let preview: String = line.chars().take(150).collect();
        return Err(EngineError::TskFailed {
            command: "fls".to_string(),
            message: format!("无法解析 fls bodyfile 行：{preview}"),
        });
    }
    let split_idx = parts.len() - 9;
    let tail = &parts[split_idx..];
    let inode = tail[0].to_string();
    let mode = tail[1].to_string();
    let size = tail[4].parse::<u64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls 文件长度解析失败（{}）：{e}", tail[4]),
    })?;
    let atime = tail[5].parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls atime 解析失败（{}）：{e}", tail[5]),
    })?;
    let mtime = tail[6].parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls mtime 解析失败（{}）：{e}", tail[6]),
    })?;
    let ctime = tail[7].parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls ctime 解析失败（{}）：{e}", tail[7]),
    })?;
    let crtime = tail[8].parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls crtime 解析失败（{}）：{e}", tail[8]),
    })?;

    let mut path = parts[1..split_idx]
        .join("|")
        .trim_start_matches('/')
        .to_string();
    let reallocated = deleted && path.ends_with(" (deleted-realloc)");
    if deleted {
        if let Some(stripped) = path.strip_suffix(" (deleted-realloc)") {
            path = stripped.to_string();
        } else if let Some(stripped) = path.strip_suffix(" (deleted)") {
            path = stripped.to_string();
        }
    }
    let directory = mode.starts_with('d') || mode.starts_with('V');

    Ok(InventoryEntry {
        path,
        inode,
        mode,
        size,
        deleted,
        reallocated,
        atime,
        mtime,
        ctime,
        crtime,
        directory,
        offset,
        filesystem: String::new(),
        start_cluster_allocated: None,
        extents: None,
    })
}

/// Parse `img_stat -i ewf` output into `(logical_size, sector_size)`.
pub fn parse_img_stat_ewf(info: &str) -> EngineResult<(u64, u32)> {
    let size = IMG_STAT_SIZE_RE
        .captures(info)
        .and_then(|c| c[1].parse::<u64>().ok());
    let sector = IMG_STAT_SECTOR_RE
        .captures(info)
        .and_then(|c| c[1].parse::<u32>().ok());
    match (size, sector) {
        (Some(sz), Some(sec)) if sec > 0 => Ok((sz, sec)),
        _ => Err(EngineError::Ewf(
            "无法确定受支持的 EWF 逻辑大小或扇区大小".to_string(),
        )),
    }
}
