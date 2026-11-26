use std::borrow::Cow;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
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

/// 严格白名单约束的只读 Sleuth Kit CLI 命令集合。
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
    /// 不含扩展名的规范小写工具名。
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

    /// 当前平台的可执行文件名（Windows 上带 `.exe` 后缀）。
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

    /// 依据严格的 6 命令只读白名单解析命令名称。
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

/// 为 RAW 或 EWF 镜像准备命令参数及可选工作目录。
///
/// 与 `forensic/engines/tsk.py::TSK.image_args` 保持一致：
/// - 当镜像路径以 `.e01`（不区分大小写）结尾时，将 `cwd` 设为 `image.parent()`，
///   把镜像参数替换为纯文件名（规避 32 位 `libewf` 路径问题），并将 `-i raw` 切换为 `-i ewf`。
/// - 始终去除 Windows 原义路径前缀 `\\?\`，确保 32 位 TSK 可执行文件能够识别路径。
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

/// 看门狗定时器：当超过 `deadline` 时终止阻塞中的子进程；
/// 使用 `Condvar` 通知退出，子进程正常结束时零延迟唤醒回收。
struct ChildWatchdog {
    state: Arc<(Mutex<bool>, Condvar)>,
    reason: Arc<AtomicU8>,
    handle: Option<thread::JoinHandle<()>>,
}

const KILL_NONE: u8 = 0;
const KILL_CANCELLED: u8 = 1;
const KILL_TIMEOUT: u8 = 2;

impl ChildWatchdog {
    fn start(child: &Child, timeout: Duration, cancel: Option<&AtomicBool>) -> Self {
        let state = Arc::new((Mutex::new(false), Condvar::new()));
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

        let state_bg = Arc::clone(&state);
        // 说明：为避免任何生命周期相关的不安全操作，此处不通过裸指针轮询 `cancel`，
        // 仅处理超时场景（`cancel` 为 `None`）；当需要协作式取消时，在作用域线程中安全借用 `&AtomicBool`。
        let _ = cancel;
        let reason_bg = Arc::clone(&reason);
        let deadline = Instant::now() + timeout;

        let handle = thread::spawn(move || {
            #[cfg(windows)]
            use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
            #[cfg(windows)]
            use windows_sys::Win32::System::Threading::TerminateProcess;

            let (lock, cvar) = &*state_bg;
            let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
            while !*done {
                let now = Instant::now();
                if now >= deadline {
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
                let wait = deadline.saturating_duration_since(now);
                let (guard, _) = cvar
                    .wait_timeout(done, wait)
                    .unwrap_or_else(|e| e.into_inner());
                done = guard;
            }
            #[cfg(windows)]
            if let Some(h) = dup_handle {
                unsafe {
                    CloseHandle(h as HANDLE);
                }
            }
        });

        Self {
            state,
            reason,
            handle: Some(handle),
        }
    }

    fn kill_reason(&self) -> u8 {
        self.reason.load(Ordering::Acquire)
    }

    fn stop(&mut self) {
        let (lock, cvar) = &*self.state;
        {
            let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
            *done = true;
            cvar.notify_one();
        }
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

/// 供作用域线程使用的安全 Windows 进程终止器（持有复制后的 `PROCESS_TERMINATE` 句柄）。
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

/// 只读 Sleuth Kit CLI 适配器（严格限制 6 个白名单命令，不经由 shell，输出按 CP_ACP 解码）。
#[derive(Debug, Clone)]
pub struct TskCli {
    bin_dir: PathBuf,
}

fn normalize_bin_dir(dir: PathBuf) -> PathBuf {
    let resolved = fs::canonicalize(&dir).unwrap_or(dir);
    strip_verbatim_prefix(&resolved)
}

impl TskCli {
    /// 按严格优先级顺序发现 Sleuth Kit 二进制目录：
    /// `override_dir` -> `TSK_BIN` -> `<app_root>/tools/**/bin` -> `PATH`。
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
            return Ok(Self {
                bin_dir: normalize_bin_dir(dir),
            });
        }
        if let Some(dir) = find_fls_on_path() {
            return Ok(Self {
                bin_dir: normalize_bin_dir(dir),
            });
        }
        Err(EngineError::TskNotFound(
            "未找到 Sleuth Kit。请运行 scripts/install_tsk.ps1，或设置 TSK_BIN 为 bin 目录。"
                .to_string(),
        ))
    }

    /// 直接从指定的 `bin` 目录构造实例（主要用于测试）。
    pub fn from_bin_dir(bin_dir: PathBuf) -> Self {
        Self {
            bin_dir: normalize_bin_dir(bin_dir),
        }
    }

    /// 已解析的 Sleuth Kit `bin` 目录路径。
    pub fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// 解析白名单命令对应的可执行文件路径。
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

    fn run_captured_cancellable(
        &self,
        cmd: TskCommand,
        args: Vec<OsString>,
        timeout: Duration,
        cancel: Option<&AtomicBool>,
    ) -> EngineResult<Vec<u8>> {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled(format!(
                "已取消执行 {}",
                cmd.as_str()
            )));
        }
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

        let (status, kill_reason) = if let Some(cancel_flag) = cancel {
            let terminator = ProcessTerminator::from_child(&child);
            let done_lock = Mutex::new(false);
            let done_cvar = Condvar::new();
            let reason = AtomicU8::new(KILL_NONE);
            let deadline = Instant::now() + timeout;

            let status = thread::scope(|s| {
                let watchdog = s.spawn(|| {
                    let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                    while !*done {
                        if cancel_flag.load(Ordering::Relaxed) {
                            reason.store(KILL_CANCELLED, Ordering::Release);
                            terminator.terminate();
                            break;
                        }
                        let now = Instant::now();
                        if now >= deadline {
                            reason.store(KILL_TIMEOUT, Ordering::Release);
                            terminator.terminate();
                            break;
                        }
                        let wait = Duration::from_millis(20)
                            .min(deadline.saturating_duration_since(now));
                        let (guard, _) = done_cvar
                            .wait_timeout(done, wait)
                            .unwrap_or_else(|e| e.into_inner());
                        done = guard;
                    }
                });
                let wait_res = child.wait();
                {
                    let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                    *done = true;
                    done_cvar.notify_one();
                }
                let _ = watchdog.join();
                wait_res
            })?;
            (status, reason.load(Ordering::Acquire))
        } else {
            let mut watchdog = ChildWatchdog::start(&child, timeout, None);
            let status = child.wait()?;
            watchdog.stop();
            (status, watchdog.kill_reason())
        };

        if kill_reason == KILL_CANCELLED || cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled(format!(
                "已取消执行 {}",
                cmd.as_str()
            )));
        }
        if kill_reason == KILL_TIMEOUT {
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

    fn run_captured(
        &self,
        cmd: TskCommand,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> EngineResult<Vec<u8>> {
        self.run_captured_cancellable(cmd, args, timeout, None)
    }

    fn run_text(&self, cmd: TskCommand, args: Vec<OsString>, timeout: Duration) -> EngineResult<String> {
        let bytes = self.run_captured(cmd, args, timeout)?;
        if cmd == TskCommand::Fls {
            Ok(decode_fls_line(&bytes).0.into_owned())
        } else {
            Ok(decode_acp_lossy(&bytes))
        }
    }

    /// 通过 `fls -V` 查询 Sleuth Kit 版本。
    pub fn version(&self) -> EngineResult<String> {
        let bytes = self.run_captured(
            TskCommand::Fls,
            vec![OsString::from("-V")],
            Duration::from_secs(30),
        )?;
        Ok(decode_acp_lossy(&bytes).trim().to_string())
    }

    /// 通过 `mmls` 检查分区表；若无可用分区表，则通过 `fsstat -t` 回退校验偏移 0。
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

    /// 对位于 `offset`（以 512 字节扇区计）的分区执行 `fsstat`（完整输出或 `-t` 仅输出类型）。
    pub fn fsstat(&self, image: &Path, offset: u64, type_only: bool) -> EngineResult<String> {
        self.fsstat_cancellable(image, offset, type_only, None)
    }

    /// 支持协作式取消的 `fsstat` 执行接口（供分区扫描与 `fls` 并行执行时共享取消/中止信号）。
    pub fn fsstat_cancellable(
        &self,
        image: &Path,
        offset: u64,
        type_only: bool,
        cancel: Option<&AtomicBool>,
    ) -> EngineResult<String> {
        let mut args = Vec::with_capacity(6);
        if type_only {
            args.push(OsString::from("-t"));
        }
        args.push(OsString::from("-i"));
        args.push(OsString::from("raw"));
        args.push(OsString::from("-o"));
        args.push(OsString::from(offset.to_string()));
        args.push(clean_image_arg(image));
        let bytes = self.run_captured_cancellable(
            TskCommand::Fsstat,
            args,
            Duration::from_secs(300),
            cancel,
        )?;
        Ok(decode_acp_lossy(&bytes))
    }

    /// 执行 `fsstat` 并将原始标准输出直接流式写入 `dest`。
    pub fn fsstat_to_file(&self, image: &Path, offset: u64, dest: &Path) -> EngineResult<()> {
        let args = vec![
            OsString::from("-i"),
            OsString::from("raw"),
            OsString::from("-o"),
            OsString::from(offset.to_string()),
            clean_image_arg(image),
        ];
        let mut command = self.build_command(TskCommand::Fsstat, args)?;
        let mut stderr_tmp = tempfile::tempfile()?;
        let out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dest)?;

        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(stderr_tmp.try_clone()?));

        let spawn_res = command.spawn();
        drop(command); // 立即释放父进程持有的 `dest` 句柄。
        let mut child = spawn_res.map_err(|e| {
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

    /// 并发列举现存（`-u`）与已删除（`-d`）条目，并严格按原始顺序合并结果：
    /// 先包含全部 `-u` 条目，随后拼接全部 `-d` 条目。
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

        // 若调用方主动取消，则确定性地返回取消错误。
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(EngineError::Cancelled("已取消建立索引".to_string()));
        }

        // 若一侧失败并中止了另一侧，则向上暴露真正的根因错误而非同行中止错误。
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

        let terminator = ProcessTerminator::from_child(&child);
        let done_lock = Mutex::new(false);
        let done_cvar = Condvar::new();
        let kill_reason = AtomicU8::new(KILL_NONE);
        let deadline = Instant::now() + timeout;

        // 主线程直接阻塞等待子进程退出（零轮询延迟），作用域看门狗通过 Condvar 响应取消/中止/超时。
        let exit_status = thread::scope(|s| {
            let watchdog = s.spawn(|| {
                let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                while !*done {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        abort.store(true, Ordering::Release);
                        kill_reason.store(KILL_CANCELLED, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    if abort.load(Ordering::Acquire) {
                        kill_reason.store(KILL_CANCELLED, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        abort.store(true, Ordering::Release);
                        kill_reason.store(KILL_TIMEOUT, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    let wait = Duration::from_millis(20)
                        .min(deadline.saturating_duration_since(now));
                    let (guard, _) = done_cvar
                        .wait_timeout(done, wait)
                        .unwrap_or_else(|e| e.into_inner());
                    done = guard;
                }
            });

            let wait_res = child.wait();
            {
                let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                *done = true;
                done_cvar.notify_one();
            }
            let _ = watchdog.join();
            wait_res
        })?;

        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            abort.store(true, Ordering::Release);
            return Err(EngineError::Cancelled("已取消建立索引".to_string()));
        }
        match kill_reason.load(Ordering::Acquire) {
            KILL_TIMEOUT => return Err(EngineError::Timeout("fls 执行超时".to_string())),
            KILL_CANCELLED => {
                return Err(EngineError::Cancelled("同行 fls 任务失败，已中止".to_string()));
            }
            _ => {}
        }

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
        let summary = parse_fls_bodyfile_reader(&mut reader, offset, deleted, cancel)?;
        if summary.skipped_lines > 0 || summary.lossy_decoded_lines > 0 {
            eprintln!(
                "[tracedesk-engines::tsk] fls(offset={offset}, deleted={deleted}) 解析汇总：有效条目 {}，跳过异常行 {}，有损解码行 {}",
                summary.entries.len(),
                summary.skipped_lines,
                summary.lossy_decoded_lines
            );
        }

        Ok(summary.entries)
    }

    /// 为指定的 `(offset, inode)` 组合构造 `icat` 参数。
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

    /// 为 [`InventoryEntry`] 构造 `icat` 参数（对未重分配的已删除条目附加 `-r`）。
    pub fn entry_args(&self, image: &Path, entry: &InventoryEntry) -> EngineResult<Vec<OsString>> {
        self.file_args(
            image,
            entry.offset,
            &entry.inode,
            entry.deleted && !entry.reallocated,
        )
    }

    /// 通过 `icat` 将常规文件直接导出到 `dest`（若 `dest` 已存在则失败）。
    pub fn export_file(
        &self,
        image: &Path,
        offset: u64,
        inode: &str,
        size: u64,
        dest: &Path,
    ) -> EngineResult<()> {
        let args = self.file_args(image, offset, inode, false)?;
        let mut command = self.build_command(TskCommand::Icat, args)?;
        let timeout = Duration::from_secs(300u64.max(size / (1 << 20)));
        let mut stderr_tmp = tempfile::tempfile()?;

        let out_file = OpenOptions::new().write(true).create_new(true).open(dest)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(stderr_tmp.try_clone()?));

        let spawn_res = command.spawn();
        drop(command); // 立即释放父进程持有的 `dest` 句柄。
        let mut child = spawn_res.map_err(|e| {
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

    /// 通过 `icat` 流式读取条目字节（在 Windows 上使用 1 MiB 内核管道并支持协作式取消）。
    /// 返回 `(bytes_written, read_note)`，对已删除条目会保留可恢复的前缀数据。
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
                // 释放 `command` 以关闭父进程持有的写端句柄，使子进程退出后读端能够收到 EOF。
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
        let done_lock = Mutex::new(false);
        let done_cvar = Condvar::new();
        let kill_reason = AtomicU8::new(KILL_NONE);
        let deadline = Instant::now() + timeout;

        thread::scope(|s| {
            let watchdog = s.spawn(|| {
                let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                while !*done {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        kill_reason.store(KILL_CANCELLED, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        kill_reason.store(KILL_TIMEOUT, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    let wait = Duration::from_millis(20)
                        .min(deadline.saturating_duration_since(now));
                    let (guard, _) = done_cvar
                        .wait_timeout(done, wait)
                        .unwrap_or_else(|e| e.into_inner());
                    done = guard;
                }
            });

            let outcome = (|| -> EngineResult<(u64, String)> {
                let buf_cap = limit.clamp(1, 1 << 20) as usize;
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

                // 当读取达到 `limit` 时，探测是否存在预期之外的多余尾随字节。
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

            {
                let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                *done = true;
                done_cvar.notify_one();
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = watchdog.join();
            outcome
        })
    }

    /// 通过 `img_stat -i ewf` 查询 EWF 逻辑介质大小与扇区大小。
    pub fn img_stat_ewf(&self, e01: &Path) -> EngineResult<(u64, u32)> {
        let args = vec![
            OsString::from("-i"),
            OsString::from("ewf"),
            clean_image_arg(e01),
        ];
        let info = self.run_text(TskCommand::ImgStat, args, Duration::from_secs(300))?;
        parse_img_stat_ewf(&info)
    }

    /// 通过 `img_cat -i ewf` 从 EWF 镜像读取单个 512 字节逻辑扇区。
    ///
    /// 注意：Sleuth Kit 4.15 的 `img_cat` 会拒绝 `-s 0` / `-e 0`（提示“must be positive”），
    /// 因此读取 0 号扇区时使用 `-e 1`（读取 0..=1 号扇区）并截取前 512 字节返回。
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

    /// 通过 `img_cat -i ewf` 流式读取 EWF 镜像的完整逻辑内容（回退路径）。
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
        let done_lock = Mutex::new(false);
        let done_cvar = Condvar::new();
        let kill_reason = AtomicU8::new(KILL_NONE);
        let deadline = Instant::now() + timeout;

        thread::scope(|s| {
            let watchdog = s.spawn(|| {
                let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                while !*done {
                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                        kill_reason.store(KILL_CANCELLED, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        kill_reason.store(KILL_TIMEOUT, Ordering::Release);
                        terminator.terminate();
                        break;
                    }
                    let wait = Duration::from_millis(20)
                        .min(deadline.saturating_duration_since(now));
                    let (guard, _) = done_cvar
                        .wait_timeout(done, wait)
                        .unwrap_or_else(|e| e.into_inner());
                    done = guard;
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

            {
                let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
                *done = true;
                done_cvar.notify_one();
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = watchdog.join();
            outcome
        })
    }
}

/// 将 `mmls` 文本输出解析为 [`PartitionInfo`] 列表（过滤掉 Unallocated 与 Extended 分区）。
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

/// `fls` bodyfile 流式解析汇总结果，保留有效条目以及单行容错统计。
#[derive(Debug, Clone, Default)]
pub struct FlsParseSummary {
    /// 成功解析的目录与文件条目列表。
    pub entries: Vec<InventoryEntry>,
    /// 因格式异常而被优雅跳过的非空行数。
    pub skipped_lines: usize,
    /// 经由有损编码降级解码的行数（用于诊断损坏或混合编码文件名）。
    pub lossy_decoded_lines: usize,
}

/// 将 `fls` 单行原始字节解码为字符串，并返回 `(解码结果, 是否触发有损降级)`：
/// 1. 优先零拷贝 `std::str::from_utf8`（同时覆盖纯 ASCII 及 UTF-8 中文/日韩文/Emoji 文件名）；
/// 2. 若非有效 UTF-8，回退 Windows `CP_ACP` 严格解码；
/// 3. 若仍失败，仅对该单行采用 `String::from_utf8_lossy` 有损降级解码（既保留合法 UTF-8 片段，
///    也避免 DBCS 孤立高位字节吞掉后续 ASCII 分隔符 `|`），防止损坏文件名中断整盘扫描。
pub fn decode_fls_line(raw_line: &[u8]) -> (Cow<'_, str>, bool) {
    if let Ok(utf8) = std::str::from_utf8(raw_line) {
        return (Cow::Borrowed(utf8), false);
    }
    if let Ok(acp) = decode_acp_strict(raw_line) {
        return (Cow::Owned(acp), false);
    }
    (String::from_utf8_lossy(raw_line), true)
}

/// 从 `fls -m /` 原始字节流中逐行解码并容错解析 bodyfile 条目：
/// 保留 [`parse_bodyfile_line`] 的严格字段边界校验，遇到单条格式异常行时优雅跳过并计数，
/// 确保不会因个别损坏记录中断整盘分区索引。
pub fn parse_fls_bodyfile_reader<R: BufRead>(
    reader: &mut R,
    offset: u64,
    deleted: bool,
    cancel: Option<&AtomicBool>,
) -> EngineResult<FlsParseSummary> {
    let mut entries = Vec::new();
    let mut skipped_lines: usize = 0;
    let mut lossy_decoded_lines: usize = 0;
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
        if raw_line.is_empty() {
            line_index += 1;
            continue;
        }

        let (decoded, used_lossy) = decode_fls_line(&raw_line);
        if used_lossy {
            lossy_decoded_lines += 1;
        }
        match parse_bodyfile_line(&decoded, offset, deleted) {
            Ok(entry) => entries.push(entry),
            Err(_) => {
                // 单条 bodyfile 格式异常仅记录计数并优雅跳过，不中断其余条目解析。
                skipped_lines += 1;
            }
        }
        line_index += 1;
    }

    Ok(FlsParseSummary {
        entries,
        skipped_lines,
        lossy_decoded_lines,
    })
}

/// 解析单行 `fls -m /` bodyfile 输出，与 `forensic/engines/tsk.py::_body_entries` 行为一致。
pub fn parse_bodyfile_line(
    line: &str,
    offset: u64,
    deleted: bool,
) -> EngineResult<InventoryEntry> {
    let invalid_line = || {
        let preview: String = line.chars().take(150).collect();
        EngineError::TskFailed {
            command: "fls".to_string(),
            message: format!("无法解析 fls bodyfile 行：{preview}"),
        }
    };
    // 从右侧切分末尾 9 个固定字段，保留路径中可能包含的 `|`，避免分配 Vec<&str> 与 join。
    let mut rev = line.rsplitn(10, '|');
    let crtime_s = rev.next().ok_or_else(invalid_line)?;
    let ctime_s = rev.next().ok_or_else(invalid_line)?;
    let mtime_s = rev.next().ok_or_else(invalid_line)?;
    let atime_s = rev.next().ok_or_else(invalid_line)?;
    let size_s = rev.next().ok_or_else(invalid_line)?;
    let _gid = rev.next().ok_or_else(invalid_line)?;
    let _uid = rev.next().ok_or_else(invalid_line)?;
    let mode_s = rev.next().ok_or_else(invalid_line)?;
    let inode_s = rev.next().ok_or_else(invalid_line)?;
    let prefix = rev.next().ok_or_else(invalid_line)?;
    let (_, raw_path) = prefix.split_once('|').ok_or_else(invalid_line)?;

    let size = size_s.parse::<u64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls 文件长度解析失败（{size_s}）：{e}"),
    })?;
    let atime = atime_s.parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls atime 解析失败（{atime_s}）：{e}"),
    })?;
    let mtime = mtime_s.parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls mtime 解析失败（{mtime_s}）：{e}"),
    })?;
    let ctime = ctime_s.parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls ctime 解析失败（{ctime_s}）：{e}"),
    })?;
    let crtime = crtime_s.parse::<i64>().map_err(|e| EngineError::TskFailed {
        command: "fls".to_string(),
        message: format!("fls crtime 解析失败（{crtime_s}）：{e}"),
    })?;

    let mut path_str = raw_path.trim_start_matches('/');
    let reallocated = deleted && path_str.ends_with(" (deleted-realloc)");
    if deleted {
        if let Some(stripped) = path_str.strip_suffix(" (deleted-realloc)") {
            path_str = stripped;
        } else if let Some(stripped) = path_str.strip_suffix(" (deleted)") {
            path_str = stripped;
        }
    }
    let directory = mode_s.starts_with('d') || mode_s.starts_with('V');

    Ok(InventoryEntry {
        path: path_str.to_string(),
        inode: inode_s.to_string(),
        mode: mode_s.to_string(),
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

/// 将 `img_stat -i ewf` 的输出解析为 `(logical_size, sector_size)`。
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
