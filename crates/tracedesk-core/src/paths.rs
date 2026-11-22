//! 项目资源与运行时目录发现。
//!
//! 在以下环境中保持一致行为：
//! - 开发仓库（`cargo test`、`cargo run`、工作区 crate）
//! - 编译产物目录（`target/release/` 或 `target/debug/`）
//! - 打包后的 Tauri 桌面安装包（`<exe_dir>/resources/` 或 `<exe_dir>/`）

use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// 解析后的 TraceDesk 运行时目录集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub root: PathBuf,
    pub tools_dir: PathBuf,
    pub cases_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub assets_dir: PathBuf,
    pub evidence_dir: PathBuf,
}

/// 去除 Windows 原义路径前缀（`\\?\` / `\\?\UNC\`），使路径符合标准展示形式，
/// 并保持与 32 位 Sleuth Kit 可执行程序及旧版 Python 元数据的兼容性。
pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
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

/// 将已存在路径规范化（不含 Windows `\\?\` 前缀）；若路径尚不存在，则基于当前目录做词法归一化。
pub fn resolve_clean(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return strip_verbatim_prefix(&canon);
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };
    let mut normalized = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    strip_verbatim_prefix(&normalized)
}

/// 若 `path` 位于 `parent` 内部（或与 `parent` 相等）则返回 `true`。
/// 在 Windows 上执行大小写不敏感比较，防止盘符或大小写差异绕过证据隔离边界。
pub fn is_within(path: &Path, parent: &Path) -> bool {
    let p = resolve_clean(path);
    let base = resolve_clean(parent);
    #[cfg(windows)]
    {
        let p_comps: Vec<String> = p
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();
        let b_comps: Vec<String> = base
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();
        p_comps.len() >= b_comps.len() && p_comps[..b_comps.len()] == b_comps[..]
    }
    #[cfg(not(windows))]
    {
        p.starts_with(&base)
    }
}

fn looks_like_repo_root(dir: &Path) -> bool {
    let has_cargo = dir.join("Cargo.toml").is_file();
    let has_forensic = dir.join("forensic").is_dir();
    let has_tools = dir.join("tools").is_dir();
    let has_crates = dir.join("crates").is_dir();
    let has_evidence = dir.join("evidence").is_dir();
    (has_cargo && (has_crates || has_tools || has_forensic))
        || (has_forensic && (has_tools || has_evidence))
}

fn looks_like_packaged_root(dir: &Path) -> bool {
    dir.join("resources").join("tools").is_dir()
        || (dir.join("tools").is_dir()
            && (dir.join("resources").is_dir()
                || dir.join("assets").is_dir()
                || dir.join("cases").is_dir()))
}

fn walk_ancestors_for_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    for _ in 0..8 {
        let dir = cur?;
        if looks_like_repo_root(dir) {
            return Some(strip_verbatim_prefix(dir));
        }
        cur = dir.parent();
    }
    None
}

fn find_tsk_bin_under(dir: &Path, depth: usize) -> Option<PathBuf> {
    if depth == 0 || !dir.is_dir() {
        return None;
    }
    if dir.file_name().is_some_and(|n| n == "bin")
        && (dir.join("fls.exe").is_file() || dir.join("fls").is_file())
    {
        return Some(dir.to_path_buf());
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return None;
    };
    let mut subdirs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();
    for sub in subdirs {
        if let Some(found) = find_tsk_bin_under(&sub, depth - 1) {
            return Some(found);
        }
    }
    None
}

impl AppPaths {
    /// 在开发仓库、`target/release/` 以及打包后的 Tauri 安装布局中自动发现应用目录。
    pub fn discover() -> Self {
        if let Ok(explicit) = env::var("TRACEDESK_ROOT")
            && !explicit.trim().is_empty()
        {
            return Self::from_root(resolve_clean(Path::new(explicit.trim())));
        }

        // 1. 检查可执行文件的祖先目录（兼容 target/debug、target/release、target/*/deps 与 Tauri 安装包）。
        if let Ok(exe) = env::current_exe() {
            let exe = resolve_clean(&exe);
            if let Some(exe_dir) = exe.parent() {
                if let Some(repo_root) = walk_ancestors_for_root(exe_dir) {
                    return Self::from_root(repo_root);
                }
                if looks_like_packaged_root(exe_dir) {
                    return Self::from_packaged_dir(exe_dir.to_path_buf());
                }
            }
        }

        // 2. 检查当前工作目录的祖先目录。
        if let Ok(cwd) = env::current_dir()
            && let Some(repo_root) = walk_ancestors_for_root(&resolve_clean(&cwd))
        {
            return Self::from_root(repo_root);
        }

        // 3. 检查编译期 CARGO_MANIFEST_DIR（开发/测试构建）。
        if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR")
            && let Some(repo_root) = walk_ancestors_for_root(&resolve_clean(Path::new(&manifest_dir)))
        {
            return Self::from_root(repo_root);
        }

        // 4. 回退至可执行文件所在目录或当前工作目录。
        let fallback = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(resolve_clean))
            .or_else(|| env::current_dir().ok().map(|p| resolve_clean(&p)))
            .unwrap_or_else(|| PathBuf::from("."));
        Self::from_root(fallback)
    }

    /// 根据显式指定的项目根目录构建 [`AppPaths`]，并应用可选的环境变量覆盖。
    pub fn from_root(root: PathBuf) -> Self {
        let root = resolve_clean(&root);
        let default_tools = if root.join("tools").is_dir() {
            root.join("tools")
        } else if root.join("resources").join("tools").is_dir() {
            root.join("resources").join("tools")
        } else {
            root.join("tools")
        };
        let default_assets = if root.join("frontend").join("public").join("assets").is_dir() {
            root.join("frontend").join("public").join("assets")
        } else if root.join("resources").join("assets").is_dir() {
            root.join("resources").join("assets")
        } else if root.join("forensic").join("assets").is_dir() {
            root.join("forensic").join("assets")
        } else {
            root.join("assets")
        };
        let mut paths = Self {
            tools_dir: default_tools,
            cases_dir: root.join("cases"),
            logs_dir: root.join("logs"),
            assets_dir: default_assets,
            evidence_dir: root.join("evidence"),
            root,
        };
        paths.apply_env_overrides();
        paths
    }

    /// 为打包后的 Tauri 可执行文件目录构建 [`AppPaths`]。
    pub fn from_packaged_dir(exe_dir: PathBuf) -> Self {
        let root = resolve_clean(&exe_dir);
        let res = root.join("resources");
        let tools_dir = if res.join("tools").is_dir() {
            res.join("tools")
        } else {
            root.join("tools")
        };
        let assets_dir = if res.join("assets").is_dir() {
            res.join("assets")
        } else {
            root.join("assets")
        };
        let mut paths = Self {
            tools_dir,
            cases_dir: root.join("cases"),
            logs_dir: root.join("logs"),
            assets_dir,
            evidence_dir: root.join("evidence"),
            root,
        };
        paths.apply_env_overrides();
        paths
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = env::var("TRACEDESK_TOOLS_DIR")
            && !v.trim().is_empty()
        {
            self.tools_dir = resolve_clean(Path::new(v.trim()));
        }
        if let Ok(v) = env::var("TRACEDESK_CASES_DIR")
            && !v.trim().is_empty()
        {
            self.cases_dir = resolve_clean(Path::new(v.trim()));
        }
        if let Ok(v) = env::var("TRACEDESK_LOGS_DIR")
            && !v.trim().is_empty()
        {
            self.logs_dir = resolve_clean(Path::new(v.trim()));
        }
        if let Ok(v) = env::var("TRACEDESK_ASSETS_DIR")
            && !v.trim().is_empty()
        {
            self.assets_dir = resolve_clean(Path::new(v.trim()));
        }
        if let Ok(v) = env::var("TRACEDESK_EVIDENCE_DIR")
            && !v.trim().is_empty()
        {
            self.evidence_dir = resolve_clean(Path::new(v.trim()));
        }
    }

    /// 在 `TSK_BIN` 或 `self.tools_dir` 中定位 Sleuth Kit 的 `bin` 目录。
    pub fn find_tsk_bin(&self) -> Option<PathBuf> {
        if let Ok(env_bin) = env::var("TSK_BIN")
            && !env_bin.trim().is_empty()
        {
            let p = resolve_clean(Path::new(env_bin.trim()));
            if p.join("fls.exe").is_file() || p.join("fls").is_file() {
                return Some(p);
            }
        }
        find_tsk_bin_under(&self.tools_dir, 3)
    }

    /// 若磁盘上存在独立的 `verify_bundle.py` 脚本，则定位其路径。
    pub fn verify_bundle_script(&self) -> Option<PathBuf> {
        let candidates = [
            self.root
                .join("crates")
                .join("tracedesk-core")
                .join("resources")
                .join("verify_bundle.py"),
            self.root.join("resources").join("verify_bundle.py"),
            self.root.join("scripts").join("verify_bundle.py"),
        ];
        candidates.into_iter().find(|p| p.is_file())
    }
}
