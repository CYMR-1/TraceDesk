//! Project resource and runtime directory discovery.
//!
//! Works consistently across:
//! - Development repository (`cargo test`, `cargo run`, workspace crates)
//! - Compiled release binaries (`target/release/` or `target/debug/`)
//! - Packaged Tauri desktop bundles (`<exe_dir>/resources/` or `<exe_dir>/`)

use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Resolved TraceDesk runtime directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub root: PathBuf,
    pub tools_dir: PathBuf,
    pub cases_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub assets_dir: PathBuf,
    pub evidence_dir: PathBuf,
}

/// Strip Windows verbatim path prefixes (`\\?\` / `\\?\UNC\`) so paths match standard display
/// and remain compatible with 32-bit Sleuth Kit executables and legacy Python metadata.
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

/// Canonicalize an existing path cleanly (without Windows `\\?\` prefix), or normalize lexically
/// against the current directory when the path does not yet exist.
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

/// Returns `true` if `path` lies inside (or equals) `parent`.
/// Performs case-insensitive comparison on Windows so drive/casing differences cannot bypass
/// evidence isolation boundaries.
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
    /// Discover application directories automatically across dev repo, `target/release/`,
    /// and packaged Tauri installation layouts.
    pub fn discover() -> Self {
        if let Ok(explicit) = env::var("TRACEDESK_ROOT")
            && !explicit.trim().is_empty()
        {
            return Self::from_root(resolve_clean(Path::new(explicit.trim())));
        }

        // 1. Check executable ancestors (works for target/debug, target/release, target/*/deps, and Tauri bundles).
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

        // 2. Check current working directory ancestors.
        if let Ok(cwd) = env::current_dir()
            && let Some(repo_root) = walk_ancestors_for_root(&resolve_clean(&cwd))
        {
            return Self::from_root(repo_root);
        }

        // 3. Check compile-time CARGO_MANIFEST_DIR (dev/test builds).
        if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR")
            && let Some(repo_root) = walk_ancestors_for_root(&resolve_clean(Path::new(&manifest_dir)))
        {
            return Self::from_root(repo_root);
        }

        // 4. Fallback to executable directory or current working directory.
        let fallback = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(resolve_clean))
            .or_else(|| env::current_dir().ok().map(|p| resolve_clean(&p)))
            .unwrap_or_else(|| PathBuf::from("."));
        Self::from_root(fallback)
    }

    /// Build [`AppPaths`] from an explicit project root directory, honoring optional env overrides.
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

    /// Build [`AppPaths`] for a packaged Tauri executable directory.
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

    /// Locate the Sleuth Kit `bin` directory inside `TSK_BIN` or `self.tools_dir`.
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

    /// Locate the standalone `verify_bundle.py` script if present on disk.
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
