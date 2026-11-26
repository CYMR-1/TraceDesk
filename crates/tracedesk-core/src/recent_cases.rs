//! 跨目录「最近案件」历史持久化与合并管理器。
//!
//! 将用户在不同目录打开或创建的案件记录持久化至 `<logs_dir>/recent-cases.json`
//! （自动遵循 `TRACEDESK_LOGS_DIR` 环境变量以便测试隔离），并在展示时与默认案件根目录
//! `cases_root` 去重合并。所有写盘均经由唯一随机 `.tmp` 文件 + `flush()` + `sync_all()` +
//! 原子 `rename` 完成，且移除历史条目绝不删除磁盘上的任何案件文件。

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
use crate::formatting;
use crate::paths::{AppPaths, resolve_clean};

/// 持久化保留的最近案件历史条目上限。
pub const MAX_RECENT_CASES: usize = 50;
/// 最近案件历史文件格式版本号。
pub const RECENT_CASES_VERSION: u32 = 1;

/// 单条「最近案件」历史持久化记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentCaseRecord {
    /// 规范化后的案件目录路径。
    pub folder: String,
    /// 最近一次打开或创建该案件的时间（UTC+8 ISO-8601 字符串）。
    pub last_opened_at: String,
    /// 是否置顶固定（默认 `false`）。
    #[serde(default)]
    pub pinned: bool,
}

/// 历史清单与 `cases_root` 去重合并后的最近案件条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MergedRecentCase {
    /// 规范化后的案件目录路径。
    pub folder: PathBuf,
    /// 历史清单记录的最近打开时间；仅来自 `cases_root` 扫描时为 `None`。
    pub last_opened_at: Option<String>,
    /// 该条目是否来自持久化历史清单。
    pub in_history: bool,
    /// 是否置顶固定。
    pub pinned: bool,
}

/// `recent-cases.json` 磁盘持久化包装结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecentCasesFile {
    version: u32,
    #[serde(default)]
    items: Vec<RecentCaseRecord>,
}

/// 返回默认的「最近案件」历史文件路径（`<logs_dir>/recent-cases.json`）。
///
/// 底层复用 [`AppPaths::discover`]，自动遵循 `TRACEDESK_LOGS_DIR` 环境变量覆盖。
pub fn default_recent_cases_path() -> PathBuf {
    AppPaths::discover().logs_dir.join("recent-cases.json")
}

/// 规范化案件目录路径：解析绝对路径、剥离 Windows `\\?\` 前缀并去除尾部多余分隔符。
fn normalize_case_folder(path: &Path) -> PathBuf {
    let resolved = resolve_clean(path);
    let mut cleaned = PathBuf::new();
    for comp in resolved.components() {
        cleaned.push(comp.as_os_str());
    }
    if cleaned.as_os_str().is_empty() {
        resolved
    } else {
        cleaned
    }
}

/// 生成路径去重与匹配键（Windows 下大小写不敏感，统一分隔符）。
fn folder_dedup_key(path: &Path) -> String {
    let raw = path.to_string_lossy();
    #[cfg(windows)]
    {
        raw.replace('/', "\\").to_lowercase()
    }
    #[cfg(not(windows))]
    {
        raw.into_owned()
    }
}

/// 解析 UTC+8/ISO-8601 时间字符串为 Unix 纳秒时间戳，便于精确按时间倒序比较。
fn parse_iso_ns(raw: &str) -> Option<i128> {
    let dt = formatting::parse_iso_to_east8(raw)?;
    Some(i128::from(dt.timestamp()) * 1_000_000_000 + i128::from(dt.timestamp_subsec_nanos()))
}

/// 读取文件修改时间（Unix 纳秒），失败返回 `None`。
fn file_mtime_ns(path: &Path) -> Option<i128> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    match modified.duration_since(UNIX_EPOCH) {
        Ok(d) => Some(d.as_nanos() as i128),
        Err(e) => Some(-(e.duration().as_nanos() as i128)),
    }
}

/// 将历史记录列表通过唯一随机 `.tmp` + `flush()` + `sync_all()` + 原子 `rename` 持久化至磁盘。
fn save_recent_cases_file(history_path: &Path, items: &[RecentCaseRecord]) -> CoreResult<()> {
    let parent = history_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let payload = RecentCasesFile {
        version: RECENT_CASES_VERSION,
        items: items.to_vec(),
    };
    let raw = serde_json::to_vec_pretty(&payload)?;

    let tmp_path = parent.join(format!("recent-cases.{}.tmp", Uuid::new_v4().simple()));
    let write_res = (|| -> CoreResult<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        f.write_all(&raw)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    if let Err(err) = fs::rename(&tmp_path, history_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(CoreError::Io(err));
    }
    Ok(())
}

/// 在保留置顶记录的前提下，将历史清单截断至不超过 [`MAX_RECENT_CASES`] 条。
fn truncate_recent_records(records: &mut Vec<RecentCaseRecord>) {
    if records.len() <= MAX_RECENT_CASES {
        return;
    }
    // 优先从尾部淘汰未置顶的较旧条目，避免普通打开记录挤掉已置顶案件。
    while records.len() > MAX_RECENT_CASES {
        if let Some(pos) = records.iter().rposition(|r| !r.pinned) {
            records.remove(pos);
        } else {
            records.pop();
        }
    }
}

/// 将案件目录记录到默认最近案件历史文件中（更新时间戳并移至最前）。
pub fn record_recent_case(folder: &Path) -> CoreResult<()> {
    record_recent_case_at(&default_recent_cases_path(), folder)
}

/// 将案件目录记录到指定历史文件中（更新时间戳并移至最前，保留原有 `pinned` 状态）。
pub fn record_recent_case_at(history_path: &Path, folder: &Path) -> CoreResult<()> {
    if folder.as_os_str().is_empty() {
        return Err(CoreError::InvalidInput("案件目录路径不能为空".to_string()));
    }

    let normalized = normalize_case_folder(folder);
    let normalized_str = normalized.to_string_lossy().into_owned();
    let target_key = folder_dedup_key(&normalized);

    let existing = list_recent_case_records_at(history_path);
    let mut preserved_pinned = false;
    let mut deduped: Vec<RecentCaseRecord> = Vec::with_capacity(existing.len().min(MAX_RECENT_CASES) + 1);
    let mut seen_keys: HashSet<String> = HashSet::new();
    seen_keys.insert(target_key.clone());

    for item in existing {
        if item.folder.trim().is_empty() {
            continue;
        }
        let item_norm = normalize_case_folder(Path::new(&item.folder));
        let item_key = folder_dedup_key(&item_norm);
        if item_key == target_key {
            if item.pinned {
                preserved_pinned = true;
            }
            continue;
        }
        if seen_keys.insert(item_key) {
            deduped.push(RecentCaseRecord {
                folder: item_norm.to_string_lossy().into_owned(),
                last_opened_at: item.last_opened_at,
                pinned: item.pinned,
            });
        }
    }

    let mut next_records = Vec::with_capacity(deduped.len() + 1);
    next_records.push(RecentCaseRecord {
        folder: normalized_str,
        last_opened_at: formatting::now(),
        pinned: preserved_pinned,
    });
    next_records.extend(deduped);
    truncate_recent_records(&mut next_records);

    save_recent_cases_file(history_path, &next_records)
}

/// 仅从默认最近案件历史清单中移除对应路径（绝不删除磁盘上的任何案件文件）。
pub fn remove_recent_case(folder: &Path) -> CoreResult<bool> {
    remove_recent_case_at(&default_recent_cases_path(), folder)
}

/// 仅从指定历史清单中移除对应路径（Windows 大小写不敏感匹配，绝不删除磁盘上的任何案件文件）。
pub fn remove_recent_case_at(history_path: &Path, folder: &Path) -> CoreResult<bool> {
    if folder.as_os_str().is_empty() || !history_path.is_file() {
        return Ok(false);
    }

    let normalized = normalize_case_folder(folder);
    let target_key = folder_dedup_key(&normalized);

    let existing = list_recent_case_records_at(history_path);
    let orig_len = existing.len();
    let remaining: Vec<RecentCaseRecord> = existing
        .into_iter()
        .filter(|item| {
            let item_norm = normalize_case_folder(Path::new(&item.folder));
            folder_dedup_key(&item_norm) != target_key
        })
        .collect();

    if remaining.len() == orig_len {
        return Ok(false);
    }
    save_recent_cases_file(history_path, &remaining)?;
    Ok(true)
}

/// 读取默认最近案件历史记录列表；若文件不存在、版本不符或 JSON 损坏，安全返回空列表。
pub fn list_recent_case_records() -> Vec<RecentCaseRecord> {
    list_recent_case_records_at(&default_recent_cases_path())
}

/// 读取指定历史文件中的最近案件记录列表；若文件不存在、版本不符或 JSON 损坏，安全返回空列表。
pub fn list_recent_case_records_at(history_path: &Path) -> Vec<RecentCaseRecord> {
    let Ok(raw) = fs::read(history_path) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_slice::<RecentCasesFile>(&raw) else {
        return Vec::new();
    };
    if parsed.version != RECENT_CASES_VERSION {
        return Vec::new();
    }
    parsed
        .items
        .into_iter()
        .filter(|item| !item.folder.trim().is_empty())
        .collect()
}

/// 内部合并排序候选条目。
struct MergeCandidate {
    merged: MergedRecentCase,
    opened_at_ns: Option<i128>,
    case_json_mtime_ns: Option<i128>,
    sort_key: String,
}

/// 将默认历史清单与 `cases_root` 下的有效案件目录去重合并并按规则排序返回前 `limit` 条。
pub fn merge_recent_case_folders(cases_root: &Path, limit: usize) -> Vec<MergedRecentCase> {
    merge_recent_case_folders_at(&default_recent_cases_path(), cases_root, limit)
}

/// 将指定历史清单与 `cases_root` 下的有效案件目录去重合并并按规则排序返回前 `limit` 条。
///
/// 合并与排序规则：
/// 1. 过滤掉磁盘上已不存在 `case.json` 的失效历史条目；
/// 2. 扫描 `cases_root` 下一级包含 `case.json` 的目录，按规范化路径去重（Windows 大小写不敏感）；
/// 3. 按 `pinned` 优先 → 有 `last_opened_at` 的按时间倒序 → 其余 `cases_root` 目录按 `case.json`
///    修改时间倒序排列，最终截取前 `limit` 条返回。
pub fn merge_recent_case_folders_at(
    history_path: &Path,
    cases_root: &Path,
    limit: usize,
) -> Vec<MergedRecentCase> {
    if limit == 0 {
        return Vec::new();
    }

    let mut seen_keys: HashSet<String> = HashSet::new();
    let mut candidates: Vec<MergeCandidate> = Vec::new();

    // 1. 读取持久化历史清单，过滤失效目录。
    for rec in list_recent_case_records_at(history_path) {
        let folder = normalize_case_folder(Path::new(&rec.folder));
        let case_json = folder.join("case.json");
        if !case_json.is_file() {
            continue;
        }
        let key = folder_dedup_key(&folder);
        if !seen_keys.insert(key.clone()) {
            continue;
        }
        let last_opened = (!rec.last_opened_at.trim().is_empty()).then_some(rec.last_opened_at);
        let opened_at_ns = last_opened.as_deref().and_then(parse_iso_ns);
        let case_json_mtime_ns = file_mtime_ns(&case_json);
        candidates.push(MergeCandidate {
            merged: MergedRecentCase {
                folder,
                last_opened_at: last_opened,
                in_history: true,
                pinned: rec.pinned,
            },
            opened_at_ns,
            case_json_mtime_ns,
            sort_key: key,
        });
    }

    // 2. 扫描默认案件根目录下一级包含 `case.json` 的目录并去重补充。
    if let Ok(read_dir) = fs::read_dir(cases_root) {
        for entry in read_dir.flatten() {
            let child = entry.path();
            if !child.is_dir() {
                continue;
            }
            let case_json = child.join("case.json");
            if !case_json.is_file() {
                continue;
            }
            let folder = normalize_case_folder(&child);
            let key = folder_dedup_key(&folder);
            if !seen_keys.insert(key.clone()) {
                continue;
            }
            let case_json_mtime_ns = file_mtime_ns(&case_json);
            candidates.push(MergeCandidate {
                merged: MergedRecentCase {
                    folder,
                    last_opened_at: None,
                    in_history: false,
                    pinned: false,
                },
                opened_at_ns: None,
                case_json_mtime_ns,
                sort_key: key,
            });
        }
    }

    // 3. 按 pinned → last_opened_at 倒序 → case.json 修改时间倒序 → 路径确定性排序。
    candidates.sort_by(|a, b| {
        b.merged
            .pinned
            .cmp(&a.merged.pinned)
            .then_with(|| {
                b.merged
                    .last_opened_at
                    .is_some()
                    .cmp(&a.merged.last_opened_at.is_some())
            })
            .then_with(|| b.opened_at_ns.cmp(&a.opened_at_ns))
            .then_with(|| b.merged.last_opened_at.cmp(&a.merged.last_opened_at))
            .then_with(|| b.case_json_mtime_ns.cmp(&a.case_json_mtime_ns))
            .then_with(|| a.sort_key.cmp(&b.sort_key))
    });

    candidates
        .into_iter()
        .take(limit)
        .map(|c| c.merged)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    /// 在指定目录创建一个最小有效的模拟案件目录（包含 `case.json`）。
    fn create_mock_case_dir(dir: &Path) {
        fs::create_dir_all(dir).expect("创建模拟案件目录");
        fs::write(dir.join("case.json"), r#"{"id":"mock"}"#).expect("写入模拟 case.json");
    }

    #[test]
    fn record_cross_directory_and_reopen_moves_to_front_preserving_pinned() {
        let tmp = tempfile::tempdir().expect("创建临时目录");
        let history_path = tmp.path().join("logs").join("recent-cases.json");
        let dir_a = tmp.path().join("disk_d").join("CaseAlpha");
        let dir_b = tmp.path().join("external").join("CaseBeta");
        create_mock_case_dir(&dir_a);
        create_mock_case_dir(&dir_b);

        // 先记录跨目录的两个案件（带尾部斜杠也应规范化）。
        let dir_a_with_slash = PathBuf::from(format!("{}{}", dir_a.display(), std::path::MAIN_SEPARATOR));
        record_recent_case_at(&history_path, &dir_a_with_slash).expect("记录 CaseAlpha");
        thread::sleep(Duration::from_millis(15));
        record_recent_case_at(&history_path, &dir_b).expect("记录 CaseBeta");

        let list = list_recent_case_records_at(&history_path);
        assert_eq!(list.len(), 2);
        assert_eq!(PathBuf::from(&list[0].folder), normalize_case_folder(&dir_b));
        assert_eq!(PathBuf::from(&list[1].folder), normalize_case_folder(&dir_a));

        // 手工将 CaseAlpha 标记为 pinned = true，再重新打开它，应置顶并保留 pinned 状态。
        let mut raw_file: RecentCasesFile =
            serde_json::from_slice(&fs::read(&history_path).expect("读取历史文件"))
                .expect("解析历史 JSON");
        raw_file.items[1].pinned = true;
        save_recent_cases_file(&history_path, &raw_file.items).expect("写回置顶状态");

        thread::sleep(Duration::from_millis(15));
        #[cfg(windows)]
        let reopen_path = PathBuf::from(dir_a.to_string_lossy().to_uppercase());
        #[cfg(not(windows))]
        let reopen_path = dir_a.clone();

        record_recent_case_at(&history_path, &reopen_path).expect("重复打开 CaseAlpha");

        let updated = list_recent_case_records_at(&history_path);
        assert_eq!(updated.len(), 2, "重复打开应去重而非新增条目");
        assert_eq!(PathBuf::from(&updated[0].folder), normalize_case_folder(&dir_a));
        assert!(updated[0].pinned, "重复打开必须保留原有 pinned 状态");
        assert_eq!(PathBuf::from(&updated[1].folder), normalize_case_folder(&dir_b));
        assert!(!updated[1].pinned);
    }

    #[test]
    fn remove_recent_case_does_not_delete_disk_files_and_matches_case_insensitively() {
        let tmp = tempfile::tempdir().expect("创建临时目录");
        let history_path = tmp.path().join("recent-cases.json");
        let case_dir = tmp.path().join("MyCaseFolder");
        create_mock_case_dir(&case_dir);
        let marker = case_dir.join("audit.jsonl");
        fs::write(&marker, "keep-me\n").expect("写入审计哨兵文件");

        record_recent_case_at(&history_path, &case_dir).expect("记录案件");
        assert_eq!(list_recent_case_records_at(&history_path).len(), 1);

        // Windows 下使用不同大小写 + 尾部斜杠路径执行移除。
        #[cfg(windows)]
        let query = PathBuf::from(format!("{}\\", case_dir.to_string_lossy().to_lowercase()));
        #[cfg(not(windows))]
        let query = PathBuf::from(format!("{}/", case_dir.display()));

        let removed = remove_recent_case_at(&history_path, &query).expect("移除历史条目");
        assert!(removed);
        assert!(list_recent_case_records_at(&history_path).is_empty());

        // 再次移除不存在的条目应返回 false。
        let removed_again = remove_recent_case_at(&history_path, &case_dir).expect("二次移除");
        assert!(!removed_again);

        // 严格校验磁盘上的案件目录与文件完好无损。
        assert!(case_dir.is_dir(), "移除历史记录绝不能删除案件目录");
        assert!(case_dir.join("case.json").is_file(), "case.json 必须保留");
        assert_eq!(
            fs::read_to_string(&marker).expect("读取哨兵文件"),
            "keep-me\n"
        );
    }

    #[test]
    fn corrupt_or_incompatible_history_file_returns_empty_safely() {
        let tmp = tempfile::tempdir().expect("创建临时目录");
        let history_path = tmp.path().join("recent-cases.json");

        // 文件不存在时返回空。
        assert!(list_recent_case_records_at(&history_path).is_empty());

        // 损坏 JSON 容错。
        fs::write(&history_path, "{broken json!!!").expect("写入损坏 JSON");
        assert!(list_recent_case_records_at(&history_path).is_empty());

        // 版本号不匹配容错。
        fs::write(
            &history_path,
            r#"{"version":999,"items":[{"folder":"C:\\a","lastOpenedAt":"2026-11-26T10:00:00+08:00"}]}"#,
        )
        .expect("写入不兼容版本 JSON");
        assert!(list_recent_case_records_at(&history_path).is_empty());

        // 损坏文件之后写入新记录能够自动覆盖修复。
        let case_dir = tmp.path().join("RecoveredCase");
        create_mock_case_dir(&case_dir);
        record_recent_case_at(&history_path, &case_dir).expect("自愈写盘");
        let records = list_recent_case_records_at(&history_path);
        assert_eq!(records.len(), 1);
        assert_eq!(PathBuf::from(&records[0].folder), normalize_case_folder(&case_dir));
    }

    #[test]
    fn merge_deduplicates_filters_stale_and_sorts_by_pinned_history_then_mtime() {
        let tmp = tempfile::tempdir().expect("创建临时目录");
        let history_path = tmp.path().join("recent-cases.json");
        let cases_root = tmp.path().join("cases");
        fs::create_dir_all(&cases_root).expect("创建 cases_root");

        // 1. 仅存在于 cases_root 的两个案件（区分 case.json 修改时间先后）。
        let root_older = cases_root.join("root_older");
        let root_newer = cases_root.join("root_newer");
        create_mock_case_dir(&root_older);
        thread::sleep(Duration::from_millis(40));
        create_mock_case_dir(&root_newer);

        // 2. 同时存在于 cases_root 与历史清单的案件（应去重且标记 in_history = true）。
        let shared_case = cases_root.join("shared_case");
        create_mock_case_dir(&shared_case);

        // 3. 位于外部目录的置顶历史案件（时间戳更早，但 pinned = true 必须排第一）。
        let pinned_ext = tmp.path().join("external_drive").join("pinned_ext");
        create_mock_case_dir(&pinned_ext);

        // 4. 位于外部目录的最新普通历史案件。
        let latest_ext = tmp.path().join("external_drive").join("latest_ext");
        create_mock_case_dir(&latest_ext);

        // 5. 已从磁盘删除的失效历史案件（无 case.json，合并时必须过滤）。
        let stale_dir = tmp.path().join("deleted_case");
        fs::create_dir_all(&stale_dir).expect("创建无 case.json 目录");

        // 6. cases_root 下的非案件普通文件夹（无 case.json，必须忽略）。
        fs::create_dir_all(cases_root.join("not_a_case")).expect("创建非案件目录");

        // 构造历史记录文件（包含显式时间与 pinned 标记）。
        let records = vec![
            RecentCaseRecord {
                folder: pinned_ext.to_string_lossy().into_owned(),
                last_opened_at: "2026-11-26T08:00:00+08:00".to_string(),
                pinned: true,
            },
            RecentCaseRecord {
                folder: shared_case.to_string_lossy().into_owned(),
                last_opened_at: "2026-11-26T09:00:00+08:00".to_string(),
                pinned: false,
            },
            RecentCaseRecord {
                folder: latest_ext.to_string_lossy().into_owned(),
                last_opened_at: "2026-11-26T10:30:00+08:00".to_string(),
                pinned: false,
            },
            RecentCaseRecord {
                folder: stale_dir.to_string_lossy().into_owned(),
                last_opened_at: "2026-11-26T11:00:00+08:00".to_string(),
                pinned: true,
            },
        ];
        save_recent_cases_file(&history_path, &records).expect("写入测试历史清单");

        let merged = merge_recent_case_folders_at(&history_path, &cases_root, 10);
        let folders: Vec<PathBuf> = merged.iter().map(|m| m.folder.clone()).collect();

        assert_eq!(
            folders,
            vec![
                normalize_case_folder(&pinned_ext),
                normalize_case_folder(&latest_ext),
                normalize_case_folder(&shared_case),
                normalize_case_folder(&root_newer),
                normalize_case_folder(&root_older),
            ],
            "期望排序：pinned → 历史时间倒序 → cases_root mtime 倒序，并过滤失效与非案件目录"
        );

        assert!(merged[0].pinned && merged[0].in_history);
        assert!(!merged[1].pinned && merged[1].in_history);
        assert!(merged[2].in_history && merged[2].last_opened_at.is_some());
        assert!(!merged[3].in_history && merged[3].last_opened_at.is_none());
        assert!(!merged[4].in_history && merged[4].last_opened_at.is_none());

        // 验证 limit 截断生效。
        let top2 = merge_recent_case_folders_at(&history_path, &cases_root, 2);
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].folder, normalize_case_folder(&pinned_ext));
        assert_eq!(top2[1].folder, normalize_case_folder(&latest_ext));
    }

    #[test]
    fn history_truncates_to_max_recent_cases_and_serializes_camel_case() {
        let tmp = tempfile::tempdir().expect("创建临时目录");
        let history_path = tmp.path().join("recent-cases.json");

        for i in 0..(MAX_RECENT_CASES + 5) {
            let dir = tmp.path().join(format!("case_{i:03}"));
            record_recent_case_at(&history_path, &dir).expect("写入历史记录");
        }

        let records = list_recent_case_records_at(&history_path);
        assert_eq!(records.len(), MAX_RECENT_CASES);
        // 最新写入的应当位于队首。
        assert_eq!(
            PathBuf::from(&records[0].folder),
            normalize_case_folder(&tmp.path().join(format!("case_{:03}", MAX_RECENT_CASES + 4)))
        );

        // 验证 camelCase 字段名。
        let val: serde_json::Value =
            serde_json::from_slice(&fs::read(&history_path).expect("读取历史 JSON"))
                .expect("解析历史 JSON");
        assert_eq!(val["version"].as_u64(), Some(u64::from(RECENT_CASES_VERSION)));
        let first = &val["items"][0];
        assert!(first.get("folder").is_some());
        assert!(first.get("lastOpenedAt").is_some());
        assert!(first.get("pinned").is_some());
    }
}
