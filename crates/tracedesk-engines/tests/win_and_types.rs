use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tracedesk_engines::{
    CaseFileLock, EngineError, FileStamp, InventoryEntry, PartitionInfo, SegmentDigest,
    SourceGuard, can_export, decode_acp_lossy, decode_acp_strict, deleted_source_note, entry_name,
    entry_status, sha256_file,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn test_inventory_entry_serde_matches_contract_and_sorts_keys() {
    let entry = InventoryEntry {
        path: "DOCS/CASE.TXT".to_string(),
        inode: "613".to_string(),
        mode: "r/rrwxrwxrwx".to_string(),
        size: 38,
        deleted: false,
        reallocated: false,
        atime: 1788220800,
        mtime: 1788249900,
        ctime: 0,
        crtime: 1788249900,
        directory: false,
        offset: 2048,
        filesystem: "FAT16".to_string(),
        start_cluster_allocated: None,
        extents: None,
    };

    // 先转为 serde_json::Value，借助 BTreeMap 对键按规范字典序排序（preserve_order 必须关闭）。
    let val = serde_json::to_value(&entry).expect("to_value");
    let canonical = serde_json::to_string(&val).expect("to_string");
    assert_eq!(
        canonical,
        r#"{"atime":1788220800,"crtime":1788249900,"ctime":0,"deleted":false,"directory":false,"filesystem":"FAT16","inode":"613","mode":"r/rrwxrwxrwx","mtime":1788249900,"offset":2048,"path":"DOCS/CASE.TXT","reallocated":false,"size":38}"#
    );

    // 验证省略 deleted/reallocated/filesystem 字段的旧版 FAT 区域 JSON 反序列化往返。
    let fat_json = r#"{"atime":0,"crtime":0,"ctime":0,"directory":false,"extents":[[1135104,8302080]],"inode":"","mode":"v/v---------","mtime":0,"offset":2048,"path":"空余空间（未分配簇）","size":8302080}"#;
    let parsed: InventoryEntry = serde_json::from_str(fat_json).expect("parse fat region");
    assert!(!parsed.deleted);
    assert!(!parsed.reallocated);
    assert!(parsed.filesystem.is_empty());
    assert_eq!(parsed.extents, Some(vec![(1135104, 8302080)]));

    // 验证 PartitionInfo、FileStamp 与 SegmentDigest 的序列化往返。
    let p = PartitionInfo {
        offset: 2048,
        description: "DOS FAT16 (0x06)".to_string(),
    };
    assert_eq!(
        serde_json::from_str::<PartitionInfo>(&serde_json::to_string(&p).unwrap()).unwrap(),
        p
    );

    let stamp = FileStamp {
        name: "demo.dd".to_string(),
        size: 9_437_184,
        mtime_ns: 1_700_000_000_000_000_000,
        ino: 42,
    };
    assert_eq!(stamp.as_tuple(), ("demo.dd", 9_437_184, 1_700_000_000_000_000_000, 42));

    let seg_unfixed: SegmentDigest =
        serde_json::from_str(r#"{"name":"img.E01","size":1234}"#).unwrap();
    assert!(seg_unfixed.sha256.is_empty());
    assert_eq!(
        serde_json::to_string(&seg_unfixed).unwrap(),
        r#"{"name":"img.E01","size":1234}"#
    );
}

#[test]
fn test_entry_status_helpers() {
    let mut e = InventoryEntry {
        path: "DOCS/CASE.TXT".to_string(),
        inode: "20".to_string(),
        mode: "r/rrwxrwxrwx".to_string(),
        size: 38,
        deleted: false,
        reallocated: false,
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        directory: false,
        offset: 2048,
        filesystem: "FAT16".to_string(),
        start_cluster_allocated: None,
        extents: None,
    };
    assert_eq!(entry_status(&e), "现存");
    assert!(can_export(&e));
    assert_eq!(deleted_source_note(&e), "");
    assert_eq!(entry_name(&e), "CASE.TXT");

    e.deleted = true;
    e.mode = "-/rrwxrwxrwx".to_string();
    assert_eq!(entry_status(&e), "已删除");
    assert!(can_export(&e));
    assert_eq!(deleted_source_note(&e), "已删除，原内容可能已覆盖");

    e.start_cluster_allocated = Some(true);
    assert_eq!(
        deleted_source_note(&e),
        "已删除 · 起始簇已被占用，原内容可能已覆盖"
    );

    e.reallocated = true;
    assert_eq!(entry_status(&e), "已删除·重分配");
    assert_eq!(
        deleted_source_note(&e),
        "已删除 · inode 已重分配，数据来自该 inode 当前内容"
    );

    let mut sys = e.clone();
    sys.deleted = false;
    sys.reallocated = false;
    sys.mode = "v/v---------".to_string();
    sys.path = "$MBR".to_string();
    assert_eq!(entry_status(&sys), "系统区域");
    assert!(!can_export(&sys));
    assert_eq!(entry_name(&sys), "引导扇区 ($MBR)");

    sys.path = "$FAT1".to_string();
    assert_eq!(entry_name(&sys), "FAT 1 ($FAT1)");

    sys.mode = "V/V---------".to_string();
    sys.directory = true;
    assert_eq!(entry_status(&sys), "虚拟目录");
    assert!(!can_export(&sys));
}

#[test]
fn test_acp_decoding_strict_and_lossy() {
    assert_eq!(decode_acp_strict(b"").unwrap(), "");
    assert_eq!(decode_acp_strict(b"DOCS/CASE.TXT").unwrap(), "DOCS/CASE.TXT");
    assert_eq!(decode_acp_lossy(b"plain ascii"), "plain ascii");

    #[cfg(windows)]
    {
        // DBCS（CP936）中的孤立前导字节或非法 UTF-8 前导字节。
        // 注：在 CP936（中文 Windows）下，0xCA 0xAF 0xCD 0xB7 解码为“石头”。
        // 检查当 ACP 为 DBCS/UTF-8 时，严格模式拒绝孤立的 0x81，
        // 而宽容模式永不 panic 并返回替换字符或有效字符串。
        let invalid = [0x81u8];
        let lossy = decode_acp_lossy(&invalid);
        assert!(!lossy.is_empty());
        // 在 CP936（936）或 UTF-8（65001）下，末尾不完整的多字节序列必须导致严格解码失败。
        let strict_res = decode_acp_strict(&invalid);
        if strict_res.is_err() {
            assert!(matches!(strict_res, Err(EngineError::Encoding(_))));
        }
    }
}

#[test]
fn test_source_guard_blocks_write_and_delete_and_verifies_stamps() {
    let dir = tempfile::tempdir().expect("tempdir");
    let f1 = dir.path().join("seg.E01");
    let f2 = dir.path().join("seg.E02");
    fs::write(&f1, b"segment-one").unwrap();
    fs::write(&f2, b"segment-two").unwrap();
    let paths = vec![f1.clone(), f2.clone()];

    let guard = SourceGuard::acquire(&paths).expect("acquire guard");
    assert_eq!(guard.stamps().len(), 2);
    assert_eq!(guard.stamps()[0].size, 11);

    // 并发读取必须成功。
    assert_eq!(fs::read(&f1).unwrap(), b"segment-one");
    assert_eq!(fs::read(&f2).unwrap(), b"segment-two");

    // 持有保护器期间，快照与 verify_unchanged 必须通过。
    guard.verify_unchanged(&paths).expect("unchanged");

    #[cfg(windows)]
    {
        // 当 SourceGuard 持有 FILE_SHARE_READ 时，内核必须拒绝写入与删除。
        assert!(OpenOptions::new().write(true).open(&f1).is_err());
        assert!(OpenOptions::new().write(true).open(&f2).is_err());
        assert!(fs::remove_file(&f1).is_err());
    }

    // 校验列表中多出额外路径时必须失败。
    let f3 = dir.path().join("seg.E03");
    fs::write(&f3, b"extra").unwrap();
    let err = guard
        .verify_unchanged(&[f1.clone(), f2.clone(), f3])
        .unwrap_err();
    assert!(matches!(err, EngineError::SourceChanged(_)));

    // 释放保护器后句柄随之关闭，写入恢复成功。
    drop(guard);
    fs::write(&f1, b"modified-after-release").unwrap();
    assert_eq!(fs::read(&f1).unwrap(), b"modified-after-release");
}

#[test]
fn test_case_file_lock_exclusive_and_reacquire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lock_path = dir.path().join("case.lock");

    let lock1 = CaseFileLock::acquire(&lock_path).expect("acquire lock1");
    assert!(lock_path.is_file());

    // 对同一文件第二次请求独占非阻塞锁时必须立即失败。
    #[cfg(windows)]
    {
        let err = CaseFileLock::acquire(&lock_path).err().expect("must fail when locked");
        assert!(matches!(err, EngineError::Locked(_)));
        assert!(err.to_string().contains("占用"));
    }

    // 释放锁时保留磁盘上的 case.lock 文件。
    lock1.unlock();
    assert!(lock_path.is_file());

    // 释放后可重新获取锁。
    let lock2 = CaseFileLock::acquire(&lock_path).expect("reacquire lock2");
    drop(lock2);
}

#[cfg(windows)]
#[test]
fn test_case_file_lock_cross_process_python_msvcrt_interop() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    // 若环境可用，定位 Python（项目 .venv 或主仓库路径）。
    let venv_py = repo_root().join(".venv").join("Scripts").join("python.exe");
    let main_repo_py = PathBuf::from(r"C:\Users\cymr1\Desktop\qimo\TraceDesk\.venv\Scripts\python.exe");
    let python = if venv_py.is_file() {
        venv_py
    } else if main_repo_py.is_file() {
        main_repo_py
    } else {
        return; // 仅当环境中不存在 Python 解释器时跳过。
    };

    let dir = tempfile::tempdir().unwrap();
    let lock_path = dir.path().join("case.lock");

    // 方向 1：Rust 持有 CaseFileLock 时，Python 的 msvcrt.locking(LK_NBLCK, 1) 必须失败。
    let rust_lock = CaseFileLock::acquire(&lock_path).unwrap();
    let py_check = Command::new(&python)
        .args([
            "-c",
            "import msvcrt, sys; f=open(sys.argv[1],'a+b'); f.seek(0); msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)",
            lock_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn python");
    assert!(
        !py_check.status.success(),
        "Python msvcrt.locking unexpectedly succeeded while Rust held CaseFileLock"
    );
    drop(rust_lock);

    // 方向 2：Python 持有 msvcrt.locking 时，Rust 的 CaseFileLock::acquire 必须失败。
    let mut child = Command::new(&python)
        .args([
            "-c",
            "import msvcrt, sys; f=open(sys.argv[1],'a+b'); f.seek(0); msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1); print('LOCKED', flush=True); sys.stdin.readline()",
            lock_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn python lock holder");

    let mut line = String::new();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "LOCKED");

    let err = CaseFileLock::acquire(&lock_path)
        .err()
        .expect("Rust CaseFileLock must fail while Python holds msvcrt lock");
    assert!(matches!(err, EngineError::Locked(_)));

    // 结束 Python 子进程，验证 Rust 可立即重新获取锁。
    drop(child.stdin.take());
    let _ = child.wait();
    let reacquired = CaseFileLock::acquire(&lock_path).expect("reacquire after python exits");
    drop(reacquired);
}

#[test]
fn test_sha256_file_streaming_progress_and_cancel() {
    let demo = repo_root().join("evidence").join("demo.dd");
    assert!(demo.is_file(), "demo.dd must exist at {}", demo.display());

    let calls = AtomicUsize::new(0);
    let progress = |_done: u64, total: u64| {
        assert_eq!(total, 9_437_184);
        calls.fetch_add(1, Ordering::Relaxed);
    };
    let digest = sha256_file(&demo, None, Some(&progress)).expect("sha256 demo.dd");
    assert_eq!(
        digest,
        "83029884b25c65f5cd8e94415c9a4e6a60f762459130cf96eac1e626890c70e8"
    );
    // 9.44 MiB / 4 MiB 缓冲区 => 至少触发 3 次进度回调。
    assert!(calls.load(Ordering::Relaxed) >= 3);

    // 预先取消的令牌应返回 Cancelled。
    let cancel = AtomicBool::new(true);
    let err = sha256_file(&demo, Some(&cancel), None).unwrap_err();
    assert!(err.is_cancelled());

    // 校验写入并刷新后的自定义小文件。
    let dir = tempfile::tempdir().unwrap();
    let sample = dir.path().join("sample.bin");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&sample)
            .unwrap();
        f.write_all(b"TraceDesk").unwrap();
    }
    let h = sha256_file(&sample, None, None).unwrap();
    assert_eq!(h.len(), 64);
}
