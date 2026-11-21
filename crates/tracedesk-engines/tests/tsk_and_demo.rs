use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use tracedesk_engines::tsk::{parse_bodyfile_line, parse_mmls_output};
use tracedesk_engines::{
    EngineError, EntryReadPlan, TskCli, TskCommand, VolumeReader, map_fat_regions, sha256_file,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[derive(Deserialize)]
struct DemoManifest {
    image_sha256: String,
    files: HashMap<String, ManifestFile>,
}

#[derive(Deserialize)]
struct ManifestFile {
    size: u64,
    sha256: String,
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn test_tsk_whitelist_and_parsers() {
    for ok_cmd in ["mmls", "fsstat", "fls", "icat", "img_stat", "img_cat"] {
        assert!(TskCommand::parse_whitelisted(ok_cmd).is_ok());
    }
    for bad_cmd in ["cmd", "powershell", "tsk_recover", "istat", "sh", ""] {
        let err = TskCommand::parse_whitelisted(bad_cmd).unwrap_err();
        assert!(matches!(err, EngineError::TskCommandDenied(_)));
    }

    // Both DOS (`000:000`) and GPT (`000`) slot formats must be recognized.
    for slot in ["000", "000:000"] {
        let sample = format!(
            "000: Meta 0000000000 0000000033 0000000034 Table\n\
             001: ------- 0000000034 0000002047 0000002014 Unallocated\n\
             002: {slot} 0000002048 0000018431 0000016384 FAT16\n\
             003: 000:001 0000018432 0000020000 0000001569 Extended (0x05)\n"
        );
        let parts = parse_mmls_output(&sample);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].offset, 2048);
        assert_eq!(parts[0].description, "FAT16");
    }

    // Bodyfile parser: pipe in path, deleted vs deleted-realloc, normal file ending with " (deleted)".
    let normal = parse_bodyfile_line(
        "0|/DIR/a|b (deleted)|15|r/rrwxrwxrwx|0|0|128|1|2|3|4",
        2048,
        false,
    )
    .unwrap();
    assert_eq!(normal.path, "DIR/a|b (deleted)");
    assert!(!normal.deleted);
    assert!(!normal.reallocated);
    assert_eq!(normal.size, 128);

    let del = parse_bodyfile_line(
        "0|/OLD.TXT (deleted)|20|r/rrwxrwxrwx|0|0|50|0|0|0|0",
        2048,
        true,
    )
    .unwrap();
    assert_eq!(del.path, "OLD.TXT");
    assert!(del.deleted);
    assert!(!del.reallocated);

    let realloc = parse_bodyfile_line(
        "0|/REUSED.TXT (deleted-realloc)|21|-/rrwxrwxrwx|0|0|64|0|0|0|0",
        2048,
        true,
    )
    .unwrap();
    assert_eq!(realloc.path, "REUSED.TXT");
    assert!(realloc.deleted);
    assert!(realloc.reallocated);
}

#[test]
fn test_demo_dd_full_pipeline_and_volume_reader_parity() {
    let root = repo_root();
    let demo = root.join("evidence").join("demo.dd");
    let manifest: DemoManifest = serde_json::from_str(
        &fs::read_to_string(root.join("evidence").join("demo.manifest.json")).unwrap(),
    )
    .unwrap();

    assert_eq!(sha256_file(&demo, None, None).unwrap(), manifest.image_sha256);

    let tsk = TskCli::discover(None).expect("discover bundled TSK");
    assert!(!tsk.version().unwrap().is_empty());

    // 1. inspect
    let (layout, partitions) = tsk.inspect(&demo).expect("inspect demo.dd");
    assert!(layout.contains("DOS Partition Table"));
    assert_eq!(partitions.len(), 1);
    assert_eq!(partitions[0].offset, 2048);
    assert!(partitions[0].description.contains("FAT16"));

    // 2. fsstat + fsstat_to_file
    let fsstat_full = tsk.fsstat(&demo, 2048, false).expect("fsstat full");
    assert!(fsstat_full.contains("File System Type: FAT16"));
    let fsstat_type = tsk.fsstat(&demo, 2048, true).expect("fsstat type");
    assert_eq!(fsstat_type.trim().to_ascii_uppercase(), "FAT16");

    let tmp = tempfile::tempdir().unwrap();
    let fsstat_file = tmp.path().join("fsstat.txt");
    tsk.fsstat_to_file(&demo, 2048, &fsstat_file).unwrap();
    assert_eq!(fs::read_to_string(&fsstat_file).unwrap(), fsstat_full);

    // 3. list_entries (concurrent -u & -d)
    let mut entries = tsk
        .list_entries(&demo, 2048, true, None, "", None)
        .expect("list_entries");
    assert_eq!(entries.len(), 10);

    // Verify UTC mtime on README.TXT matches golden baseline (2026-09-01 08:05 UTC).
    let readme = entries.iter().find(|e| e.path == "README.TXT").unwrap();
    assert_eq!(readme.mtime, 1788249900);

    // Verify single-directory listing with dir_inode + prefix_path.
    let docs_dir = entries.iter().find(|e| e.path == "DOCS").unwrap();
    assert!(docs_dir.directory);
    let docs_children = tsk
        .list_entries(&demo, 2048, false, Some(&docs_dir.inode), "DOCS", None)
        .expect("list DOCS");
    assert!(docs_children.iter().any(|e| e.path == "DOCS/CASE.TXT"));

    // Pre-cancelled list_entries returns Cancelled immediately.
    let cancel = AtomicBool::new(true);
    assert!(
        tsk.list_entries(&demo, 2048, true, None, "", Some(&cancel))
            .unwrap_err()
            .is_cancelled()
    );

    // 4. map_fat_regions matches golden case byte-for-byte.
    let regions = map_fat_regions(&demo, 2048, &fsstat_full, &mut entries, None)
        .expect("map_fat_regions");
    assert_eq!(regions.len(), 3);
    assert_eq!(regions[0].path, "(根目录)");
    assert_eq!(regions[0].inode, "2");
    assert_eq!(regions[0].size, 16_384);
    assert_eq!(regions[1].path, "空余空间（未分配簇）");
    assert_eq!(regions[1].size, 8_302_080);
    assert_eq!(regions[1].extents, Some(vec![(1_135_104, 8_302_080)]));
    assert_eq!(regions[2].path, "闲置空间（已分配未关联簇）");
    assert_eq!(regions[2].size, 0);
    assert_eq!(regions[2].extents, Some(vec![]));

    // 5. export_file, stream_entry, and VolumeReader byte-for-byte parity on EVERY manifest file!
    let mut volume = VolumeReader::open(&demo).expect("VolumeReader::open");
    for (rel_path, expected) in &manifest.files {
        let entry = entries
            .iter()
            .find(|e| &e.path == rel_path)
            .unwrap_or_else(|| panic!("missing manifest entry {rel_path}"));
        assert_eq!(entry.size, expected.size);

        // export_file
        let exported = tmp.path().join(rel_path.replace('/', "_"));
        tsk.export_file(&demo, entry.offset, &entry.inode, entry.size, &exported)
            .unwrap();
        assert_eq!(sha256_file(&exported, None, None).unwrap(), expected.sha256);

        // stream_entry
        let mut streamed = Vec::new();
        let (written, note) = tsk
            .stream_entry(&demo, entry, None, |chunk| {
                streamed.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(written, expected.size);
        assert!(note.is_empty());
        assert_eq!(sha256_hex(&streamed), expected.sha256);

        // VolumeReader plan_entry & full read
        match volume.plan_entry(entry, b"TraceDesk") {
            EntryReadPlan::Direct {
                intervals,
                total_size,
            } => {
                assert_eq!(total_size, expected.size);
                assert_eq!(intervals.len(), 1);
                assert_eq!(intervals[0].start, 0);
                assert_eq!(intervals[0].end, expected.size);
            }
            EntryReadPlan::FallbackToIcat => panic!("expected Direct plan for {rel_path}"),
        }

        let direct = volume
            .read_entry_at(entry, 0, entry.size as usize)
            .expect("VolumeReader full read");
        assert_eq!(direct, streamed, "byte mismatch for {rel_path}");

        // Random sliced read across cluster boundary (especially PAYLOAD.BIN: 1536 bytes = 3 clusters)
        if entry.size > 20 {
            let start = entry.size / 3;
            let len = ((entry.size - start) / 2).max(1) as usize;
            let slice = volume
                .read_entry_at(entry, start, len)
                .expect("VolumeReader slice read");
            assert_eq!(slice, &streamed[start as usize..start as usize + len]);
        }
    }
}

#[test]
fn test_unpartitioned_demo_volume_fallback_offset_zero() {
    let vol = repo_root().join("evidence").join("demo_volume.dd");
    assert!(vol.is_file());
    let tsk = TskCli::discover(None).unwrap();
    let (layout, parts) = tsk.inspect(&vol).expect("inspect demo_volume.dd");
    assert!(layout.contains("偏移 0"));
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].offset, 0);

    let entries = tsk.list_entries(&vol, 0, true, None, "", None).unwrap();
    assert!(entries.iter().any(|e| e.path == "DOCS/CASE.TXT"));
}

#[test]
fn test_deleted_fat_entries_and_idle_clusters() {
    let root = repo_root();
    let demo = root.join("evidence").join("demo.dd");
    let manifest: DemoManifest = serde_json::from_str(
        &fs::read_to_string(root.join("evidence").join("demo.manifest.json")).unwrap(),
    )
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let mutated = tmp.path().join("demo_deleted.dd");
    fs::copy(&demo, &mutated).unwrap();

    // Mirror tests/core/test_workflow.py::test_deleted_records_and_fat_regions
    let volume_base = 2048u64 * 512;
    let root_dir = volume_base + (1 + 2 * 64) * 512;
    let data_base = root_dir + 32 * 512;
    {
        let mut f = OpenOptions::new().read(true).write(true).open(&mutated).unwrap();
        let mut rec = [0u8; 32];
        f.seek(SeekFrom::Start(root_dir)).unwrap();
        f.read_exact(&mut rec).unwrap();
        rec[0] = 0xe5;

        let mut empty = rec;
        empty[26..32].fill(0);

        f.seek(SeekFrom::Start(root_dir + 5 * 32)).unwrap();
        f.write_all(&empty).unwrap();
        f.write_all(&rec).unwrap();

        for fat in [1u64, 65u64] {
            f.seek(SeekFrom::Start(volume_base + fat * 512 + 20 * 2)).unwrap();
            f.write_all(&[0xff, 0xff]).unwrap();
        }
    }

    let tsk = TskCli::discover(None).unwrap();
    let fsstat = tsk.fsstat(&mutated, 2048, false).unwrap();
    let mut entries = tsk.list_entries(&mutated, 2048, true, None, "", None).unwrap();

    // Verify strict ordering: all allocated (-u) entries appear before all deleted (-d) entries.
    let first_del = entries.iter().position(|e| e.deleted).expect("has deleted");
    assert!(entries[..first_del].iter().all(|e| !e.deleted));
    assert!(entries[first_del..].iter().all(|e| e.deleted));

    let regions = map_fat_regions(&mutated, 2048, &fsstat, &mut entries, None).unwrap();

    let deleted: Vec<_> = entries
        .iter()
        .filter(|e| e.deleted && e.path.ends_with("EADME.TXT"))
        .collect();
    assert_eq!(deleted.len(), 2);
    assert_eq!(deleted[0].start_cluster_allocated, None);
    assert_eq!(deleted[1].start_cluster_allocated, Some(true));

    // FAT deleted entries MUST fall back to icat in VolumeReader.
    let mut vol = VolumeReader::open(&mutated).unwrap();
    assert_eq!(
        vol.plan_entry(deleted[1], b"TraceDesk"),
        EntryReadPlan::FallbackToIcat
    );

    // Recovering via stream_entry matches README.TXT SHA-256 (and 0-byte empty returns 0 bytes).
    let (n0, _) = tsk.stream_entry(&mutated, deleted[0], None, |_| Ok(())).unwrap();
    assert_eq!(n0, 0);

    let mut recovered = Vec::new();
    let (n1, _) = tsk
        .stream_entry(&mutated, deleted[1], None, |b| {
            recovered.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(n1, manifest.files["README.TXT"].size);
    assert_eq!(sha256_hex(&recovered), manifest.files["README.TXT"].sha256);

    // Verify idle and free extents match exact expected disk offsets.
    let idle = regions
        .iter()
        .find(|r| r.path == "闲置空间（已分配未关联簇）")
        .unwrap();
    assert_eq!(idle.extents, Some(vec![(data_base + 18 * 512, 512)]));

    let free = regions
        .iter()
        .find(|r| r.path == "空余空间（未分配簇）")
        .unwrap();
    let free_extents = free.extents.as_ref().unwrap();
    assert_eq!(free_extents.len(), 2);
    assert_eq!(free.size, free_extents.iter().map(|(_, l)| *l).sum::<u64>());
}

#[test]
fn test_tsk_bin_dir_normalization_and_no_stray_dest_on_missing_tool() {
    // Discovered bin_dir must always be absolute without Windows `\\?\` verbatim prefix.
    let discovered = TskCli::discover(None).expect("discover TSK");
    assert!(discovered.bin_dir().is_absolute());
    assert!(
        !discovered
            .bin_dir()
            .to_string_lossy()
            .starts_with(r"\\?\")
    );

    // Missing tool in `fsstat_to_file` / `export_file` must fail before creating `dest`.
    let tmp = tempfile::tempdir().unwrap();
    let empty_bin = tmp.path().join("empty_bin");
    fs::create_dir(&empty_bin).unwrap();
    let broken_tsk = TskCli::from_bin_dir(empty_bin);
    let demo = repo_root().join("evidence").join("demo.dd");

    let fsstat_dest = tmp.path().join("should_not_exist_fsstat.txt");
    assert!(broken_tsk.fsstat_to_file(&demo, 2048, &fsstat_dest).is_err());
    assert!(
        !fsstat_dest.exists(),
        "fsstat_to_file must not leave a 0-byte dest file when executable is missing"
    );

    let export_dest = tmp.path().join("should_not_exist_export.bin");
    assert!(
        broken_tsk
            .export_file(&demo, 2048, "3", 65, &export_dest)
            .is_err()
    );
    assert!(
        !export_dest.exists(),
        "export_file must not leave a 0-byte dest file when executable is missing"
    );
}
