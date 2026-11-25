//! 纯 Rust 确定性 FAT16 取证演示镜像生成器（`make-demo [--out-dir <dir>]`），
//! 与 `scripts/make_demo.py` 实现 100% 逐字节兼容。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracedesk_core::{AppPaths, CoreResult, sha256_hex};

/// 标准分区版 `demo.dd` 镜像的预期 SHA-256（与 `scripts/make_demo.py` 一致）。
pub const EXPECTED_DEMO_DD_SHA256: &str =
    "83029884b25c65f5cd8e94415c9a4e6a60f762459130cf96eac1e626890c70e8";

/// 标准无分区版 `demo_volume.dd` 镜像的预期 SHA-256（与 `scripts/make_demo.py` 一致）。
pub const EXPECTED_DEMO_VOLUME_DD_SHA256: &str =
    "a67bd44a28eb789dc7dbd29c6994ca66a905a96f3166a7312ba4327ee17c5f3d";

/// `<stem>.manifest.json` 中的单个文件摘要条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoFileDigest {
    pub size: usize,
    pub sha256: String,
}

/// 随演示镜像一并生成的清单信息（`<stem>.manifest.json` 与 `<file>.sha256`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoImageManifest {
    pub image_path: PathBuf,
    pub manifest_path: PathBuf,
    pub sha256_path: PathBuf,
    pub image_sha256: String,
    pub image_size: usize,
    pub files: Vec<(String, DemoFileDigest)>,
}

/// [`run_make_demo_command`] 返回的执行摘要。
#[derive(Debug, Clone)]
pub struct MakeDemoSummary {
    pub out_dir: PathBuf,
    pub generated: Vec<DemoImageManifest>,
    pub skipped: Vec<PathBuf>,
}

fn make_fat_dir_entry(
    name: &str,
    cluster: u16,
    size: u32,
    attr: u8,
    fat_time: u16,
    fat_date: u16,
) -> [u8; 32] {
    let mut record = [0u8; 32];
    let mut parts = name.splitn(2, '.');
    let stem = parts.next().unwrap_or("");
    let ext = parts.next().unwrap_or("");
    let formatted = format!("{:<8}{:<3}", stem, ext);
    record[..11].copy_from_slice(&formatted.as_bytes()[..11]);
    record[11] = attr;
    record[14..16].copy_from_slice(&fat_time.to_le_bytes());
    record[16..18].copy_from_slice(&fat_date.to_le_bytes());
    record[18..20].copy_from_slice(&fat_date.to_le_bytes());
    record[22..24].copy_from_slice(&fat_time.to_le_bytes());
    record[24..26].copy_from_slice(&fat_date.to_le_bytes());
    record[26..28].copy_from_slice(&cluster.to_le_bytes());
    record[28..32].copy_from_slice(&size.to_le_bytes());
    record
}

/// 构造确定性 FAT16 演示镜像的原始字节与内置文件载荷列表。
///
/// 当 `include_deleted` 为 `false` 时，输出结果与
/// `scripts/make_demo.py::create(path, partitioned)` 100% 逐字节一致。
/// 当 `include_deleted` 为 `true` 时，会在 `DOCS` 之后额外写入一个已删除的 FAT 目录项
/// （`0xE5` 标记）及对应数据簇，用于测试已删除文件恢复流程。
pub fn build_demo_image_bytes(
    partitioned: bool,
    include_deleted: bool,
) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let sectors: usize = 16_384;
    let fat_size: usize = 64;
    let root_sectors: usize = 32;
    let offset: usize = if partitioned { 2048 } else { 0 };

    let mut image = vec![0u8; (sectors + offset) * 512];
    if partitioned {
        // 偏移 446 处的 MBR 第 1 分区表项：类型 0x06（DOS FAT16），起始扇区=2048，扇区数=16384
        image[446] = 0;
        image[447..450].copy_from_slice(&[0, 2, 0]);
        image[450] = 6;
        image[451..454].copy_from_slice(&[0xff, 0xff, 0xff]);
        image[454..458].copy_from_slice(&(offset as u32).to_le_bytes());
        image[458..462].copy_from_slice(&(sectors as u32).to_le_bytes());
        image[510..512].copy_from_slice(&[0x55, 0xaa]);
    }

    let start = offset * 512;
    let mut boot = [0u8; 512];
    boot[0..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
    boot[3..11].copy_from_slice(b"TRACEDSK");
    // 按小端序写入 FAT16 引导扇区 BPB 字段（对应 struct.pack_into('<HBHBHHBHHHII', ...)）
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&1u16.to_le_bytes());
    boot[16] = 2;
    boot[17..19].copy_from_slice(&512u16.to_le_bytes());
    boot[19..21].copy_from_slice(&(sectors as u16).to_le_bytes());
    boot[21] = 0xf8;
    boot[22..24].copy_from_slice(&(fat_size as u16).to_le_bytes());
    boot[24..26].copy_from_slice(&32u16.to_le_bytes());
    boot[26..28].copy_from_slice(&64u16.to_le_bytes());
    boot[28..32].copy_from_slice(&(offset as u32).to_le_bytes());
    boot[32..36].copy_from_slice(&0u32.to_le_bytes());
    boot[36..39].copy_from_slice(&[0x80, 0x00, 0x29]);
    boot[39..43].copy_from_slice(&20_261_107u32.to_le_bytes());
    boot[43..54].copy_from_slice(b"TRACE DEMO ");
    boot[54..62].copy_from_slice(b"FAT16   ");
    boot[510..512].copy_from_slice(&[0x55, 0xaa]);
    image[start..start + 512].copy_from_slice(&boot);

    let mut fat = vec![0u8; fat_size * 512];
    fat[0..2].copy_from_slice(&0xfff8u16.to_le_bytes());
    fat[2..4].copy_from_slice(&0xffffu16.to_le_bytes());

    let root = start + (1 + 2 * fat_size) * 512;
    let data = root + root_sectors * 512;

    let mut payload_bin = Vec::with_capacity(256 * 6);
    for _ in 0..6 {
        for b in 0..=255u8 {
            payload_bin.push(b);
        }
    }

    let mut payloads: Vec<(String, Vec<u8>)> = vec![
        (
            "README.TXT".to_string(),
            b"TraceDesk forensic demonstration.\r\nRead-only evidence workflow.\r\n".to_vec(),
        ),
        (
            "NOTES.TXT".to_string(),
            "取证演示：证据固定、审计、文件导出。\r\n"
                .as_bytes()
                .to_vec(),
        ),
        (
            "EVENTS.CSV".to_string(),
            b"time,event\r\n2026-09-01T08:00:00Z,login\r\n2026-09-01T08:05:00Z,copy\r\n".to_vec(),
        ),
        ("PAYLOAD.BIN".to_string(), payload_bin),
    ];

    let fat_date: u16 = ((2026 - 1980) << 9) | (9 << 5) | 1;
    let fat_time: u16 = (8 << 11) | (5 << 5);

    let mut cluster: u16 = 2;
    for (i, (name, content)) in payloads.iter().enumerate() {
        let first = cluster;
        let count = content.len().div_ceil(512);
        for n in 0..count {
            let next_val: u16 = if n + 1 < count { cluster + 1 } else { 0xffff };
            let fat_off = (cluster as usize) * 2;
            fat[fat_off..fat_off + 2].copy_from_slice(&next_val.to_le_bytes());

            let chunk = &content[n * 512..((n + 1) * 512).min(content.len())];
            let data_off = data + ((cluster as usize) - 2) * 512;
            image[data_off..data_off + chunk.len()].copy_from_slice(chunk);
            cluster += 1;
        }
        let dir_rec =
            make_fat_dir_entry(name, first, content.len() as u32, 0x20, fat_time, fat_date);
        image[root + i * 32..root + (i + 1) * 32].copy_from_slice(&dir_rec);
    }

    // 添加子目录 `DOCS` 及其嵌套文件 `DOCS/CASE.TXT`
    let folder_cluster = cluster;
    let child_cluster = cluster + 1;
    for c in [folder_cluster, child_cluster] {
        let fat_off = (c as usize) * 2;
        fat[fat_off..fat_off + 2].copy_from_slice(&0xffffu16.to_le_bytes());
    }
    let i = payloads.len();
    let docs_rec = make_fat_dir_entry("DOCS", folder_cluster, 0, 0x10, fat_time, fat_date);
    image[root + i * 32..root + (i + 1) * 32].copy_from_slice(&docs_rec);

    let pos = data + ((folder_cluster as usize) - 2) * 512;
    let mut dot = make_fat_dir_entry("DOCS", folder_cluster, 0, 0x10, fat_time, fat_date);
    dot[..11].copy_from_slice(b".          ");
    image[pos..pos + 32].copy_from_slice(&dot);

    let mut dotdot = dot;
    dotdot[..11].copy_from_slice(b"..         ");
    dotdot[26..28].copy_from_slice(&0u16.to_le_bytes());
    image[pos + 32..pos + 64].copy_from_slice(&dotdot);

    let case_content = b"Case note inside a nested directory.\r\n".to_vec();
    let case_rec = make_fat_dir_entry(
        "CASE.TXT",
        child_cluster,
        case_content.len() as u32,
        0x20,
        fat_time,
        fat_date,
    );
    image[pos + 64..pos + 96].copy_from_slice(&case_rec);
    let child_off = data + ((child_cluster as usize) - 2) * 512;
    image[child_off..child_off + case_content.len()].copy_from_slice(&case_content);
    payloads.push(("DOCS/CASE.TXT".to_string(), case_content));

    if include_deleted {
        // 在根目录槽位 `i + 1` 添加一个未分配的已删除文件目录项（`0xE5` 标记）
        let del_cluster = child_cluster + 1;
        let del_content =
            b"Deleted forensic artifact recoverable via TSK icat -r.\r\n".to_vec();
        let mut del_rec = make_fat_dir_entry(
            "DELETED.TXT",
            del_cluster,
            del_content.len() as u32,
            0x20,
            fat_time,
            fat_date,
        );
        del_rec[0] = 0xe5; // FAT 已删除标记
        let slot = i + 1;
        image[root + slot * 32..root + (slot + 1) * 32].copy_from_slice(&del_rec);
        let del_off = data + ((del_cluster as usize) - 2) * 512;
        image[del_off..del_off + del_content.len()].copy_from_slice(&del_content);
        payloads.push(("DELETED.TXT (deleted)".to_string(), del_content));
    }

    for copy in 0..2 {
        let begin = start + (1 + copy * fat_size) * 512;
        image[begin..begin + fat.len()].copy_from_slice(&fat);
    }

    (image, payloads)
}

fn write_demo_image_files(
    path: &Path,
    partitioned: bool,
    include_deleted: bool,
) -> CoreResult<DemoImageManifest> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let (image, payloads) = build_demo_image_bytes(partitioned, include_deleted);
    let image_sha256 = sha256_hex(&image);

    // 绝不覆盖已有证据文件（保持 Python `open('xb')` 独占创建语义）。
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&image)?;
    file.flush()?;
    drop(file);

    let mut files_map = Map::new();
    let mut files_vec = Vec::with_capacity(payloads.len());
    for (name, content) in &payloads {
        let digest = sha256_hex(content);
        let size = content.len();
        let mut obj = Map::new();
        obj.insert("size".to_string(), Value::from(size as u64));
        obj.insert("sha256".to_string(), Value::String(digest.clone()));
        files_map.insert(name.clone(), Value::Object(obj));
        files_vec.push((name.clone(), DemoFileDigest { size, sha256: digest }));
    }

    let mut root_manifest = Map::new();
    root_manifest.insert(
        "image_sha256".to_string(),
        Value::String(image_sha256.clone()),
    );
    root_manifest.insert("files".to_string(), Value::Object(files_map));

    let manifest_path = path.with_extension("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&Value::Object(root_manifest))?;
    fs::write(&manifest_path, manifest_json.as_bytes())?;

    // 写入配套的 `.sha256` 校验清单文件（格式：`<sha256>  <filename>\n`）。
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "demo.dd".to_string());
    let sha256_path = PathBuf::from(format!("{}.sha256", path.display()));
    fs::write(
        &sha256_path,
        format!("{image_sha256}  {file_name}\n").as_bytes(),
    )?;

    Ok(DemoImageManifest {
        image_path: path.to_path_buf(),
        manifest_path,
        sha256_path,
        image_sha256,
        image_size: image.len(),
        files: files_vec,
    })
}

/// 在 `path` 处生成确定性 FAT16 演示镜像（与 `scripts/make_demo.py::create` 100% 兼容）。
pub fn create_demo_image(path: &Path, partitioned: bool) -> CoreResult<DemoImageManifest> {
    write_demo_image_files(path, partitioned, false)
}

/// 在 `path` 处生成确定性 FAT16 演示镜像，并在根目录额外包含一个已删除目录项（`0xE5`）。
pub fn create_demo_image_with_deleted(
    path: &Path,
    partitioned: bool,
) -> CoreResult<DemoImageManifest> {
    write_demo_image_files(path, partitioned, true)
}

/// 执行 `make-demo [--out-dir <dir>]` 子命令。
///
/// 在 `out_dir`（默认为 `<repo_root>/evidence`）下生成 `demo.dd`（分区镜像）与
/// `demo_volume.dd`（无分区卷镜像），若目标文件已存在则保留且不覆盖。
pub fn run_make_demo_command(out_dir: Option<&Path>) -> CoreResult<MakeDemoSummary> {
    let paths = AppPaths::discover();
    let target_dir = match out_dir {
        Some(d) => d.to_path_buf(),
        None => paths.evidence_dir,
    };
    fs::create_dir_all(&target_dir)?;

    let mut generated = Vec::new();
    let mut skipped = Vec::new();

    for (name, partitioned) in [("demo.dd", true), ("demo_volume.dd", false)] {
        let path = target_dir.join(name);
        if path.exists() {
            println!("已存在，保留： {}", path.display());
            skipped.push(path);
        } else {
            let manifest = create_demo_image(&path, partitioned)?;
            println!(
                "已生成： {} (SHA-256: {})",
                path.display(),
                manifest.image_sha256
            );
            generated.push(manifest);
        }
    }

    Ok(MakeDemoSummary {
        out_dir: target_dir,
        generated,
        skipped,
    })
}
