# TraceDesk Rust + Tauri 2 迁移性能对比实测

本文记录 TraceDesk 由 Python 3.13 + PySide6 架构全面迁移至 **Rust (`--release`) + Tauri 2 + React/TypeScript** 架构后的实测性能对比、Release 产物指标、原生冒烟实测及双向数据兼容性验证结果。

## 1. 测试环境

| 项目 | 规格 / 版本 |
| --- | --- |
| 操作系统 | Windows 11 (`10.0.26300`) x86_64 |
| 处理器 | Intel(R) Core(TM) i9-14900HX（24 核 32 逻辑线程） |
| 物理内存 | 31.6 GiB |
| Rust 工具链 | `rustc 1.100.0` / `cargo 1.100.0`（Edition 2024，`--release` 优化构建） |
| 前端工具链 | Node.js `v24.19.0` / npm `11.17.0` / Vite `6.4.6` / React `19.1` / Tauri `2` |
| Python 对比基线 | Python `3.13.12`（项目 `.venv`，PySide6 + `pytsk3` + `libewf-python` + `mcp`） |
| 外部只读取证工具 | 官方 Windows 版 The Sleuth Kit `4.15.0`（未作二进制修改） |

## 2. Rust (`--release`) vs Python 3.13 性能实测对比

以下基线数据由同一台测试机分别运行原 Python 基准套件与 Rust `tracedesk-cli bench`（`--release`）实测采集。

### 2.1 核心数据结构与取证算法基准

| 测试场景 | 数据规模 | Python 3.13 (ms) | Rust `--release` (ms) | 加速比 |
| --- | --- | ---: | ---: | ---: |
| 10 万条清单 Gzip (`level=1`) 写入 | 100,000 条 | 523.44 | 63.03 | **8.30×** |
| 10 万条清单 Gzip (`level=1`) 读取 | 100,000 条 | 372.27 | 87.94 | **4.23×** |
| 40 万条 MACB 时间线构建与排序 | 400,000 事件 | 108.19 | 5.51 | **19.64×** |
| 40 万条 MACB 筛选项提取 | 400,000 事件 | 36.90 | 1.92 | **19.22×** |
| 40 万条 MACB 事件+关键词筛选 | 命中 1,000 条 | 420.54 | 1.39 | **302.55×** |
| 40 万条 MACB 事件+状态筛选 | 命中 5,000 条 | 142.48 | 1.52 | **93.74×** |
| 40 万条 MACB 全量日期关键词扫描 | 命中 400,000 条 | 1,861.81 | 7.36 | **252.96×** |
| 50 万簇 FAT32 非稀疏混合簇映射 | 500,000 簇 / 246 MiB | 11,563.17 | 20.98 | **551.15×** |
| 50 万簇 FAT32 全零快路径映射 | 500,000 簇 / 246 MiB | 34.10 | 17.13 | **1.99×** |
| 连续 200 次审计链追加写入（每次 `fsync`） | 201 条记录 | 8,526.25 | 4,329.17 | **1.97×** |
| 201 条审计链整链 SHA-256 校验 | 201 条记录 | 41.93 | 20.13 | **2.08×** |

> 说明：连续 200 次审计链追加写入受限于磁盘真实 `fsync` 落盘开销（每次写入均需持久化 `audit.jsonl` 与 64 字节 `audit.head` 尾部锚点），Rust 仍将单次平均写入耗时从 `42.63 ms` 压低至 `21.65 ms`。

### 2.2 `demo.dd` 端到端取证闭环耗时（含真实 TSK 外部进程调用）

| 闭环阶段 | Python 3.13 (ms) | Rust `--release` (ms) | 加速比 |
| --- | ---: | ---: | ---: |
| **端到端闭环总耗时** | **1,535.75** | **727.74** | **2.11×** |
| ├─ 载入镜像（SHA-256 + 分区表 + 覆盖评估） | 245.39 | 76.00 | **3.23×** |
| ├─ 全分区扫描（`fls` + FAT 空间区域映射） | 258.79 | 144.01 | **1.80×** |
| ├─ 导出 2 份文件（含前后原镜像校验） | 287.73 | 134.27 | **2.14×** |
| ├─ ASCII 内容搜索（`TraceDesk`） | 97.41 | 28.43 | **3.43×** |
| ├─ UTF-8 中文内容搜索（`取证演示`） | 91.37 | 31.68 | **2.88×** |
| ├─ MACB 时间线构建（18 条事件） | 22.06 | 22.33 | 0.99× |
| ├─ 10 章节 Markdown 报告生成 | 125.38 | 55.06 | **2.28×** |
| ├─ ZIP64 复核包构建 | 207.03 | 180.21 | **1.15×** |
| └─ 复核包独立核验（ZIP 成员摘要 + 27 条审计链） | 94.13 | 1.78 | **52.88×** |

### 2.3 Rust 原生并行吞吐实测（无 Python 对应实现）

| 原生能力 | 测试规模 | 实测耗时 | 实测吞吐 |
| --- | --- | ---: | ---: |
| 纯 Rust EWF1/E01 多段并行解压与 SHA-256 校验（Rayon） | 64 MiB 逻辑介质（4 分段 / 2,048 块） | 127.57 ms | **501.69 MiB/s** |
| `memmem` SIMD (AVX2) + Rayon 多线程内容搜索 | 256 MiB / 32 流 / 256 命中 | 17.31 ms | **14,789.14 MiB/s（14.44 GiB/s）** |

## 3. Release 产物指标与三大二进制真实冒烟测试

执行 `npm.cmd run build`（前端 1.58 s 零错误打包）与 `cargo build --release --workspace`（零警告通过）后，三大原生可执行文件体积及临时目录冒烟结果如下：

| 产物 | 精确字节数 | 体积 (MiB) | 冒烟测试结果 |
| --- | ---: | ---: | --- |
| `target/release/tracedesk-desktop.exe` | 18,803,200 B | 17.93 MiB | 原生桌面窗口正常拉起，稳定存活 2.5 s 无崩溃，`CloseMainWindow` 优雅退出，0 残留进程 |
| `target/release/tracedesk-mcp.exe` | 5,711,360 B | 5.45 MiB | `--transport stdio` 发送 `initialize` + `tools/list`，暖启动 **33.72 ms** 返回全部 **19** 个取证工具（协议 `2025-03-26`） |
| `target/release/tracedesk-cli.exe` | 4,642,816 B | 4.43 MiB | `run-demo --cases-dir <temp>` 全流程退出码 0，总耗时 **1,057.28 ms**，ZIP64 复核包自验签 **1.20 ms**（`核验通过：10 份材料及审计链。`） |

对比原 Python 打包方案（需附带完整 Python 解释器、PySide6/Qt 6 运行库与多项原生轮子，整体目录通常超过数百 MiB），Rust + Tauri 2 复用系统 WebView2，核心桌面宿主、MCP 服务端与 CLI 三个原生可执行文件合计仅 **27.81 MiB**，零 Python 运行时依赖。

## 4. 双向格式与证据链兼容性验证结论

1. **规范化 JSON 字节级一致**：全工作区 `serde_json` 保持默认 `BTreeMap` 字典序（未启用 `preserve_order`），自定义规范化序列化输出与 Python `json.dumps(..., ensure_ascii=False, sort_keys=True, separators=(',', ':'))` 逐字节完全一致。
2. **审计哈希链与锚点格式一致**：`audit.head` 严格输出精确 64 字节 ASCII 十六进制摘要（不含尾部换行符）；Rust `Case::open` 可无损打开 Python 3.13 生成的黄金案件（`GOLDEN-2026-001`），完整验证全部 27 条审计记录（链尾 `c7c6169c...`）、13 条文件清单、18 条 MACB 时间线事件与 2 条导出记录。
3. **复核包双向互验通过**：
   - Python 生成的黄金复核包 ZIP（10 份材料）通过原生 Rust `tracedesk-core::verify_bundle` 与 `tracedesk-cli verify-bundle` 零错误核验；
   - Rust 生成的 ZIP64 复核包（12 份材料）同时通过原生 Rust `verify_bundle` 与包内嵌入的独立 `verify_bundle.py` 双向核验通过。
4. **纯 Rust 零 Python 环境自包含验证**：`crates/tracedesk-core/tests/` 已解除对外部基线与 Python 解释器的硬依赖，在无 Python 环境下 `cargo clippy --workspace --all-targets -- -D warnings` 与 `cargo test --workspace` 100% 零警告自包含通过。
