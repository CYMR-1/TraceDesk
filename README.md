# TraceDesk 电子数据取证工作台

依据课程取证软件开发要求实现的中文原生桌面电子数据取证工作台。项目全面采用 **Rust + Tauri 2 + React 19 / TypeScript** 架构，零 Python 运行时依赖：Rust 核心库负责案件隔离、4 MiB 流式 SHA-256、追加式审计哈希链、纯 Rust EWF1/E01 多段并行解码、FAT/NTFS 底层解析、AVX2 SIMD + Rayon 并行内容搜索、MACB 时间线、Markdown 报告与 ZIP64 可独立核验复核包；随工程分发的官方 Windows 版 The Sleuth Kit 4.15.0 负责只读分区与文件系统扫描；内置标准 MCP 服务端 `tracedesk-mcp` 供外部 AI 客户端接入。所有取证操作均在本地执行，不上传证据。

## 性能实测亮点（Rust `--release` vs Python 3.13）

同一硬件平台（Intel i9-14900HX / Windows 11）下，全面迁移至 Rust + Tauri 2 后的实测提升如下（完整对比与双向兼容性验证见 [Rust 迁移性能对比实测](docs/validation/Rust迁移性能对比实测.md)）：

| 实测指标 | Python 3.13 | Rust `--release` | 提升幅度 |
| --- | ---: | ---: | ---: |
| 50 万簇 FAT32 非稀疏混合簇映射 | 11,563.17 ms | **20.98 ms** | **551.15×** |
| 40 万条 MACB 时间线事件+关键词筛选 | 420.54 ms | **1.39 ms** | **302.55×** |
| 40 万条 MACB 全量日期扫描（40 万命中） | 1,861.81 ms | **7.36 ms** | **252.96×** |
| 复核包独立核验（ZIP 成员摘要 + 审计链） | 94.13 ms | **1.78 ms** | **52.88×** |
| 40 万条 MACB 时间线构建与排序 | 108.19 ms | **5.51 ms** | **19.64×** |
| 10 万条文件清单 Gzip 写入 / 读取 | 523.44 / 372.27 ms | **63.03 / 87.94 ms** | **8.30× / 4.23×** |
| `demo.dd` 端到端闭环总耗时（含真实 TSK） | 1,535.75 ms | **727.74 ms** | **2.11×** |
| 纯 Rust EWF1 多段并行校验 / SIMD 搜索吞吐 | — | **501.69 MiB/s** / **14.44 GiB/s** | 原生并发 |

三大 Release 原生二进制体积紧凑（启用 LTO、符号裁剪、WebP 引导图与可选 `image-preview` 特性）：`tracedesk-desktop.exe` **8.34 MiB**（已内嵌 `frontend/dist` 生产资源）、`tracedesk-mcp.exe` **3.18 MiB**、`tracedesk-cli.exe` **2.72 MiB**。

## 目录导航

| 位置 | 用途 |
| --- | --- |
| `Cargo.toml`、`启动取证工作台.bat` | Rust 工作区（5 个成员）与一键构建/启动入口 |
| `crates/tracedesk-engines/` | 底层只读取证引擎：TSK 白名单、纯 Rust EWF1 并行解码、FAT/NTFS、卷随机读取与 Windows 拒写句柄 |
| `crates/tracedesk-core/` | 案件隔离、SHA-256 审计链、目录树索引、时间线、9 编码与图片预览、SIMD 并行搜索、报告与 ZIP64 复核包 |
| `crates/tracedesk-mcp/` | 标准 MCP 服务端 `tracedesk-mcp.exe`（19 工具 + 2 资源、跨进程实时遥测与统计，支持 `stdio` 与仅回环 `Streamable HTTP`） |
| `crates/tracedesk-cli/` | 命令行工具 `tracedesk-cli.exe`（`run-demo`、`make-demo`、`verify-bundle`、`bench`） |
| `src-tauri/` | Tauri 2 原生桌面宿主 `tracedesk-desktop.exe`（49 项 IPC 命令、8 项流式事件、跨进程 MCP 遥测尾随与内嵌 HTTP MCP 托管） |
| `frontend/` | Vite + React 19 + TypeScript 桌面工作台前端（明净瓷白与晴空蓝浅色视觉规范、虚拟表格、MCP 实时监控主工作区与 9 份图文引导） |
| `scripts/install_tsk.ps1` | 官方 Sleuth Kit 4.15.0 下载与 SHA-256 校验脚本 |
| `docs/` | 目录结构维护指南、设计与验收说明及实测验证记录 |
| `evidence/`、`cases/`、`tools/` | 源证据输入、案件输出目录、官方第三方 TSK 工具 |

完整文件树与“改功能该去哪里”见 [目录结构与维护指南](docs/目录结构.md)；其他资料见 [文档导航](docs/README.md)。

## 环境配置与构建运行

### 1. 构建前置环境（Windows）

- **Rust 工具链**（推荐 `rustc` 1.85+ / Edition 2024，支持 `rsproxy.cn` 镜像加速）：
  ```powershell
  $env:RUSTUP_DIST_SERVER = "https://rsproxy.cn"
  $env:RUSTUP_UPDATE_ROOT = "https://rsproxy.cn/rustup"
  # 从 https://rustup.rs/ 安装 rustup-init.exe（或 winget install Rustlang.Rustup）
  ```
  如需为 `cargo` 配置国内稀疏索引镜像，可在 `%USERPROFILE%\.cargo\config.toml` 中配置 `rsproxy-sparse` 源。
- **Node.js**（v20+，随附 `npm`）
- **Visual Studio Build Tools（MSVC C++ 工具集）** 与 Windows 11 自带的 **WebView2 Runtime**
- **The Sleuth Kit 4.15.0**：本仓库已随附完整官方 Windows 版 TSK 与两份 FAT16 演示镜像；如 `tools/` 缺失，运行 `powershell -File scripts/install_tsk.ps1` 或将环境变量 `TSK_BIN` 指向完整 TSK `bin` 目录（须保留 DLL 与 `licenses/`）。

### 2. 一键启动桌面工作台

双击根目录 **启动取证工作台.bat**：
- 若 `target\release\tracedesk-desktop.exe` 已存在，直接拉起原生桌面工作台并在确认窗口创建后自动关闭启动终端；若启动异常或秒退，会保留终端显示错误并输出 `logs\startup.log`（桌面端同时弹窗提示）；
- 若尚未编译，自动检查 `frontend\dist`（缺失时执行 `npm.cmd ci` 与 `npm.cmd run build`），随后执行 `cargo build --release -p tracedesk-desktop`（默认启用 `custom-protocol` 内嵌前端资源）并启动桌面端。

### 3. 手动编译、运行与测试

```powershell
# 1. 安装前端依赖并构建生产包
Set-Location frontend
npm.cmd ci
npm.cmd run build
Set-Location ..

# 2. Release 全量编译（生成 desktop / mcp / cli 三大原生二进制，0 警告）
cargo build --release --workspace

# 3. 启动原生桌面工作台
.\target\release\tracedesk-desktop.exe

# 4. 静态检查与全工作区自动化测试（含真实 TSK 与双向兼容性测试）
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### 4. CLI 常用子命令（`tracedesk-cli.exe`）

```powershell
# 运行 demo.dd 端到端取证演示并自验签 ZIP64 复核包（默认写入 cases/）
.\target\release\tracedesk-cli.exe run-demo
# 指定自定义案件目录（未设 TRACEDESK_LOGS_DIR 时标记文件写入自定义目录，不覆盖全局 logs/latest-demo.txt）
.\target\release\tracedesk-cli.exe run-demo --cases-dir .\cases

# 重新生成两份自建 FAT16 演示镜像及哈希清单（已存在文件默认保留）
.\target\release\tracedesk-cli.exe make-demo

# 原生高速独立核验复核包 ZIP 与 SHA-256 审计链
.\target\release\tracedesk-cli.exe verify-bundle "复核包路径.zip" --sha256 独立取得的64位摘要

# 运行性能基准测试套件（10 万清单、40 万时间线、50 万 FAT 簇、EWF 并行与 SIMD 搜索）
.\target\release\tracedesk-cli.exe bench
```

## 桌面工作台视觉与操作流程

界面采用 **明净瓷白与晴空蓝（Daylight Porcelain & Cerulean Sky）** 浅色取证视觉规范：顶部明净瓷白命令带（`#FFFFFF`）、带 3 px 语义状态边框的浅冰色案件保管栏（`#F7FAFD`）、薄雾浅蓝模块导航带（`#EFF4F9`，右侧嵌入镜像操作按钮）、纯白证据工作区与浅瓷色底栏；主色晴空蓝（`#2674C4`），提供柔和浅底语义胶囊徽章（现存/已删除/重分配/人工/MCP/MACB 事件）、虚拟滚动表格、本地高 DPI 矢量图标与内置 9 主题图文操作说明（支持高清 Lightbox 大图查看）。

### 完整取证闭环操作

1. **新建/打开案件**：填写编号、取证人员、对象并选择 `cases` 案件库，目录名按“案件编号_取证人员_取证对象”自动生成，重名依次添加 ` (2)`、` (3)`。
2. **加载镜像**：选择 `evidence/demo.dd`（带分区表 FAT16，偏移 2048）或 `evidence/demo_volume.dd`（偏移 0 无分区表卷），自动固定 SHA-256、识别分区、评估卷声明覆盖范围并扫描全部可读分区。
3. **浏览与预览**：左侧按镜像/分区/目录展示完整树，右上列表支持后缀、路径关键词和状态筛选与分页（双击页码跳页），右下支持 9 种文本编码（ASCII、UTF-8、UTF-16LE/BE、GBK、GB18030、Big5、Windows-1252、ISO-8859-1）、十六进制与安全图片缩放预览（单张上限 32 MiB / 4000 万像素，显示副本最长边缩至 4096 px）。所有时间统一展示东八区（UTC+8），未记录时间不误显为 1970 年。
4. **校验与导出**：点击“校验完整性”后选择现存或已删除文件导出至 `exports/`（重名时不再创建子目录，直接在 `exports/` 下于文件名后追加 `(1)`、`(2)` 等序号后缀，如 `NOTES(1).TXT`），导出前后均校验原镜像并记录副本 SHA-256；单文件导出结果弹窗可直接点击“记为取证发现”顺手补录研判笔记。
5. **取证发现与内容搜索**：在文件预览区顶部操作栏或导出结果弹窗可一键点击“记为取证发现”，右键文件亦可记录取证发现、计算单文件 SHA-256 或与本地副本比对；“内容搜索与复核”支持 UTF-8 / UTF-16LE / GBK / HEX 精确字节并行搜索、流式实时展示、三态全选、分区偏移筛选、排除与批量保存为取证发现；“取证发现”页支持按文件归组查看并一键批量导出副本与汇总清单。
6. **时间线、审计、报告与复核包**：在“MACB 时间线”“审计日志”“取证发现”中双击打开底部双栏详情（支持在吸顶详情栏右上角点击 `× 关闭` 随时收起；审计日志区分 `[人工]` 与 `[MCP · <使用者>]` 来源、支持按调用方精筛并展示前后哈希），点击“生成 Markdown 报告”输出 10 章节中文报告，点击“导出复核包”按需勾选导出副本与搜索记录生成 ZIP64 复核包及 `.zip.sha256`（包内同时附带独立 `verify_bundle.py`，也可使用 `tracedesk-cli verify-bundle` 毫秒级核验）。
7. **MCP 实时监控**：切换至主工作区 **MCP 实时监控** 标签页（或在顶部 **MCP 服务** 按钮查看实时脉冲指示），即时透视外部 AI 客户端每一步工具调用的起止过程、入参 JSON 与返回预览、19 项工具调用统计及案件热刷新状态。

## 大容量镜像（≥1 GiB）

逻辑容量达到 **1 GiB** 时自动启用按需目录浏览模式：
- 打开后直达首个可读根目录（带容量上限的 LRU 目录缓存），左侧文件树默认保持分区根目录折叠态并支持点击按需逐层展开读取与多分支缓存（不可识别文件系统的保留分区如 GPT MSR 展示柔和错误提示与重试，单击目录节点同步刷新右侧列表与左侧树分支）；≥8 MiB 普通文件通过纯 Rust `VolumeReader` 按偏移随机读取，可直接跳至末页；删除记录继续使用 `icat` 恢复可读字节。
- 需要全案搜索或 MACB 时间线时点击“建立完整文件索引”（可随时取消，不破坏已有清单）；大清单以 gzip 压缩 JSONL 存于 `inventory-*.jsonl.gz`。
- 需要完整性结论时点击“校验完整性”执行后台可取消整镜像哈希校验（EWF 多段由 Rayon 并行解压与校验）。
- Windows 下大镜像会话与受保护搜索对 RAW 或全部 EWF 分段持有拒写、拒删除只读共享句柄（`FILE_SHARE_READ`）。

分段 EWF 大镜像实测见 [EWF 加载与复核实测](docs/validation/EWF加载与复核实测.md)，核心算法与闭环性能实测见 [Rust 迁移性能对比实测](docs/validation/Rust迁移性能对比实测.md)。

## 证据保护边界

- **只读与目录隔离**：源镜像只读打开；TSK 仅开放 `mmls`、`fsstat`、`fls`、`icat`、`img_stat`、`img_cat` 六项读取白名单且一律以参数数组调用（无 shell）；严格拒绝加载位于案件库目录内的镜像文件。Windows 共享只读句柄用于应用层防误写，不能替代硬件写保护器；跨物理介质隔离需由操作人员将案件库与源镜像部署于不同设备。
- **审计哈希链边界**：审计日志 `audit.jsonl` 无修改/删除入口，单条记录含 `seq`、`timestamp`、`actor`、`origin`（`manual`/`mcp`）、`action`、`subject`、`result`、`details`、`previous`、`hash`，每次落盘同步更新精确 64 字节 `audit.head` 锚点；当来源为 `mcp` 时，自动采集的使用者与客户端身份同步写入审计字段并纳入 SHA-256 哈希链。可检测单独修改、删除或截断，但不能防御对案件目录具备完整写权限者同时重写三份文件。本原型不是通过 SF/T 0146-2023 认证的产品。
- **格式与解析范围**：支持 512 字节扇区的 RAW 与分段 EWF1（`.E01` 起，支持 `.E99` 后字母续段，无需解压拼接，自动读取同名 Guymager `.info` 参照）；自定义 FAT 空间区域映射仅支持 RAW；内容搜索针对清单内可读文件与删除记录，不解压归档文档、不扫描未分配空间；未实现无目录项雕刻、加密卷解密或异常分区修复。

## MCP 服务端接入

TraceDesk 内置原生标准 Model Context Protocol（MCP）服务端 `tracedesk-mcp.exe`（桌面端亦内嵌复用同一 `McpServer`），将完整电子数据取证工作流暴露为 **19 个工具**与 **2 个资源**（`tracedesk://cases`、`tracedesk://guide/workflow`），供 Claude Desktop、Cursor、Antigravity 等外部 AI 客户端调用：

- **案件管理**：`tracedesk_list_cases`、`tracedesk_create_case`、`tracedesk_get_case_summary`
- **证据镜像**：`tracedesk_load_image`、`tracedesk_verify_integrity`、`tracedesk_register_source`、`tracedesk_scan_partitions`
- **文件分析**：`tracedesk_list_files`、`tracedesk_preview_file`、`tracedesk_search_content`、`tracedesk_examine_file`
- **发现、时间线与审计**：`tracedesk_record_finding`、`tracedesk_list_findings`、`tracedesk_query_timeline`、`tracedesk_query_audit_log`
- **导出与报告**：`tracedesk_export_file`、`tracedesk_export_findings`、`tracedesk_generate_report`、`tracedesk_build_review_bundle`

所有受控写操作以 `origin="mcp"` 记入案件 SHA-256 审计链（桌面端人工操作为 `origin="manual"`）。桌面端与 MCP 服务统一采用**仅写入瞬间短锁 + 实时自动同步**机制：桌面端打开案件浏览期间不长期占用 `case.lock`，写入瞬间自动排队加短锁并同步磁盘指纹、落盘后立即释放，外部 `stdio` 与 `HTTP` 客户端可直接对当前打开的案件执行读写操作（无需关闭案件或手动释放锁）；Streamable HTTP 模式仅允许绑定回环地址（`127.0.0.1` / `localhost` / `::1`），启用 DNS 重绑定校验（非法 `Host` 返回 `421`、非法 `Origin` 返回 `403`、请求体上限 `16 MiB`）与请求帧安全加固（拒绝重复/冲突关键头、清理 `Mcp-Session-Id` 防止 CRLF 注入并限制最大并发连接数）。

当审计日志来源为 MCP 时，服务端会自动采集并标记使用者与客户端身份：按优先级结合 `initialize` 握手的 `clientInfo.name`（并按 `Mcp-Session-Id` 或 `stdio` 会话关联，不再拼接末尾版本号数字）、HTTP 请求头 `X-MCP-User` / `X-MCP-Client`（或 `X-Client-Name`）及非通用 `User-Agent`，以及命令行 `--actor`、环境变量 `TRACEDESK_MCP_ACTOR` 与工具参数 `actor` 综合识别调用方；最终统一以去除末尾版本号数字的 `MCP · <使用者>`（同时具备使用者与客户端时为 `MCP · <使用者> / <客户端>`）展示在桌面端审计日志（支持按具体调用方合并筛选与检索且不改写历史 `audit.jsonl` 原文）、MCP 实时监控、取证发现、Markdown 报告与 `tracedesk_query_audit_log` 输出中，并完整纳入 `audit.jsonl` 的 SHA-256 哈希链防篡改保护。

### 命令行启动

```powershell
# stdio 模式（默认，毫秒级响应，推荐由本地 MCP 客户端按需拉起）
.\target\release\tracedesk-mcp.exe --transport stdio

# 本地 Streamable HTTP 模式（仅监听本机回环）
.\target\release\tracedesk-mcp.exe --transport streamable-http --host 127.0.0.1 --port 8765 --path /mcp
```

支持 `--cases-dir`、`--actor` 参数及环境变量 `TRACEDESK_CASES_DIR`、`TRACEDESK_MCP_ACTOR`、`TRACEDESK_MCP_ACTIVITY_LOG`（可选指定跨进程遥测日志路径）。在桌面工作台点击顶部 **MCP 服务** 按钮，可直接一键复制客户端 JSON 配置、启停内嵌本地 HTTP MCP 服务，并在保持案件打开的同时实时监控外部 `stdio` 与 `HTTP` 客户端协同操作（采用仅写入瞬间短锁，无需手动释放锁）。

### MCP 实时监控与案件自动热刷新

桌面工作台内置 **MCP 实时监控** 主工作区标签页，结合 `crates/tracedesk-mcp/src/activity.rs` 与桌面宿主后台尾随推送，完整可视外部 AI 客户端的实时取证过程：

- **跨进程全通道实时监控**：同时汇聚桌面端内嵌 HTTP（`desktop-http`）、独立 HTTP 进程（`streamable-http`）与外部客户端拉起的独立 `stdio` 子进程三类通道活动。`desktop-http` 通过进程内事件直推前端（`mcp:activity`），独立 `stdio` / `streamable-http` 进程通过跨进程伴随锁安全追加写入 `logs/mcp-activity.jsonl`（超过 1,200 行自动原子截断保留最近 600 行），桌面端以带头部指纹校验的增量字节尾随线程实时汇聚并按 `callId` 原位更新“执行中 → 成功 / 失败”状态。
- **单步参数与结果透视**：支持按阶段（执行中/成功/失败）、只读/受控写入、调用方客户端、传输通道与关键词多维筛选；右侧可拖拽分栏展示单步调用的完整时间戳、耗时、来源与目标案件、美化后的入参 JSON、返回结果预览（超 16 KiB 安全截断）及失败错误详情，并支持一键跳转审计日志核查哈希链。
- **19 工具调用统计与接入配置**：内置四项紧凑遥测指标卡（总调用/执行中、成功率与平均耗时、活跃客户端、只读与受控写入占比）以及“实时操作流 / 接入配置 / 工具清单与调用统计”三合一子视图，集中呈现全部 **19 项 MCP 工具**的累计调用次数、失败次数与平均耗时。
- **案件自动热刷新**：当任意 MCP 进程对桌面端当前已打开的案件完成受控写入（如加载镜像、扫描分区、记录发现、生成报告或导出复核包）后，宿主自动发出 `mcp:case-updated` 事件并触发当前案件视图平滑热刷新（同步刷新案件快照、文件浏览、发现、时间线与审计日志），无需手动关闭重开案件。

## 第三方依赖与 AI 参与

The Sleuth Kit 4.15.0 Windows 官方发行包来自：
https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0-win32.zip

下载校验 SHA-256：`C2EBAB8105B893D97BD8CE35B88E01985E2A106EFC97F03ADF95840A631B20CE`（本工程实际下载记录，未执行独立 GPG 签名认证；`scripts/install_tsk.ps1` 使用该值检测后续下载变化）。上游源码：https://github.com/sleuthkit/sleuthkit/tree/sleuthkit-4.15.0。发行包许可证及第三方组件声明完整保留于 `tools/sleuthkit-4.15.0-win32/licenses/`，分发时必须一并保留；TSK 未作二进制修改，仅通过独立子进程调用。

Rust 与前端开源依赖由 `Cargo.lock` 与 `frontend/package-lock.json` 锁定管理（包括 Tauri 2、React 19、Vite、`rayon`、`memchr`、`flate2`、`sha2`、`zip`、`image`、`encoding_rs`、`serde` 等），各组件许可证以对应上游仓库声明为准。

AI 使用说明：AI 编程助手主要用于辅助架构重构、代码实现与调试、测试编写及技术文档整理。个人学习心得、姓名学号和对项目的理解由本人据实补充。
