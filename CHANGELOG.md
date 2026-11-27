# Changelog

All notable changes to TraceDesk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.0] - 2026-11-27

### Added
- **全量 Rust + Tauri 2 + React 19 / TypeScript 原生桌面工作台**：彻底移除 Python 运行时依赖，拆分为 `tracedesk-engines`、`tracedesk-core`、`tracedesk-mcp`、`tracedesk-cli` 与 `src-tauri`（56 项 IPC 命令 + 8 项流式事件），交付紧凑原生三端二进制（`tracedesk-desktop.exe`、`tracedesk-mcp.exe`、`tracedesk-cli.exe`）。
- **只读取证引擎与大镜像按需模式**：纯 Rust EWF1/E01 多段并行解码与校验、FAT12/16/32 与 NTFS 底层解析、`VolumeReader` 大文件随机直读、4 MiB 流式 SHA-256、Windows 拒写共享句柄（`FILE_SHARE_READ`），≥1 GiB 镜像自动启用按需目录浏览与单分区增量索引（`scan_partition`）。
- **文件头魔数（Magic Bytes）识别与扩展名伪装检测**：纯只读识别 25 类常见文件头（PE/ELF/Mach-O/LNK/PDF/SQLite/OLE2/OOXML/ZIP/PNG/JPEG/MP4 等），支持全案并行伪装扫描、语义徽章过滤、预览区一键记为发现及 `.cache/magic-scan.json` 磁盘缓存自动恢复。
- **AVX2 SIMD + Rayon 并行内容搜索与跨模块定位**：支持 UTF-8 / UTF-16LE / GBK / HEX 无锁流式并行搜索、历史搜索记录（`reports/search_*.json`）回放、二次筛查与恢复已排除项；时间线/发现/搜索支持一键「定位原文件」，HEX 预览支持精确字节高亮、`0x...` 偏移跳转与一键复制。
- **双格式取证报告与独立可核验 ZIP64 复核包**：支持 10 章节 Markdown 报告与离线自包含单文件 HTML 报告（含人工 vs MCP 协同统计、EWF 逐段 SHA-256 明细与首尾基线审计摘要）；导出复核包自动同步打包 `report.md` 与 `report.html`，内置桌面端「核验复核包」可视化篡改检出面板与独立 `verify_bundle.py` / `tracedesk-cli verify-bundle` 核验。
- **标准 MCP 服务端与跨进程实时监控**：提供 20 个 MCP 工具（含只读分页读取工具 `tracedesk_read_search_report`）与 2 个资源，支持 `stdio` 与仅回环 `Streamable HTTP`（含 DNS 重绑定防护）；桌面端内置 **MCP 实时监控**主工作区，汇聚 `desktop-http`、`streamable-http` 与 `stdio` 通道活动并支持案件自动热刷新。
- **案件持久化与工作台体验增强**：支持 `logs/recent-cases.json` 跨目录最近案件历史管理（打开目录 / 移出列表不删盘）、受 SHA-256 强制校验保护的「重新定位源镜像」（`rebind_image_path`）、分分区压缩清单 `inventory-p<offset>-*.jsonl.gz` 增量保存与 Rayon 并行加载、`audit.head` `sync_all()` 与 `case.json.bak` 落盘加固；提供未开案全屏启动首页、单行左右保管栏、分段与下拉式顶栏命令带、拖拽打开、长任务取消与 ETA 及 9 份图文操作说明。

### Changed
- 桌面端与 MCP 服务端统一采用“仅写入瞬间短锁 + 磁盘指纹同步 + `disk_dirty` 延迟热刷新”协同机制，支持外部 MCP 客户端在桌面端打开案件期间并发协同操作。
- 案件默认文件夹命名采用下划线分隔（`<编号>_<人员>_<对象>`），重名导出副本于 `exports/` 内直接追加 `(1)`、`(2)` 序号后缀。

### Fixed
- 修复 TSK `fls` 输出强制 `CP_ACP` 严格解码遇到 UTF-8 中文/日韩文/Emoji 文件名导致整盘索引中断的问题，改为 UTF-8 优先与单行容错跳过统计。
- 修复大文件预览路由 3 无上限落盘 `%TEMP%` 问题，放开小文件与已删除 NTFS 进程内直读并增加 64 MiB 缓存截断保护。
- 修复内容搜索期间长占 `case_lock` 阻塞保存取证发现、跨进程热刷新 `WouldBlock` 假刷新、MCP 搜索翻页重扫镜像、CLI `verify-bundle` 漏区分 HTML 报告审计摘要以及操作说明弹窗引导图被压缩遮挡的问题。
