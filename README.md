# TraceDesk 电子数据取证工作台

依据课程取证软件开发要求实现的中文桌面教学原型。PySide6（Qt 6）提供本地桌面工作台，Python 标准库负责案件隔离、SHA-256、审计哈希链、Markdown 报告与复核包，The Sleuth Kit 4.15.0 与 `pytsk3` / `libewf-python` 负责 RAW 和分段 EWF 镜像的只读解析、大文件随机读取及内容检索，内置标准 MCP 服务端 `tracedesk_mcp` 供外部 AI 客户端接入。所有取证操作均在本地执行，不上传证据。

## 目录导航

| 位置 | 用途 |
| --- | --- |
| `main.py`、`mcp_server.py`、`启动取证工作台.bat` | 桌面工作台与 MCP 服务端启动入口 |
| `forensic/core/` | 案件、哈希、审计、搜索、导出、报告、复核包和后台任务 |
| `forensic/mcp/` | MCP 服务端业务编排、FastMCP 工具定义与本地 HTTP 托管 |
| `forensic/features/` | 启用清单、11 个可装配功能模块、按钮和页面 |
| `forensic/engines/` | TSK 只读适配、分段 EWF、`pytsk3`/`pyewf` 随机读取与 FAT 空间分析 |
| `forensic/ui/` | PySide6 控制器、明净瓷白与晴空蓝浅色主题、委托、窗口、文件树与预览 |
| `forensic/paths.py`、`forensic/assets/` | 统一资源定位、应用徽标、控件矢量图标与操作说明引导图 |
| `scripts/`、`tests/` | 开发辅助命令与对应职责的回归测试 |
| `docs/` | 维护指南、设计与验收说明和验证记录 |
| `evidence/`、`cases/`、`tools/` | 源证据输入、案件输出、官方第三方工具 |
| `logs/`、`dist/`、`.venv/` | 本地运行日志、打包输出和项目虚拟环境 |

完整文件树与“改功能该去哪里”见 [目录结构与维护指南](docs/目录结构.md)；其他资料见 [文档导航](docs/README.md)。

## 启动

Windows 已安装 Python 3.10+ 时，双击 **启动取证工作台.bat**。脚本会切换到项目目录，首次运行创建本目录 `.venv`，缺少界面、镜像读取或 MCP 依赖（`PySide6`、`pytsk3`、`pyewf`、`mcp`）时通过清华镜像安装 `requirements.txt` 中的依赖，再通过 `.venv\Scripts\python.exe main.py` 启动界面。首次安装依赖需要联网；依赖已安装后直接启动，不重复联网安装。保留终端窗口，运行失败时暂停以便查看错误。也可在本目录手动执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

已有虚拟环境并安装依赖后，可直接执行 `.\.venv\Scripts\python.exe main.py`。程序初始化失败和未处理的 Qt 界面回调错误会弹窗提示，并记录到 `logs/startup.log`。

当前工程已经包含官方 Windows TSK 程序和两份演示镜像，TSK 无需通过 pip 安装。若 TSK 文件丢失，运行 `powershell -File scripts/install_tsk.ps1`，或将环境变量 `TSK_BIN` 指向完整 TSK `bin` 目录。需要保留 DLL 与 licenses，不要只复制四个 exe。

界面统一使用 PySide6 原生控件，采用 **明净瓷白与晴空蓝（Daylight Porcelain & Cerulean Sky）** 浅色视觉规范：顶部为明净瓷白命令带（`#FFFFFF`），下方依次为带 3 px 语义状态指示条的浅冰色案件保管栏（`#F7FAFD`）、薄雾浅蓝模块导航标签带（`#EFF4F9`，右侧嵌入镜像操作按钮）、纯白证据工作区与浅瓷色底栏；主色为晴空蓝（`#2674C4`），列表和文件树通过统一渲染委托呈现柔和浅底语义胶囊徽章（现存/已删除/重分配/人工/MCP/MACB 事件）、晴空蓝选中导轨和本地高 DPI 矢量图标。文件浏览采用左侧数据源与完整文件树、右上文件列表、右下文本/图片/十六进制预览布局。Qt 6 自动处理高 DPI 和逻辑像素缩放；界面文本按本机可用字体优先选用 `Segoe UI Variable Text` / `Segoe UI` 与 `Microsoft YaHei UI` / `Microsoft YaHei` 混排，字节数、inode、偏移、哈希、十六进制、JSON 与 `fsstat` 统一使用 `Cascadia Mono` / `Cascadia Code` / `Consolas` 等宽字体。树、列表与内容支持滚动，区域之间可以拖动分隔条调整大小。所有 Python 第三方依赖只安装到本项目 `.venv`，使用清华镜像：

```powershell
.\.venv\Scripts\python.exe -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
```

若已有精简虚拟环境没有 pip，可先运行 `.\.venv\Scripts\python.exe -m ensurepip --upgrade`；BAT 启动器也会在依赖缺失时自动补齐 pip。

## 完整操作

1. 新建案件，填写编号、取证人员、对象，选择 `cases` 为案件库。中文目录选择器在地址栏预填“案件编号-取证人员-取证对象”，可编辑完整路径和目录名，重名时依次添加 ` (2)`、` (3)`。
2. 加载 `evidence/demo.dd`，自动固定 SHA-256、识别分区并读取所有分区的文件树。
3. 左侧镜像下按分区展示完整清单，无需手动选择分区或点击读取。演示镜像的 FAT16 分区偏移为 2048；`evidence/demo_volume.dd` 是偏移为 0 的无分区表卷镜像。
4. 展开 DOCS 查看 CASE.TXT；可按 `.txt` 后缀或路径关键词筛选。界面和新生成的报告使用东八区（UTC+8），FAT 等无时区元数据按 UTC 解释，真实分析需预先核对源设备时区；未记录的时间不会显示成 1970 年。
5. 点击“校验完整性”，再选择现存或已删除的文件导出。副本以原文件名保存到案件的 `exports` 目录。遇到重名时，新副本保存在独立子目录中，仍使用原文件名。导出前后均校验原镜像，并记录副本哈希。
6. 右键树或列表中的普通文件可记录取证发现、计算 SHA-256 或与本地副本比对。进入“取证发现”查看按路径、分区和 inode 汇总的记录，可通过表头下拉框按状态/分区偏移筛选并支持“一键导出”对应镜像文件与汇总清单，生成报告时自动纳入。
7. 在“MACB 时间线”“审计日志”和“取证发现”中，双击记录在下方打开详情，再单击其他记录切换内容。审计详情分栏列出操作来源（人工/MCP）、操作参数、结果和前后关联的哈希值。点击“生成 Markdown 报告”，可在案件 `reports` 中查看 `.md` 文件。
8. 重启后通过“打开案件”选择该案件 `case.json`；旧案件尚未覆盖全部分区时自动补齐扫描。

加载后左侧保留所有已识别分区及各自的目录、文件、删除记录和系统区域。无法读取的分区仍显示节点，点击可查看原因，不影响其他分区。点击镜像查看所有分区条目，点击分区只查看该分区，点击目录更新右上列表，双击列表中的目录进入。“全部展开/全部折叠”控制树的层级；后缀、路径和状态筛选只作用于当前范围，不裁剪左侧完整树。切换目录或点击“重置”清除筛选。

同名文件按分区偏移和独立目录记录区分，预览、导出、时间线与报告保留分区来源。文件列表显示大小、inode、MAC 时间和分区偏移，底部显示所选文件摘要；“文本/十六进制”标签支持分页，并可切换 ASCII、UTF-8、UTF-16LE/BE、GBK、GB18030、Big5、Windows-1252 和 ISO-8859-1 编码。选中已删除文件可预览并导出镜像中仍可读的字节。预览栏会提示部分读取、inode 重分配或扫描时发现的 FAT 起始簇占用。导出记录保留目录记录大小、实际写入字节数和副本哈希；遇到短读时只保存可读部分。FAT 分区还可查看根目录数据、FAT 表、引导扇区，以及按簇计算的未分配空间和已分配但未关联的空间。

图片文件按内容识别后，“文本”标签自动切换为“图片”，预览随区域大小等比例缩放，仍可切换“十六进制”分页查看原始字节。支持 Qt 可解码的 PNG、JPEG、BMP、GIF 等格式，动画显示首帧；单张预览上限为 32 MiB、4000 万像素，较大图片的显示副本最长边缩至 4096 像素，原始证据不变。损坏或超限图片提示原因，可导出后查看。底部文件摘要与操作状态分居同一行两侧，预览翻页按钮采用紧凑尺寸。

快速生成一个保留在 `cases` 的完整演示案件并打开界面：

```powershell
.\.venv\Scripts\python.exe scripts/run_demo.py --gui
```

每次运行建立新案，不清空既有数据。可重复创建测试镜像：`.\.venv\Scripts\python.exe scripts/make_demo.py`，已存在文件会保留。

右键工具与取证发现页由 `file_tools` 模块提供，启用清单位于 `forensic/features/config.py`。笔记与比对结果写入案件的审计链，重新打开案件仍可查看。

## 实现与验证

- 七项基本功能均实现；自动化测试真实调用 TSK，不用模拟解析器替代。
- 扩展：审计哈希链及尾部锚点（区分人工/MCP 来源）、MACB 时间线、分段 EWF 与大容量镜像按需浏览、路径关键词与表头下拉筛选、多进程内容搜索与流式复核、导出副本 SHA-256、导出前后原镜像校验、可独立核验复核包与标准 MCP 服务端。
- `.\.venv\Scripts\python.exe -m unittest discover -s tests -v` 运行回归测试（共 16 个测试模块、122 个测试用例）；历史记录见 [test-results.txt](docs/validation/test-results.txt)，大容量与 EWF 实测见 [1TiB 镜像性能实测](docs/validation/1TiB镜像性能实测.md) 和 [EWF 加载与复核实测](docs/validation/EWF加载与复核实测.md)。
- 架构、界面规范、评分对应、限制与 AI 参与说明见 [设计与验收说明.md](docs/设计与验收说明.md)。
- 面向对象结构：`ApplicationLauncher` 管理入口和异常报告，`App` 协调操作，`FeatureRegistry` 按需装配功能模块，`WorkbenchView` / `FileBrowserView` 管理布局和文件树，`DesktopAppearance` / `theme` / `ForensicItemDelegate` / `HexItemDelegate` 管理视觉规范与自定义渲染，`TaskRunner` 管理后台任务，`FilePreview` / `PreviewReader` 分离预览显示与读取，`Case`、`TSK`、`VolumeReader` 负责核心取证业务与只读解析，`CaseService` / `LocalHttpMcpManager` 负责 MCP 编排与本地托管。
- 主要入口：桌面入口 `main.py`、MCP 入口 `mcp_server.py`、控制器 `forensic/ui/controller.py`、窗口布局 `forensic/ui/workspace.py`、主题与委托 `forensic/ui/theme.py` / `appearance.py` / `delegates.py`、目录树 `forensic/ui/browser.py`、核心案件逻辑 `forensic/core/case.py`、TSK 与 EWF/随机读取适配 `forensic/engines/tsk.py` / `ewf.py` / `random_read.py`；完整模块清单见 [目录结构与维护指南](docs/目录结构.md)。
- 标题栏、任务栏和工作台左上角使用浅冰晴空蓝渐变圆角底、晴空蓝磁道圆弧与纯白镜片准星的“精密取证盘片与准星”徽标（顶部命令带直接由 SVG 按屏幕缩放倍率光栅化），资源位于 `forensic/assets/`。修改 `tracedesk.svg` 后，可运行 `.\.venv\Scripts\python.exe scripts/make_icon.py` 重建 256 px PNG 和 16–256 px 多尺寸 ICO；重启程序生效。工作台顶部的 **操作说明** 内置 9 个分主题图文引导页（附带编号标注的真实界面截图与点击放大查看器），界面改动后可运行 `.\.venv\Scripts\python.exe scripts/make_guide_images.py` 重新生成全部引导图。
- `.\.venv\Scripts\python.exe scripts/package.py` 生成 `dist/学号_姓名_ForensicTool.zip`，提交前将文件名中的姓名和学号替换为本人信息。包内不含本地运行案件、私人证据和 `.venv`，解压后可重新运行演示脚本。

## 大容量镜像

逻辑容量达到 **1 GiB** 时自动启用按目录浏览。打开后显示分区和首个可读根目录，双击目录或在左侧选择其他分区即可继续。近期目录使用有上限的内存缓存。大普通文件按文件内偏移读取预览，可以直接跳到末页。删除记录继续使用 icat 恢复可读内容。

- **只查一个文件**时可以直接预览、计算文件摘要、比对或导出。在“内容搜索与复核”选择“文件浏览中选中的文件”即可限定搜索范围。尚未固定整镜像时，导出和取证记录保留操作当时的完整性状态。
- **需要全案搜索或时间线**时，在文件浏览左侧点击“建立完整文件索引”。该操作递归读取各分区并把清单写入案件。写入完成前可取消，保留原有清单。打开保存过完整清单的案件会复用该清单。完整索引的耗时与目录项数量有关，全文搜索还取决于实际需读取的内容量。
- **需要完整性结论**时，点击“校验完整性”。首次完整读取建立 SHA-256 基线，之后点击会重新读取校验。读取期间可以继续浏览目录或取消校验，取消不会发布摘要。生成正式报告和复核包需要已固定的基线与本次会话的校验记录。
- Windows 在大镜像会话期间对 RAW 或每个 EWF 分段持有拒写、拒删除句柄，经完整读取后复用同一受保护会话的结果。重开已固定的案件后，先点击“校验完整性”才能继续导出和正式分析。
- 原生文件读取依赖安装在项目虚拟环境。pytsk3 按分区、inode 和属性读取文件，libewf-python 解码 EWF 逻辑介质。所有分段需位于同一目录，从 .E01 打开，支持 .E99 后的字母续段。

容量夹具、测量范围和耗时见[大容量镜像性能实测](docs/validation/1TiB镜像性能实测.md)。

## 证据保护边界

源镜像只读打开；TSK 仅开放 mmls、fsstat、fls、icat、img_stat 和 img_cat 读取命令。案件库外部镜像与案件输出分目录，拒绝加载位于整个案件库中的镜像。大镜像会话和受保护的搜索使用 Windows 共享模式限制外部写入；硬件写保护需另行配置。要求不同物理介质时，请将案件库与源镜像分别存放到不同设备。

日志不提供修改、删除入口。哈希链及本地锚点可检测日志单独修改和截断，但不能防止有写权限者同时重写日志、锚点和案件元数据。本原型不是通过 SF/T 0146-2023 认证的产品。

范围限定：一个案件固定一份 RAW 或分段 EWF 镜像，限 512 字节扇区。EWF 从 E01 打开，所有分段须在同一目录；不需要解压或拼接出 RAW。首次逐字节校验逻辑介质并固定每段 SHA-256，后续校验重新读取全部压缩分段，核对分段清单和各摘要。Guymager 的同名 .info 如含 SHA256 采集记录，会作为外部参照单独展示。自定义 FAT 空间区域映射仅支持 RAW。未实现无目录项雕刻、硬件写保护、多用户签名或异常分区修复。

“镜像与文件系统”区分哈希一致性与声明范围。对可识别的 NTFS/FAT 引导扇区和分区表计算声明结束位置；未知格式不判定为完整。旧 RAW 案件运行一次完整性校验即可补上范围判定。覆盖声明范围不能证明没有坏扇区或原盘已全部采集。

“内容搜索与复核”支持 UTF-8、UTF-16LE、GBK 和 HEX 精确字节搜索，可查全部清单或选中文件，命中条数不设上限。搜索与取消搜索合并为同一按钮，右侧紧邻“排除所选项”与“保存为取证发现”按钮，在独立后台通道运行，一边搜索一边实时展示已命中的条目；搜索期间即可通过表头全选框（带“全选”字样，支持未选/半选/全选三态）、“分区偏移”表头下拉筛选、双击查看原始十六进制、排除所选项以及批量保存为取证发现进行操作，失败项和实际范围写入 reports/search_*.json。搜索不解压文档、不扫描未分配空间。整案搜索采用多进程分片并行读取、滚动窗口内按 inode 聚合排序、硬链接去重、大文件非稀疏区间切分与跳过稀疏零区等策略，仍严格按原清单顺序发布命中，确保结果顺序可复现；FAT 删除记录及无法直接定位的属性自动回退 icat 读取。小镜像搜索期间对 RAW 文件或全部 EWF 分段持有拒写、拒删除句柄，开始时复算摘要；无法取得保护时，在搜索前后分别复算。每次搜索采用的校验方式随清单保存。

可在“镜像与文件系统”页点击“登记证据来源”填写证据编号、来源、采集时间、采集工具和交付方 SHA-256；顶部标题栏“生成 Markdown 报告”右侧提供“导出复核包”。当案件已有历史导出副本或内容搜索记录时，点击“导出复核包”会弹出材料选择窗口：若存在已被删除或隔离的本地导出副本或 `reports/search_*.json`，顶部会给出清晰中文缺失清单并支持一键复制与“仅看缺失项”筛选，用户可在“导出副本”和“内容搜索记录”两个标签页中自由勾选现存材料纳入复核包，未勾选或缺失的历史记录会如实记入 `manifest.json` 的 `omitted_exports` / `omitted_searches`。Markdown 报告采用分节表格呈现案件概览、完整性校验结论、分区与清单抽样（含 MACB 四时间）、导出副本、内容搜索记录、结构化取证发现和中文操作名称的审计日志摘要。复核包包含 Markdown 报告、来源、发现、导出副本、搜索记录、审计链和成员摘要，不包含原始镜像。请通过独立渠道交付 ZIP 摘要。复核人在项目虚拟环境执行 `.venv\Scripts\python.exe scripts/verify_bundle.py 包路径 --sha256 独立取得的摘要` 即可验证包和审计链，具体证据按包中说明在原镜像上复查。

打开旧版案件会将非空文件清单迁移到同目录的 `inventory-*.jsonl.gz`；备份或移动案件时请复制整个案件目录。重新校验、导出等操作只更新小型元数据，不重复写清单。扫描时 fls 输出暂存在系统临时目录并逐行解析，超时按镜像大小计算（每 GiB 120 秒，至少 300 秒）。请为临时清单预留磁盘空间。

超过 1,000 项时，右侧文件列表按每页 100 项显示，筛选覆盖当前范围的所有页。左侧文件树由完整清单建立，展开目录即可查看其全部子项；点选文件会自动定位到右侧对应页。大案件的 MAC/B 时间线按需在后台生成，每条记录的序号在翻页和筛选后保持不变；取证发现默认按最近记录（UTC+8）正序（早的在前）排列，在取证发现、MACB 时间线和审计日志中单击“序号”或时间列表头均可切换正序/倒序；在取证发现、内容搜索与复核、MACB 时间线和审计日志中，事件、状态、分区偏移、来源（人工/MCP）、操作人员、操作、结果列表头均支持下拉筛选。单击记录在顶部显示序号，双击在下方打开详情。文件列表、时间线和文件内容预览均可双击页码直接跳页。文件清单、已生成的时间线仍需放入内存，不能仅凭镜像容量推定可处理的文件数量。

## MCP 服务端接入

TraceDesk 内置标准 Model Context Protocol（MCP）服务端 `tracedesk_mcp`，将完整电子数据取证工作流暴露为 **19 个工具**与 **2 个资源**（`tracedesk://cases`、`tracedesk://guide/workflow`），供 Claude Desktop、Cursor、Antigravity 等外部 AI 客户端调用：

- **案件管理**：`tracedesk_list_cases`、`tracedesk_create_case`、`tracedesk_get_case_summary`
- **证据镜像**：`tracedesk_load_image`、`tracedesk_verify_integrity`、`tracedesk_register_source`、`tracedesk_scan_partitions`
- **文件分析**：`tracedesk_list_files`、`tracedesk_preview_file`、`tracedesk_search_content`、`tracedesk_examine_file`
- **发现、时间线与审计**：`tracedesk_record_finding`、`tracedesk_list_findings`、`tracedesk_query_timeline`、`tracedesk_query_audit_log`
- **导出与报告**：`tracedesk_export_file`、`tracedesk_export_findings`、`tracedesk_generate_report`、`tracedesk_build_review_bundle`

所有工具严格遵守 TraceDesk 证据保护边界：源镜像只读打开且禁止位于案件库内；同名或跨分区文件通过 `partition_offset`、`inode` 和 `deleted` 唯一定位；所有受控写操作都会以 `origin="mcp"` 写入案件 SHA-256 审计链（桌面端人工操作写入 `origin="manual"`），审计日志表格、详情页、取证发现、Markdown 报告及 `tracedesk_query_audit_log` 均明确标记并支持按 **人工 / MCP** 筛选，且篡改来源字段会被审计哈希链检出；每次调用结束后及时释放 `case.lock`。

### 命令行启动

```powershell
# stdio 模式（默认，推荐由本地 MCP 客户端按需拉起）
.\.venv\Scripts\python.exe mcp_server.py

# 本地 Streamable HTTP 模式（仅允许监听 127.0.0.1 / localhost，启用 DNS 重绑定防护）
.\.venv\Scripts\python.exe mcp_server.py --transport streamable-http --host 127.0.0.1 --port 8765 --path /mcp
```

也可通过 `.\.venv\Scripts\python.exe -m forensic.mcp` 启动，并支持 `--cases-dir`、`--actor` 参数（或环境变量 `TRACEDESK_CASES_DIR`、`TRACEDESK_MCP_ACTOR`）。

### 桌面端配置与本地 HTTP 托管

点击工作台顶部标题栏的 **MCP 服务** 按钮，可直接查看和一键复制 `stdio` / `Streamable HTTP` 客户端配置 JSON、启动命令与全部 19 个工具清单，并在桌面端内直接启停本地 `127.0.0.1` Streamable HTTP MCP 服务（关闭桌面窗口时自动停止）。当桌面端已打开某个案件并持有 `case.lock` 时，弹窗顶部会显示提示并提供 **释放当前案件锁** 一键按钮，点击即可关闭当前案件并释放锁供外部 MCP 客户端接入。

## 第三方依赖与 AI 参与

The Sleuth Kit 4.15.0 Windows 官方发行包来自：
https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0-win32.zip

本次下载文件 SHA-256：`C2EBAB8105B893D97BD8CE35B88E01985E2A106EFC97F03ADF95840A631B20CE`。
此值为本工程实际下载记录，未执行独立 GPG 签名认证。安装脚本使用它检测后续下载变化。

上游源码：https://github.com/sleuthkit/sleuthkit/tree/sleuthkit-4.15.0

发行包的许可证及第三方组件许可证完整保留于 `tools/sleuthkit-4.15.0-win32/licenses/`，分发时必须一并保留。TSK 未作二进制修改；通过独立进程调用。

桌面界面使用 Qt for Python 官方 `PySide6`（Qt 6）及其随包依赖，大容量文件随机读取与 EWF 逻辑介质解码使用 `pytsk3` 和 `libewf-python`，MCP 服务端使用官方 Python SDK（`mcp`），以上依赖均由 `requirements.txt` 安装到项目 `.venv`。官方文档与许可入口：[Qt for Python](https://doc.qt.io/qtforpython-6/)、[Commercial Use](https://doc.qt.io/qtforpython-6/commercial/index.html)。各组件具体适用许可及第三方声明以安装包所附文件为准。本工程仅通过 Python 导入使用，未修改 PySide6、Qt、pytsk3、libewf 或 mcp 二进制文件；源码工程包不包含 `.venv`，运行前需安装依赖，若另行分发运行库应一并保留其许可证和声明。

AI 使用说明：Codex 主要用于辅助代码实现与调试、界面调整、测试及技术文档整理。个人学习心得、姓名学号和对项目的理解由本人据实补充。
