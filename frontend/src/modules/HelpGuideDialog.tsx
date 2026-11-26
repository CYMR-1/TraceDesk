/**
 * 模块 8：图文操作说明弹窗 (help)
 * 内置 9 个分步取证主题、红色 ①–⑤ 标注、真实桌面引导图与 Lightbox 大图查看器。
 */
import React, { useRef, useState } from 'react';
import { UiIcon } from '../components/Icons';
import { LightboxDialog } from '../components/dialogs/LightboxDialog';
import { Modal } from '../components/dialogs/Modal';
import { assetUrl } from '../utils/assets';

interface GuidePage {
  title: string;
  navLabel: string;
  summary: string;
  image: string;
  caption: string;
  content: string;
}

const GUIDE_PAGES: readonly GuidePage[] = [
  {
    title: '用演示镜像走一遍流程',
    navLabel: '快速上手：演示镜像',
    summary: '从全屏启动首页出发，用内置 FAT16 演示镜像 5 步走通建案、浏览、预览、导出校验与「生成报告 ▾」双格式输出闭环，并支持一键离线核验复核包。',
    image: 'assets/guide/01_quickstart.webp',
    caption: '图 1 · 工作台分区布局与演示流程五大核心入口（点击查看大图）',
    content: `1. 未开案时软件以**全屏启动首页**呈现，可直接点击快捷瓷砖 **新建案件**（打开案件后自动切入三段式取证工作台，亦可在顶栏右侧分段控件组使用 ① **新建案件** / **打开案件** / **关闭**）。编号可填 \`DEMO-01\`，取证人员填自己的姓名，对象填“FAT16 演示镜像”，选择案件上级目录并确认路径后点击 **创建案件**（历史案件也可在启动首页左栏 **最近案件** 实时筛选后一键打开，或直接将 \`case.json\` 拖入窗口）。
2. 点击右侧 ② **加载镜像**，选择项目里的 \`evidence/demo.dd\`。等待文件树自动建立后，在左侧 ③ 展开偏移 **2048 扇区** 的分区，进入 **DOCS**，选中 **CASE.TXT**。
3. 在下方 ④ **文本** 页应看到 \`Case note inside a nested directory.\`。切到 **十六进制**，首行偏移为 \`00000000\`，开头四个字节为 \`43 61 73 65\`（对应 “Case”）。
4. 点击预览区右上方的 **导出所选文件**，在结果窗口点 **打开所在目录**（或直接 **打开文件** / **复制路径**）。回到工作台，右键同一个 \`CASE.TXT\`，选择 **校验一致性…**，选中刚导出的副本，结果应显示 **一致**。
5. 点击顶栏 ⑤ **生成报告 ▾** 下拉菜单，按需选择 **Markdown 报告（.md）** 或 **离线 HTML 报告（.html）**（零外链离线单文件），在“导出副本”和“文件取证发现”中核对文件路径与 SHA-256 摘要；导出复核包后，随时可点击顶栏 **核验复核包** 或全屏启动首页 **离线核验复核包** 验证整包完整性。`,
  },
  {
    title: '创建案件、加载镜像与登记来源',
    navLabel: '建案、加载与来源',
    summary: '从全屏启动首页或顶栏分段控件组快速建案/开案，支持最近案件实时筛选、拖入文件快速打开与动态窗口标题；在“镜像与文件系统”页核对固定摘要与来源登记。',
    image: 'assets/guide/02_case_and_source.webp',
    caption: '图 2 · 镜像与文件系统页：固定摘要、覆盖范围评估与来源登记（点击查看大图）',
    content: `1. 启动 TraceDesk 后进入**全屏启动首页**：顶部全宽品牌栏右侧提供 **操作说明** 与 **MCP 服务** 入口，主区包含 **新建案件**、**打开已有案件**、**离线核验复核包** 三列快捷瓷砖，右栏内置 4 步 **标准取证闭环** 速览。点击 **新建案件**（或开案后顶栏右侧分段控件组 ① **新建案件**），填写案件编号、取证人员和取证对象并选择上级目录；开案后自动切入三段式取证工作台，原生窗口标题栏会动态显示当前 **案件编号与镜像名**，案件保管状态条以紧凑**单行左右排布**呈现（左侧案件信息、右侧带状态圆点的镜像校验结论，鼠标悬停可看完整内容）。
2. 每个案件固定分析一份镜像，源镜像必须放在案件库目录之外（例如案件放在 \`cases\`，镜像放在同级 \`evidence\`）。点击 ② **加载镜像**，选择 RAW 镜像或分段 EWF 的 **.E01 首段**（所有续段需位于同一目录）；已开案状态下也可直接将 \`.dd\` / \`.E01\` 等镜像文件 **拖拽入窗口** 快捷加载。
3. 切换到 **镜像与文件系统**，点击右上角 ③ **登记证据来源**，填写证据编号、来源、采集时间与时区、采集工具；如交付方提供了 SHA-256，填入其 64 位十六进制摘要。
4. 在 ④ **证据固定 / 覆盖范围与证据来源** 区域核对路径、逻辑大小（点击大小数值可在 TiB / GiB / MiB / KiB 与精确字节数之间切换）、SHA-256、卷声明范围及交付方摘要比对结论；在 ⑤ 查看底层原始分区表（\`mmls\`）与文件系统信息（\`fsstat\`）。

> 快捷开案与安全关闭：在全屏启动首页左栏等高单列 **最近案件** 中支持实时筛选编号、对象、人员或目录名并一键打开，也可点击或将 \`case.json\` 拖入右栏 **拖入文件快速打开** 区，或点击顶栏分段控件组 ① **打开案件**；需要结束当前会话平滑返回全屏启动首页时，点击顶栏分段控件组中的 **关闭** 即可。备份或移交案件时请复制整个案件文件夹（含压缩清单、审计链与导出材料）。`,
  },
  {
    title: '大镜像、按需索引与 SHA-256',
    navLabel: '大镜像与 SHA-256',
    summary: '逻辑容量达到 1 GiB 时自动切换为按需目录浏览，支持单分区或全案按需建索引，边浏览边在后台校验 SHA-256 并实时展示已耗时与 ETA。',
    image: 'assets/guide/03_large_image.webp',
    caption: '图 3 · 大容量镜像按需目录浏览、完整索引与后台校验入口（点击查看大图）',
    content: `- **先浏览，不阻塞**　小于 1 GiB 的镜像会自动固定摘要并扫描全部分区；达到 1 GiB 时先打开首个可读根目录，并在 ① 紧凑**单行左右排布**的案件保管状态条右侧（带状态圆点，鼠标悬停可看完整内容）标明“整镜像 SHA-256 待固定”。左侧文件树支持点击分区或目录按需逐层展开并缓存多分支（深层目录或长目录名自动提供**水平滚动条**），也可双击目录深入浏览、点击左侧 ② **返回上级目录** 回退。
- **全案与单分区按需建索引**　需要全案内容搜索或 MACB 时间线时，点击左侧 ③ **建立完整文件索引**；若只需深挖特定分区，可在左侧分区节点右键（或点击节点快捷操作）或在 **镜像与文件系统** 页分区表点击 **仅索引此分区**，按需完成单分区建索引。写入完成前可随时点击 **取消建立索引**、底部状态栏或进度弹窗的 **取消当前任务** 中止并保留已有结果；完成后清单压缩保存至 \`inventory-*.jsonl.gz\`，重开案件直接复用。
- **后台校验与 ETA 进度**　点击右上角 ④ **校验完整性**。大镜像首次完整读取会建立 SHA-256 基线，后续校验与基线比对；读取期间底栏与进度视图实时显示读取速率、**已耗时** 与 **预计剩余时间（ETA）**，可继续浏览目录，也可通过 **取消校验** 或底栏取消按钮直接中止本次读取。EWF 首次解码逻辑介质并固定全部分段，后续逐段复算封装摘要。
- **正式报告前置条件**　大镜像在固定前导出的副本会标明“初步分析”；重新打开已固定大镜像案件后，需先完成本次会话的完整性校验，再导出副本或生成正式报告。

> 说明：Windows 在大镜像会话期间对 RAW 或全部 EWF 分段持有拒写/拒删除共享句柄。卷声明范围已覆盖仅说明声明结束位置落在镜像内，是否完整采集仍需结合采集记录核验。`,
  },
  {
    title: '浏览、魔数伪装检测与多格式预览',
    navLabel: '浏览、筛选与预览',
    summary: '左侧完整目录树支持深层路径水平滚动浏览，支持一键文件头魔数伪装检测与胶囊过滤；下方支持多编码文本、图片与可跳转高亮的十六进制分页预览。',
    image: 'assets/guide/04_browse_preview.webp',
    caption: '图 4 · 文件树、条件筛选栏与十六进制/多编码分页预览（点击查看大图）',
    content: `1. 在左侧树选择镜像、分区或目录，可用 ① **全部展开 / 全部折叠** 控制层级。无论是全量索引还是大镜像按需展开深层目录或较长目录/文件名时，左侧文件树都会自动提供**水平滚动条**，无需强行拉宽侧栏即可完整查看路径；遇到跨分区同名文件，可结合 **分区偏移、路径、inode** 精准区分。
2. 在 ② 筛选栏输入后缀（如 \`.txt\`）或路径关键词，或在状态下拉框选择 **现存文件 / 已删除**，按回车或点击 **筛选**；点击 **重置** 恢复当前范围。筛选不裁剪左侧完整树。
3. **文件头魔数伪装检测**：在 ② 工具栏点击 **魔数伪装检测** 扫描文件真实魔数（Magic Bytes）与声明扩展名是否冲突；检出后点击 **仅看疑似伪装 (N)** 语义胶囊即可全案聚合过滤可疑项。③ 文件列表会以 **高危红**（高危伪装）或 **中危琥珀**（疑似伪装）徽章直观标注；选中文件后，预览区顶部魔数元信息栏会自动展示真实类型与前 16B 魔数 HEX，点击一键 **记为取证发现** 即可自动预填结构化伪装分析笔记。
4. 在 ③ 文件列表核对状态胶囊、字节数、inode 与 MACB 四时间（UTC+8）。单击文件即可在下方预览，预览区右上角提供 **记为取证发现** 与 **导出所选文件** 快捷按钮；右键文件也可快速导出、记录发现、计算摘要、校验一致性或 **单文件检索内容…**；超过 1,000 项时列表自动按每页 100 项分页。
5. 在 ④ 切换 **文本 / 十六进制**（可识别图片自动显示 **图片** 页，上限 32 MiB、4000 万像素），中文乱码时可在 **编码** 下拉框选择 UTF-8、UTF-16LE/BE、GBK、GB18030、Big5 等 9 种编码。HEX 预览区支持 **精确字节高亮**（HEX 双字节格与右侧 ASCII 同步标亮）、输入 \`0x...\` 十六进制或十进制 **字节偏移跳转**，以及一键 **复制当前页文本 / 复制当前页 HEX**；使用下方 **上一页 / 下一页** 或双击 ⑤ 页码徽标可快速翻页。

> 性能与安全提示：预览小文件及已删除 NTFS 记录支持进程内直读（免除外部子进程反复拉起开销），并设置 **64 MiB 安全缓存上限**，兼顾响应速度与内存稳定。`,
  },
  {
    title: '搜索文件内容并实时复核命中',
    navLabel: '内容搜索与复核',
    summary: '支持 UTF-8、UTF-16LE、GBK 与 HEX 无锁流式检索，支持历史记录回放、命中二次筛查、恢复已排除项与一键定位原文件。',
    image: 'assets/guide/05_content_search.webp',
    caption: '图 5 · 内容搜索与复核页：实时流式命中、三态全选与批量保存（点击查看大图）',
    content: `1. 切换到 **内容搜索与复核**。在 ① 输入搜索文字或十六进制字节（文本编码会精确保留首尾空格），选择编码与范围（**全部文件** 或 **文件浏览中选中的文件**；大镜像全案搜索需先建立完整索引），点击 **搜索**。运行中按钮自动切换为 **取消搜索**。
2. 用演示镜像验证：选择编码 **HEX**，输入 \`6E 6F 74 65\`，点击 **搜索**，即可在 ④ 命中 \`DOCS/CASE.TXT\`，**文件内字节偏移为 5**（从文件开头的 0 起算）。
3. **无锁流式执行与后台指示**：搜索不设命中上限且全程无锁流式执行，结果边扫描边展示；搜索期间可随时勾选保存发现或自由切换至其他模块，底部状态栏与模块标签头会持续保留运行态进度指示与取消入口。
4. **二次筛查、恢复排除与历史回放**：在 ③ 可通过表头 **全选** 三态复选框勾选命中、按 **分区偏移** 表头下拉筛选，或在工具条按 **路径关键词** 与 **文件状态（全部 / 现存 / 已删除）** 对命中列表进行二次筛查；勾选误报后点 ② **排除所选项**，随时可点 **恢复已排除项** 撤回；通过 **历史搜索记录回放** 下拉框可随时重放历史 \`reports/search_*.json\` 命中结果。
5. **精确高亮与一键定位原文件**：双击 ④ 中任意命中行，直接弹出对应偏移的十六进制精确字节高亮预览；在命中行或十六进制弹窗点击 **定位原文件**，即可一键直跳 **文件浏览** 自动选中该文件并在 HEX 视图高亮定位到精确命中字节；勾选一条或多条命中后点击 ② **保存为取证发现** 可批量写入审计链。

> 说明：每次搜索的完整命中、范围、校验方式与失败明细均自动保存至案件 \`reports/search_*.json\`。内容搜索覆盖清单中可读取的文件及已删除记录，不解压归档文档、不扫描未分配空间。`,
  },
  {
    title: '导出副本、恢复删除文件与取证发现',
    navLabel: '导出与取证发现',
    summary: '导出前后自动复核原镜像，支持已删除文件可读字节恢复；取证发现支持表头筛查、批量导出与一键定位原文件联动。',
    image: 'assets/guide/06_export_findings.webp',
    caption: '图 6 · 取证发现页：表头筛选排序、一键批量导出与可关闭分栏详情（点击查看大图）',
    content: `1. **导出文件副本**：在 **文件浏览** 选中现存或已删除文件，点击 **导出所选文件**。副本保存至案件 \`exports\` 目录（重名时不再创建子目录，直接在 \`exports\` 下于文件名后追加 \`(1)\`、\`(2)\` 等序号后缀，如 \`NOTES(1).TXT\`），并记录副本 SHA-256；导出成功弹窗支持直接点击 **记为取证发现** 顺手补录研判笔记。
2. **恢复已删除文件**：将状态切为 **已删除**，选中记录核对能否预览、目录记录大小及恢复提示后再导出。若提示“部分导出”、inode 已重分配或 FAT 起始簇已被占用，应如实记录实际字节数并结合内容研判。
3. **记录取证发现与文件工具**：在预览区右上角、魔数伪装提示栏或导出成功弹窗点击 **记为取证发现**，或在文件树/列表右键普通文件使用 **记录取证发现**、**计算哈希值（SHA-256）**、**校验一致性…**（与本地副本逐字节比对）与 **单文件检索内容…**，结果自动绑定镜像摘要、分区偏移与 inode 写入审计链。
4. **集中复核、一键导出与定位原文件**：打开 **取证发现**，通过 ② **状态 / 分区偏移** 表头下拉筛选或点击 **序号 / 最近记录** 切换正倒序；在 ③ 双击文件于下方 ④ 展开笔记、摘要与比对明细（点击详情栏右上角 **× 关闭** 可随时收起面板）；点击详情区或条目处的 **定位原文件**，可跨模块一键直跳 **文件浏览** 自动定位、选中并预览该文件；点击右上角 ① **一键导出** 即可批量导出对应副本并生成汇总 Markdown。`,
  },
  {
    title: 'MACB 时间线与审计日志核验',
    navLabel: '时间线与审计日志',
    summary: '通过 MACB 时间线还原文件活动并一键定位原文件，在审计日志中按人工与具体 MCP 使用者追踪全部操作并核验 SHA-256 哈希链。',
    image: 'assets/guide/07_timeline_audit.webp',
    caption: '图 7 · 审计日志页：人工/MCP 分层来源筛选、正倒序切换与可关闭哈希链详情（点击查看大图）',
    content: `1. 在 ① 模块标签栏切换 **MACB 时间线** 与 **审计日志**。大案件首次进入时间线时点击 **生成时间线** 在后台整理事件，序号在翻页与筛选后保持不变。
2. **理解 MACB 四时间与跨模块定位**：**M** 为内容修改，**A** 为访问，**C** 为元数据变更，**B** 为创建。FAT 不保存 C 时间，查看创建时间请看 B 列；界面统一显示 UTC+8，解释 FAT 等无时区时间时请核对源设备时区。在时间线记录行或详情栏点击 **定位原文件**，即可一键直跳 **文件浏览** 对应目录并自动选中预览该文件。
3. **排序与表头下拉筛选**：在时间线与审计日志中，单击 ② **序号** 或 **时间（UTC+8）** 表头可切换正序/倒序；单击 ③ 表头可下拉筛选（时间线支持事件/状态/分区偏移；审计日志支持 **来源（人工 / MCP 及具体 MCP 使用者）**、操作人员、操作、结果）。
4. **查看/关闭详情与防篡改校验**：双击任意记录在下方 ④ 展开完整详情（审计详情含操作来源、MCP 使用者、参数、结果及前序/当前 SHA-256 哈希值）；详情标题栏吸顶固定，随时点击右上角 **× 关闭** 即可收起下方详情页。审计链与 \`audit.head\` 尾部锚点用于检出单方面修改或截断。

> 边界提示：本工具实施应用层只读约束与日志链校验；需要硬件级写保护的采集场景，须另行配合硬件写保护器。`,
  },
  {
    title: '生成双格式报告、复核包与离线核验',
    navLabel: '报告与复核包',
    summary: '通过顶栏「生成报告 ▾」下拉菜单导出 Markdown 与零外链离线 HTML 双格式报告，导出复核包自动同步打包双报告，并支持首页与顶栏一键离线核验。',
    image: 'assets/guide/08_report_bundle.webp',
    caption: '图 8 · 复核包材料选择弹窗：缺失中文清单提示、双标签勾选与导出（点击查看大图）',
    content: `1. **生成 Markdown 与离线 HTML 双报告**：先在 **取证发现** 和 **镜像与文件系统** 核对内容，再点击顶栏 **生成报告 ▾** 下拉菜单，按需选择 **Markdown 报告（.md）**（自动执行完整性校验，生成包含 **人工 vs MCP 协同统计**、**EWF 逐段哈希表** 与 **审计首尾基线抽样** 的 10 章节中文报告）或 **离线 HTML 报告（.html）**（导出零外链离线单文件 HTML 报告，结果弹窗支持一键 **复制路径**、**打开文件**、**打开所在目录** 并展示 SHA-256 摘要）。
2. **按需选择复核包材料（自动同步双报告）**：点击顶栏 **导出复核包**。复核包会自动同步生成并打包最新 \`report.md\` 与 \`report.html\`，同时纳入 \`SHA256SUMS.json\` 及跨文件审计链交叉核对。若案件存在历史导出副本或搜索记录，会弹出材料选择窗口：当部分本地文件已被清理或隔离时，顶部 ① 会给出清晰中文缺失清单，并支持下方 ④ **复制缺失清单**。
3. 在 ② 切换 **导出副本** 与 **内容搜索记录** 标签页，利用 ③ **全选可用副本 / 全不选 / 仅看缺失项** 自由勾选要打入复核包的现存材料，点击 ④ **生成复核包**。未勾选或缺失的历史条目会如实记入 \`manifest.json\` 的 \`omitted_exports\` / \`omitted_searches\`。
4. **桌面端一键可视化核验复核包**：在未开案**全屏启动首页**点击 **离线核验复核包** 快捷瓷砖，或在已开案工作台顶栏 / 未开案 MCP 监控顶栏点击 **核验复核包**（**未打开案件同样可用**），选择 \`.zip\` 复核包即可离线核验。期望摘要留空时自动读取同目录 \`.zip.sha256\` 伴随文件，可视化展示整包 SHA-256、审计链与 64B \`audit.head\` 锚点、跨文件审计链核对及逐成员哈希表，支持「仅看异常成员」筛选并高亮定位任意单字节篡改成员。
5. **CLI 与跨平台脚本独立核验**：复核包与 \`.zip.sha256\` 保存于 \`reports\` 目录（不含原始镜像）。复核人也可使用原生 CLI 毫秒级核验全部成员与审计链，或使用包内附带的独立 \`verify_bundle.py\` 脚本进行跨平台离线核验：

\`\`\`powershell
.\\target\\release\\tracedesk-cli.exe verify-bundle "复核包路径.zip" --sha256 交付方提供的64位摘要
\`\`\``,
  },
  {
    title: 'MCP 实时监控与 AI 客户端接入',
    navLabel: 'MCP 实时监控与接入',
    summary: '内置原生 Rust MCP 服务端 tracedesk-mcp.exe（20 工具 + 2 资源），支持未开案独立监控（← 返回首页）与开案热重载，在桌面端实时透视 AI 协同过程。',
    image: 'assets/guide/09_mcp_dialog.webp',
    caption: '图 9 · MCP 实时监控主工作区：HTTP 服务启停、遥测指标卡、实时操作流与单步详情透视（点击查看大图）',
    content: `1. 未开案时在**全屏启动首页**点击顶部品牌栏右侧 **MCP 服务**（或右栏底部 **MCP 20 工具** 微卡）即可独立进入 **MCP 实时监控**，顶部呈现带 **← 返回首页** 按钮的专属极简顶栏（支持一键返回启动首页，或直接建案/开案自动切入三段式取证工作台）；已开案时可点击顶栏 **MCP 服务** 或切换至 **MCP 实时监控** 标签页。在 ① 顶部控制条可设置本机回环端口并启停内嵌 HTTP 服务（仅监听 \`127.0.0.1\` 且启用 DNS 重绑定与并发连接防护，关闭主窗口时自动停止）；采用仅写入瞬间短锁机制，桌面端打开案件期间无需手动释放锁，后端配合 \`disk_dirty\` 延迟补刷机制，在长任务占锁期间自动登记脏标记并于锁空闲后安全热重载，杜绝界面假刷新，也可随时点击 **立即同步** 手动刷新。
2. 在 ② 查看四项实时遥测指标卡（总调用/执行中、成功率与平均耗时、活跃客户端、只读与受控写入占比），并切换 **实时操作流 / 接入配置 / 工具清单与统计** 三个子视图。
3. 在 ③ **实时操作流** 可按阶段、读写模式、客户端、传输通道（准确区分并同步汇聚内嵌 \`desktop-http\`、独立 \`streamable-http\` 与外部 \`stdio\` 子进程三类通道）与关键词筛选，实时追踪每一步工具调用的“执行中 → 成功 / 失败”全过程。
4. 单击步骤即可在 ④ 右侧可拖拽分栏查看完整时间戳、耗时、来源与目标案件、美化入参 JSON、返回结果预览与错误详情，并支持一键跳转 **审计日志** 核验 SHA-256 哈希链。

> 接入配置与工具统计：切到 **接入配置** 可一键复制 \`tracedesk-mcp.exe\` 的 **stdio**（Claude Desktop、Cursor、Antigravity 等本地客户端推荐，按需拉起子进程）或 **Streamable HTTP** 配置 JSON 与启动命令；切到 **工具清单与统计** 可查看全部 **20 工具 + 2 资源**（含只读分页读取历史搜索明细的 \`tracedesk_read_search_report\`）的读写标识及累计调用耗时，双击工具行可直接筛选该工具的调用流。`,
  },
];

const INLINE_RE = /`([^`]+)`|\*\*([^*]+)\*\*|([①②③④⑤])/g;

function renderInline(text: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  let cursor = 0;
  let key = 0;
  INLINE_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = INLINE_RE.exec(text)) !== null) {
    if (match.index > cursor) {
      out.push(<React.Fragment key={key++}>{text.slice(cursor, match.index)}</React.Fragment>);
    }
    const [, codeText, boldText, refMark] = match;
    if (codeText !== undefined) {
      out.push(<code key={key++}>{codeText}</code>);
    } else if (boldText !== undefined) {
      out.push(<strong key={key++}>{boldText}</strong>);
    } else if (refMark !== undefined) {
      out.push(
        <span key={key++} className="td-step-ref">
          {refMark}
        </span>
      );
    }
    cursor = match.index + match[0].length;
  }
  if (cursor < text.length) {
    out.push(<React.Fragment key={key++}>{text.slice(cursor)}</React.Fragment>);
  }
  return out;
}

const GuideContent: React.FC<{ markdown: string }> = ({ markdown }) => {
  const blocks: React.ReactNode[] = [];
  const lines = markdown.split(/\r?\n/);
  let listType: 'ol' | 'ul' | null = null;
  let listItems: React.ReactNode[] = [];
  let inCode = false;
  let codeLines: string[] = [];
  let blockKey = 0;

  const flushList = () => {
    if (!listType) return;
    if (listType === 'ol') {
      blocks.push(<ol key={blockKey++}>{listItems}</ol>);
    } else {
      blocks.push(<ul key={blockKey++}>{listItems}</ul>);
    }
    listType = null;
    listItems = [];
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith('```')) {
      if (inCode) {
        blocks.push(<pre key={blockKey++}>{codeLines.join('\n')}</pre>);
        codeLines = [];
        inCode = false;
      } else {
        flushList();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line);
      continue;
    }
    const stripped = line.trim();
    if (!stripped) {
      flushList();
      continue;
    }
    if (stripped.startsWith('> ')) {
      flushList();
      blocks.push(
        <div key={blockKey++} className="td-guide-callout">
          {renderInline(stripped.slice(2))}
        </div>
      );
      continue;
    }
    const ordered = /^(\d+)\.\s+(.*)$/.exec(stripped);
    if (ordered) {
      if (listType !== 'ol') {
        flushList();
        listType = 'ol';
      }
      listItems.push(<li key={listItems.length}>{renderInline(ordered[2])}</li>);
      continue;
    }
    if (stripped.startsWith('- ')) {
      if (listType !== 'ul') {
        flushList();
        listType = 'ul';
      }
      listItems.push(<li key={listItems.length}>{renderInline(stripped.slice(2))}</li>);
      continue;
    }
    flushList();
    blocks.push(<p key={blockKey++}>{renderInline(stripped)}</p>);
  }
  if (inCode && codeLines.length > 0) {
    blocks.push(<pre key={blockKey++}>{codeLines.join('\n')}</pre>);
  }
  flushList();

  return <div className="td-guide-article">{blocks}</div>;
};

interface HelpGuideDialogProps {
  onClose: () => void;
}

export const HelpGuideDialog: React.FC<HelpGuideDialogProps> = ({ onClose }) => {
  const [index, setIndex] = useState(0);
  const [lightboxOpen, setLightboxOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const page = GUIDE_PAGES[index];
  const imgSrc = assetUrl(page.image);

  const goTo = (nextIdx: number) => {
    if (nextIdx < 0 || nextIdx >= GUIDE_PAGES.length) return;
    setIndex(nextIdx);
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  };

  return (
    <>
      <Modal
        title="TraceDesk 分步操作引导"
        subtitle="对照真实界面编号标注（①–⑤）快速定位控件 · 点击引导图可放大查看"
        width="min(1040px, 92vw)"
        height="min(720px, 88vh)"
        flushBody
        onClose={onClose}
        footer={
          <>
            <span className="td-muted-text" style={{ fontSize: 12 }}>
              第 {index + 1} / {GUIDE_PAGES.length} 页
            </span>
            <div className="td-modal-footer-spacer" />
            <button
              type="button"
              className="td-btn"
              disabled={index <= 0}
              onClick={() => goTo(index - 1)}
            >
              上一步
            </button>
            <button
              type="button"
              className="td-btn td-btn--soft"
              disabled={index + 1 >= GUIDE_PAGES.length}
              onClick={() => goTo(index + 1)}
            >
              下一步
            </button>
            <button type="button" className="td-btn" onClick={onClose}>
              关闭
            </button>
          </>
        }
      >
        <div className="td-guide-shell">
          <aside className="td-guide-nav">
            <div className="td-guide-nav-heading">操作主题（{GUIDE_PAGES.length}）</div>
            <div className="td-guide-nav-list" role="listbox" aria-label="操作说明主题列表">
              {GUIDE_PAGES.map((item, idx) => (
                <button
                  key={item.navLabel}
                  type="button"
                  role="option"
                  aria-selected={idx === index}
                  title={item.title}
                  className={`td-guide-nav-item ${idx === index ? 'td-guide-nav-item--active' : ''}`}
                  onClick={() => goTo(idx)}
                >
                  <span className="td-mono" style={{ opacity: 0.75 }}>
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.navLabel}
                  </span>
                </button>
              ))}
            </div>
          </aside>

          <div ref={scrollRef} className="td-guide-content">
            <h2 className="td-guide-page-title">
              {index + 1}. {page.title}
            </h2>
            <p className="td-guide-page-summary">{page.summary}</p>

            <div className="td-guide-figure">
              <div
                className="td-guide-figure-canvas"
                title="点击放大查看高清引导图"
                onClick={() => setLightboxOpen(true)}
              >
                <img src={imgSrc} alt={page.caption} />
              </div>
              <div className="td-guide-figure-footer">
                <span>{page.caption}</span>
                <button
                  type="button"
                  className="td-btn td-btn--compact"
                  onClick={() => setLightboxOpen(true)}
                >
                  <UiIcon name="search" size={12} color="var(--text-secondary)" />
                  查看大图
                </button>
              </div>
            </div>

            <GuideContent markdown={page.content} />
          </div>
        </div>
      </Modal>

      {lightboxOpen && (
        <LightboxDialog
          title={page.title}
          caption={page.caption}
          src={imgSrc}
          onClose={() => setLightboxOpen(false)}
        />
      )}
    </>
  );
};
