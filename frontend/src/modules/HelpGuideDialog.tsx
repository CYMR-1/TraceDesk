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
    summary: '用项目内置的 FAT16 演示镜像，5 步走通建案、浏览、预览、导出校验与报告生成闭环。',
    image: 'assets/guide/01_quickstart.webp',
    caption: '图 1 · 工作台分区布局与演示流程五大核心入口（点击查看大图）',
    content: `1. 点击顶部 ① **新建案件**。编号可填 \`DEMO-01\`，取证人员填自己的姓名，对象填“FAT16 演示镜像”。选择案件上级目录，确认案件目录地址后点击 **创建案件**。
2. 点击右侧 ② **加载镜像**，选择项目里的 \`evidence/demo.dd\`。等待文件树自动建立后，在左侧 ③ 展开偏移 **2048 扇区** 的分区，进入 **DOCS**，选中 **CASE.TXT**。
3. 在下方 ④ **文本** 页应看到 \`Case note inside a nested directory.\`。切到 **十六进制**，首行偏移为 \`00000000\`，开头四个字节为 \`43 61 73 65\`（对应 “Case”）。
4. 点击预览区右上方的 **导出所选文件**，在结果窗口点 **打开文件所在文件夹**。回到工作台，右键同一个 \`CASE.TXT\`，选择 **校验一致性…**，选中刚导出的副本，结果应显示 **一致**。
5. 点击顶部 ⑤ **生成 Markdown 报告**，打开生成的文件，在“导出副本”和“文件取证发现”两节核对文件路径与 SHA-256 摘要。`,
  },
  {
    title: '创建案件、加载镜像与登记来源',
    navLabel: '建案、加载与来源',
    summary: '确保源镜像与案件库分离存放，在“镜像与文件系统”页核对固定摘要、卷声明范围与交付方摘要比对结果。',
    image: 'assets/guide/02_case_and_source.webp',
    caption: '图 2 · 镜像与文件系统页：固定摘要、覆盖范围评估与来源登记（点击查看大图）',
    content: `1. 启动 TraceDesk 桌面工作台。点击 ① **新建案件**，填写案件编号、取证人员和取证对象；选择上级目录，并可直接修改案件文件夹名。
2. 每个案件固定分析一份镜像，源镜像必须放在案件库目录之外（例如案件放在 \`cases\`，镜像放在同级 \`evidence\`）。点击 ② **加载镜像**，选择 RAW 镜像或分段 EWF 的 **.E01 首段**（所有续段需位于同一目录）。
3. 切换到 **镜像与文件系统**，点击右上角 ③ **登记证据来源**，填写证据编号、来源、采集时间与时区、采集工具；如交付方提供了 SHA-256，填入其 64 位十六进制摘要。
4. 在 ④ **证据固定 / 覆盖范围与证据来源** 区域核对路径、逻辑大小（点击大小数值可在 TiB / GiB / MiB / KiB 与精确字节数之间切换）、SHA-256、卷声明范围及交付方摘要比对结论；在 ⑤ 查看底层原始分区表（\`mmls\`）与文件系统信息（\`fsstat\`）。

> 继续已有案件：点击顶部 ① **打开案件**，选择案件目录中的 \`case.json\`。备份或移交案件时请复制整个案件文件夹（含压缩清单、审计链与导出材料）。`,
  },
  {
    title: '大镜像、完整索引与 SHA-256',
    navLabel: '大镜像与 SHA-256',
    summary: '逻辑容量达到 1 GiB 时自动切换为按需目录浏览，可边浏览边在后台校验基线，按需建立完整索引。',
    image: 'assets/guide/03_large_image.webp',
    caption: '图 3 · 大容量镜像按需目录浏览、完整索引与后台校验入口（点击查看大图）',
    content: `- **先浏览，不阻塞**　小于 1 GiB 的镜像会自动固定摘要并扫描全部分区；达到 1 GiB 时先打开首个可读根目录，并在 ① 保管状态条标明“整镜像 SHA-256 待固定”。左侧文件树支持点击分区或目录按需逐层展开并缓存多分支，也可双击目录深入浏览、点击左侧 ② **返回上级目录** 回退。
- **按需建立完整索引**　需要全案内容搜索或 MACB 时间线时，点击左侧 ③ **建立完整文件索引**。写入完成前可随时点 **取消建立索引**，已有目录结果会保留；完成后清单压缩保存至 \`inventory-*.jsonl.gz\`，重开案件直接复用。
- **后台校验与固定基线**　点击右上角 ④ **校验完整性**。大镜像首次完整读取会建立 SHA-256 基线，后续校验与基线比对；读取期间可继续浏览目录，也可点击 **取消校验** 中止本次读取。EWF 首次解码逻辑介质并固定全部分段，后续逐段复算封装摘要。
- **正式报告前置条件**　大镜像在固定前导出的副本会标明“初步分析”；重新打开已固定大镜像案件后，需先完成本次会话的完整性校验，再导出副本或生成正式报告。

> 说明：Windows 在大镜像会话期间对 RAW 或全部 EWF 分段持有拒写/拒删除共享句柄。卷声明范围已覆盖仅说明声明结束位置落在镜像内，是否完整采集仍需结合采集记录核验。`,
  },
  {
    title: '定位目录、筛选文件与多格式预览',
    navLabel: '浏览、筛选与预览',
    summary: '左侧保留完整目录树，筛选仅过滤当前范围列表；下方支持文本（9 编码）、图片与十六进制分页预览。',
    image: 'assets/guide/04_browse_preview.webp',
    caption: '图 4 · 文件树、条件筛选栏与十六进制/多编码分页预览（点击查看大图）',
    content: `1. 在左侧树选择镜像、分区或目录，可用 ① **全部展开 / 全部折叠** 控制层级。遇到跨分区同名文件，结合 **分区偏移、路径、inode** 精准区分。
2. 在 ② 筛选栏输入后缀（如 \`.txt\`）或路径关键词，或在状态下拉框选择 **现存文件 / 已删除**，按回车或点击 **筛选**；点击 **重置** 恢复当前范围。筛选不裁剪左侧完整树。
3. 在 ③ 文件列表核对状态胶囊、字节数、inode 与 MACB 四时间（UTC+8）。单击文件即可在下方预览，预览区右上角提供 **记为取证发现** 与 **导出所选文件** 快捷按钮；右键文件也可快速导出、记录发现、计算摘要、校验一致性或 **单文件检索内容…**；超过 1,000 项时列表自动按每页 100 项分页。
4. 在 ④ 切换 **文本 / 十六进制**，中文乱码时按来源在 **编码** 下拉框选择 UTF-8、UTF-16LE/BE、GBK、GB18030、Big5 等 9 种编码。可识别的图片自动显示 **图片** 页（上限 32 MiB、4000 万像素），并可随时切回 **十六进制** 核对原始字节。
5. 使用下方 **上一页 / 下一页** 翻页，或双击 ⑤ 页码徽标直接输入目标页号跳转（大普通文件可直接跳到末页）。`,
  },
  {
    title: '搜索文件内容并实时复核命中',
    navLabel: '内容搜索与复核',
    summary: '支持 UTF-8、UTF-16LE、GBK 与 HEX 精确字节检索，结果实时流式展示，搜索期间即可筛选、排除并保存为取证发现。',
    image: 'assets/guide/05_content_search.webp',
    caption: '图 5 · 内容搜索与复核页：实时流式命中、三态全选与批量保存（点击查看大图）',
    content: `1. 切换到 **内容搜索与复核**。在 ① 输入搜索文字或十六进制字节（文本编码会精确保留首尾空格），选择编码与范围（**全部文件** 或 **文件浏览中选中的文件**；大镜像全案搜索需先建立完整索引），点击 **搜索**。运行中按钮自动切换为 **取消搜索**。
2. 用演示镜像验证：选择编码 **HEX**，输入 \`6E 6F 74 65\`，点击 **搜索**，即可在 ④ 命中 \`DOCS/CASE.TXT\`，**文件内字节偏移为 5**（从文件开头的 0 起算）。
3. 搜索不设命中上限，结果一边扫描一边实时展示。搜索期间即可通过 ③ 表头 **全选** 三态复选框勾选命中，或点击 **分区偏移** 表头下拉筛选。
4. 双击 ④ 中任意命中行，直接弹出对应偏移的十六进制精准定位预览；勾选一条或多条命中后，点击 ② **排除所选项** 剔除误报，或点击 **保存为取证发现** 批量写入审计链。
5. 每次搜索的完整命中、范围、校验方式与失败明细均自动保存至案件 \`reports/search_*.json\`。

> 说明：内容搜索覆盖清单中可读取的文件及已删除记录，不解压归档文档、不扫描未分配空间。`,
  },
  {
    title: '导出副本、恢复删除文件与取证发现',
    navLabel: '导出与取证发现',
    summary: '导出前后自动复核原镜像，支持已删除文件可读字节恢复；右键文件工具与“取证发现”页形成结构化证据归档。',
    image: 'assets/guide/06_export_findings.webp',
    caption: '图 6 · 取证发现页：表头筛选排序、一键批量导出与可关闭分栏详情（点击查看大图）',
    content: `1. **导出文件副本**：在 **文件浏览** 选中现存或已删除文件，点击 **导出所选文件**。副本保存至案件 \`exports\` 目录（重名时不再创建子目录，直接在 \`exports\` 下于文件名后追加 \`(1)\`、\`(2)\` 等序号后缀，如 \`NOTES(1).TXT\`），并记录副本 SHA-256；导出成功弹窗支持直接点击 **记为取证发现** 顺手补录研判笔记。
2. **恢复已删除文件**：将状态切为 **已删除**，选中记录核对能否预览、目录记录大小及恢复提示后再导出。若提示“部分导出”、inode 已重分配或 FAT 起始簇已被占用，应如实记录实际字节数并结合内容研判。
3. **记录取证发现与文件工具**：在预览区右上角或导出成功弹窗点击 **记为取证发现**，或在文件树/列表右键普通文件使用 **记录取证发现**、**计算哈希值（SHA-256）**、**校验一致性…**（与本地副本逐字节比对）与 **单文件检索内容…**，结果自动绑定镜像摘要、分区偏移与 inode 写入审计链。
4. **集中复核与一键导出**：打开 **取证发现**，通过 ② **状态 / 分区偏移** 表头下拉筛选或点击 **序号 / 最近记录** 切换正倒序；在 ③ 双击文件于下方 ④ 展开笔记、摘要与比对明细（点击详情栏右上角 **× 关闭** 可随时收起详情面板），点击右上角 ① **一键导出** 即可批量导出对应副本并生成汇总 Markdown。`,
  },
  {
    title: 'MACB 时间线与审计日志核验',
    navLabel: '时间线与审计日志',
    summary: '通过 MACB 时间线还原文件活动脉络，在审计日志中按人工与具体 MCP 使用者追踪全部操作并核验 SHA-256 哈希链。',
    image: 'assets/guide/07_timeline_audit.webp',
    caption: '图 7 · 审计日志页：人工/MCP 分层来源筛选、正倒序切换与可关闭哈希链详情（点击查看大图）',
    content: `1. 在 ① 模块标签栏切换 **MACB 时间线** 与 **审计日志**。大案件首次进入时间线时点击 **生成时间线** 在后台整理事件，序号在翻页与筛选后保持不变。
2. **理解 MACB 四时间**：**M** 为内容修改，**A** 为访问，**C** 为元数据变更，**B** 为创建。FAT 不保存 C 时间，查看创建时间请看 B 列；界面统一显示 UTC+8，解释 FAT 等无时区时间时请核对源设备时区。
3. **排序与表头下拉筛选**：在时间线与审计日志中，单击 ② **序号** 或 **时间（UTC+8）** 表头可切换正序/倒序；单击 ③ 表头可下拉筛选（时间线支持事件/状态/分区偏移；审计日志支持 **来源（人工 / MCP 及具体 MCP 使用者）**、操作人员、操作、结果）。
4. **查看/关闭详情与防篡改校验**：双击任意记录在下方 ④ 展开完整详情（审计详情含操作来源、MCP 使用者、参数、结果及前序/当前 SHA-256 哈希值）；详情标题栏吸顶固定，随时点击右上角 **× 关闭** 即可收起下方详情页。审计链与 \`audit.head\` 尾部锚点用于检出单方面修改或截断。

> 边界提示：本工具实施应用层只读约束与日志链校验；需要硬件级写保护的采集场景，须另行配合硬件写保护器。`,
  },
  {
    title: '生成报告与交付可核验复核包',
    navLabel: '报告与复核包',
    summary: '生成结构化 Markdown 取证报告，并通过材料选择窗口按需构建可独立离线核验的 ZIP64 复核包。',
    image: 'assets/guide/08_report_bundle.webp',
    caption: '图 8 · 复核包材料选择弹窗：缺失中文清单提示、双标签勾选与导出（点击查看大图）',
    content: `1. **生成 Markdown 报告**：先在 **取证发现** 和 **镜像与文件系统** 核对内容，再点击顶部 **生成 Markdown 报告**。程序会执行完整性校验并将 10 章节中文报告写入案件 \`reports\` 目录。
2. **按需选择复核包材料**：点击顶部 **导出复核包**。若案件存在历史导出副本或搜索记录，会弹出材料选择窗口：当部分本地文件已被清理或隔离时，顶部 ① 会给出清晰中文缺失清单，并支持下方 ④ **复制缺失清单**。
3. 在 ② 切换 **导出副本** 与 **内容搜索记录** 标签页，利用 ③ **全选可用项 / 全不选 / 仅看缺失项** 自由勾选要打入复核包的现存材料，点击 ④ **生成复核包**。未勾选或缺失的历史条目会如实记入 \`manifest.json\` 的 \`omitted_exports\` / \`omitted_searches\`。
4. **独立离线核验**：复核包与 \`.zip.sha256\` 保存于 \`reports\` 目录（不含原始镜像）。通过独立渠道交付 ZIP 摘要后，复核人可使用原生 CLI 毫秒级核验全部成员与审计链（包内同时附带独立 \`verify_bundle.py\` 脚本供跨平台核验）：

\`\`\`powershell
.\\target\\release\\tracedesk-cli.exe verify-bundle "复核包路径.zip" --sha256 交付方提供的64位摘要
\`\`\``,
  },
  {
    title: 'MCP 实时监控与 AI 客户端接入',
    navLabel: 'MCP 实时监控与接入',
    summary: '内置原生 Rust MCP 服务端 tracedesk-mcp.exe（19 工具 + 2 资源），采用仅写入瞬间短锁与跨进程遥测，在桌面端实时透视外部 AI 协同过程。',
    image: 'assets/guide/09_mcp_dialog.webp',
    caption: '图 9 · MCP 实时监控主工作区：HTTP 服务启停、遥测指标卡、实时操作流与单步详情透视（点击查看大图）',
    content: `1. 点击工作台顶部 **MCP 服务** 按钮或直接切换到 **MCP 实时监控** 标签页。在 ① 顶部控制条可设置本机回环端口并启停内嵌 HTTP 服务（仅监听 \`127.0.0.1\` 且启用 DNS 重绑定与并发连接防护，关闭主窗口时自动停止）；采用仅写入瞬间短锁机制，桌面端打开案件期间无需手动释放锁，MCP 完成受控写入后会自动温和刷新界面，也可点击 **立即同步** 手动刷新。
2. 在 ② 查看四项实时遥测指标卡（总调用/执行中、成功率与平均耗时、活跃客户端、只读与受控写入占比），并切换 **实时操作流 / 接入配置 / 工具清单与统计** 三个子视图。
3. 在 ③ **实时操作流** 可按阶段、读写模式、客户端、传输通道（同步汇聚 \`desktop-http\`、\`streamable-http\` 与外部 \`stdio\` 子进程）与关键词筛选，实时追踪每一步工具调用的“执行中 → 成功 / 失败”全过程。
4. 单击步骤即可在 ④ 右侧可拖拽分栏查看完整时间戳、耗时、来源与目标案件、美化入参 JSON、返回结果预览与错误详情，并支持一键跳转 **审计日志** 核验 SHA-256 哈希链。

> 接入配置与工具统计：切到 **接入配置** 可一键复制 \`tracedesk-mcp.exe\` 的 **stdio**（Claude Desktop、Cursor、Antigravity 等本地客户端推荐，按需拉起子进程）或 **Streamable HTTP** 配置 JSON 与启动命令；切到 **工具清单与统计（19）** 可查看只读/受控写入标识及累计调用耗时，双击工具行可直接筛选该工具的调用流。`,
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
