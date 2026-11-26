/**
 * 只读文件内容预览组件 (PreviewPane)：
 * - 支持 9 种文本编码切换（ASCII / UTF-8 / UTF-16LE / UTF-16BE / GBK / GB18030 / Big5 / Windows-1252 / ISO-8859-1）
 * - 顶部魔数元信息栏：自动展示当前文件真实文件头与前 16B 魔数 HEX；检出扩展名伪装时醒目告警并支持一键预填「记为取证发现」
 * - 十六进制分页视图：凹陷偏移槽 (#F7FAFD / #356391)、00 空字节弱化 (#A8B5C4)、不可打印占位符 · 弱化 (#B2BECA)、
 *   精确字节级命中高亮（HEX 双字节格 + 右侧 ASCII 同步标亮）、字节偏移跳转（0x1A0 / 十进制）与复制当前页文本/HEX
 * - 图片预览：支持超限 (>32MiB / >40MP) 或损坏提示与一键切换十六进制，点击图片弹出高清 Lightbox
 * - 页码底栏：支持双击页码跳页 + 上一页 / 下一页
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { tauriApi } from '../api/tauri';
import {
  PREVIEW_ENCODINGS,
  type EntryView,
  type HexRowDto,
  type InspectEntryMagicResponse,
  type MagicMismatchItemDto,
  type PreviewEncoding,
  type PreviewImageResponse,
  type PreviewPageResponse,
} from '../types/ipc';
import { copyToClipboard, formatError } from '../utils/assets';
import { UiIcon } from './Icons';
import { Pagination } from './Pagination';
import { LightboxDialog } from './dialogs/LightboxDialog';

const PAGE_BYTES = 4096;
const IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tif', 'tiff', 'ico']);

function isLikelyImagePath(path: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  return IMAGE_EXTENSIONS.has(ext);
}

/** 解析十六进制（0x1A0）或十进制字节偏移输入 */
function parseByteOffsetInput(raw: string): number | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (/^0[xX][0-9a-fA-F]+$/.test(trimmed)) {
    const val = Number.parseInt(trimmed.slice(2), 16);
    return Number.isSafeInteger(val) && val >= 0 ? val : null;
  }
  if (/^\d+$/.test(trimmed)) {
    const val = Number.parseInt(trimmed, 10);
    return Number.isSafeInteger(val) && val >= 0 ? val : null;
  }
  return null;
}

/** 生成扩展名伪装一键“记为取证发现”预填笔记 */
function buildMagicFindingPrefill(entry: EntryView, magic: InspectEntryMagicResponse): string {
  const extText = magic.extension ? `.${magic.extension.replace(/^\./, '')}` : '无扩展名';
  const detectedDesc = magic.detectedLabel
    ? `${magic.detectedLabel}${magic.detectedType ? `（${magic.detectedType}）` : ''}`
    : magic.detectedType || '未知类型';
  const levelText = magic.severity === 'high' ? '高危伪装' : '疑似伪装';
  return [
    `【${levelText} · 魔数与扩展名不匹配】`,
    `文件路径：${entry.path}（分区偏移 ${entry.offset}，inode ${entry.inode || '—'}）`,
    `声明扩展名：${extText}；魔数识别真实类型：${detectedDesc}`,
    `研判原因：${magic.reason}`,
    `文件头前 16B 魔数 HEX：${magic.magicHex || '—'}`,
  ].join('\n');
}

interface PreviewPaneProps {
  entry: EntryView | null;
  /** 可选覆盖空态主文案（如“没有匹配项”、“请选择目录中的文件”） */
  emptyMessage?: string;
  /** 初始强制显示模式（内容搜索双击命中定位十六进制弹窗使用） */
  initialTab?: 'primary' | 'hex';
  /** 初始目标页号（从 0 开始，用于搜索命中定位） */
  initialPage?: number;
  /** 高亮并滚动至目标十六进制行号（0..255） */
  highlightHexRow?: number | null;
  /** 可选精确高亮起始绝对字节偏移（文件内偏移，优先于整行高亮） */
  highlightByteStart?: number | null;
  /** 可选精确高亮字节长度（默认 1 字节） */
  highlightByteLength?: number | null;
  /** 跨模块定位令牌：每次变化强制切至 HEX 视图并跳转到 highlightByteStart 所在页与行 */
  locateToken?: number;
  /** 可选魔数扫描缓存命中项（优先展示，避免重复 IPC 探测） */
  cachedMagic?: MagicMismatchItemDto | null;
  /** 是否显示顶部文件魔数识别元信息栏（默认 true） */
  showMagicMeta?: boolean;
  /** 检出魔数伪装时，一键带预填笔记触发「记为取证发现」回调 */
  onRecordFindingWithPrefill?: (entry: EntryView, prefillNote: string) => void;
}

const HexBytesLine: React.FC<{
  bytesHex: string;
  hlStartCol: number;
  hlEndCol: number;
}> = React.memo(({ bytesHex, hlStartCol, hlEndCol }) => {
  const parts = bytesHex.split(/(\s+)/);
  let byteCol = 0;
  return (
    <>
      {parts.map((part, idx) => {
        if (!part) return null;
        if (/^\s+$/.test(part)) {
          return <React.Fragment key={idx}>{part}</React.Fragment>;
        }
        const col = byteCol;
        byteCol += 1;
        const isHit = hlStartCol >= 0 && col >= hlStartCol && col < hlEndCol;
        if (isHit) {
          return (
            <span key={idx} className="td-hex-byte-hit">
              {part}
            </span>
          );
        }
        if (part === '00') {
          return (
            <span key={idx} className="td-hex-null">
              00
            </span>
          );
        }
        return <React.Fragment key={idx}>{part}</React.Fragment>;
      })}
    </>
  );
});

const HexCharsLine: React.FC<{
  chars: string;
  hlStartCol: number;
  hlEndCol: number;
}> = React.memo(({ chars, hlStartCol, hlEndCol }) => {
  if (hlStartCol < 0) {
    if (!chars.includes('·')) {
      return <>{chars}</>;
    }
    // 无精确字节高亮时，将连续的 '·' 与普通字符分段着色，保留原生复杂文字整形
    const segments: { text: string; muted: boolean }[] = [];
    let i = 0;
    while (i < chars.length) {
      const muted = chars[i] === '·';
      let j = i + 1;
      while (j < chars.length && (chars[j] === '·') === muted) {
        j += 1;
      }
      segments.push({ text: chars.slice(i, j), muted });
      i = j;
    }
    return (
      <>
        {segments.map((seg, idx) =>
          seg.muted ? (
            <span key={idx} className="td-hex-dot">
              {seg.text}
            </span>
          ) : (
            <React.Fragment key={idx}>{seg.text}</React.Fragment>
          )
        )}
      </>
    );
  }

  // 精确字节命中时逐字符对照渲染，使右侧 ASCII 与左侧 HEX 双字节格严格同步标亮
  const nodes: React.ReactNode[] = [];
  for (let col = 0; col < chars.length; col += 1) {
    const ch = chars[col];
    const isHit = col >= hlStartCol && col < hlEndCol;
    if (isHit) {
      nodes.push(
        <span key={col} className="td-hex-char-hit">
          {ch}
        </span>
      );
    } else if (ch === '·') {
      nodes.push(
        <span key={col} className="td-hex-dot">
          ·
        </span>
      );
    } else {
      nodes.push(<React.Fragment key={col}>{ch}</React.Fragment>);
    }
  }
  return <>{nodes}</>;
});

/** 单行十六进制记忆化组件：点击切换选中行时仅重渲染变更的 2 行而非全部 256 行 */
const HexRowItem: React.FC<{
  index: number;
  row: HexRowDto;
  selected: boolean;
  hlStartCol: number;
  hlEndCol: number;
  onSelect: (idx: number) => void;
  registerRef: (idx: number, el: HTMLDivElement | null) => void;
}> = React.memo(({ index, row, selected, hlStartCol, hlEndCol, onSelect, registerRef }) => (
  <div
    ref={(el) => registerRef(index, el)}
    className={`td-hex-row ${selected ? 'td-hex-row--selected' : ''}`}
    onClick={() => onSelect(index)}
  >
    <div className="td-hex-offset">{row.offsetHex}</div>
    <div className="td-hex-bytes">
      <HexBytesLine bytesHex={row.bytesHex} hlStartCol={hlStartCol} hlEndCol={hlEndCol} />
    </div>
    <div className="td-hex-chars">
      <HexCharsLine chars={row.chars} hlStartCol={hlStartCol} hlEndCol={hlEndCol} />
    </div>
  </div>
));

export const PreviewPane: React.FC<PreviewPaneProps> = ({
  entry,
  emptyMessage = '请选择文件',
  initialTab = 'primary',
  initialPage = 0,
  highlightHexRow = null,
  highlightByteStart = null,
  highlightByteLength = null,
  locateToken = 0,
  cachedMagic = null,
  showMagicMeta = true,
  onRecordFindingWithPrefill,
}) => {
  const [activeTab, setActiveTab] = useState<'primary' | 'hex'>(initialTab);
  const [encoding, setEncoding] = useState<PreviewEncoding>('UTF-8');
  const [page, setPage] = useState<number>(initialPage);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [pageData, setPageData] = useState<PreviewPageResponse | null>(null);
  const [isImageMode, setIsImageMode] = useState(false);
  const [imageLoading, setImageLoading] = useState(false);
  const [imageData, setImageData] = useState<PreviewImageResponse | null>(null);
  const [selectedHexIdx, setSelectedHexIdx] = useState<number | null>(highlightHexRow);
  const [lightboxOpen, setLightboxOpen] = useState(false);

  // 文件魔数识别状态
  const [magicLoading, setMagicLoading] = useState(false);
  const [inspectedMagic, setInspectedMagic] = useState<InspectEntryMagicResponse | null>(null);

  // 手动字节偏移跳转与复制当前页状态
  const [offsetInput, setOffsetInput] = useState('');
  const [offsetError, setOffsetError] = useState<string | null>(null);
  const [manualJumpHighlight, setManualJumpHighlight] = useState<{
    start: number;
    length: number;
    page: number;
    row: number;
    seq: number;
  } | null>(null);
  const [copiedMode, setCopiedMode] = useState<'text' | 'hex' | null>(null);

  const reqSeqRef = useRef(0);
  const magicReqSeqRef = useRef(0);
  const imageCheckedEntryRef = useRef<string | null>(null);
  const activeEntryIdRef = useRef<string | null>(null);
  const lastInitialPageRef = useRef<number>(initialPage);
  const lastLocateTokenRef = useRef<number>(locateToken);
  const lastLoadedKeyRef = useRef<string | null>(null);
  const hexRowRefs = useRef<Record<number, HTMLDivElement | null>>({});
  const pendingScrollRef = useRef<{ page: number; row: number } | null>(
    highlightByteStart != null
      ? {
          page: Math.floor(highlightByteStart / PAGE_BYTES),
          row: Math.floor((highlightByteStart % PAGE_BYTES) / 16),
        }
      : highlightHexRow != null
        ? { page: initialPage, row: highlightHexRow }
        : null
  );

  const canPreview = Boolean(entry && !entry.directory && !entry.mode.startsWith('V/'));

  const registerHexRowRef = useCallback((idx: number, el: HTMLDivElement | null) => {
    if (el) {
      hexRowRefs.current[idx] = el;
    } else {
      delete hexRowRefs.current[idx];
    }
  }, []);

  const handleSelectHexRow = useCallback((idx: number) => {
    setSelectedHexIdx(idx);
  }, []);

  // 合并魔数信息：优先复用全案扫描缓存，无缓存时按需异步调用 inspectEntryMagic
  const effectiveMagic = useMemo<InspectEntryMagicResponse | null>(() => {
    if (!showMagicMeta || !entry || !canPreview) return null;
    if (cachedMagic) {
      return {
        detectedType: cachedMagic.detectedType,
        detectedFamily: cachedMagic.detectedFamily,
        detectedLabel: cachedMagic.detectedLabel,
        extension: cachedMagic.extension,
        mismatch: true,
        severity: cachedMagic.severity,
        reason: cachedMagic.reason,
        magicHex: cachedMagic.magicHex,
      };
    }
    return inspectedMagic;
  }, [showMagicMeta, entry, canPreview, cachedMagic, inspectedMagic]);

  useEffect(() => {
    const seq = ++magicReqSeqRef.current;
    if (!showMagicMeta || !entry || !canPreview || entry.size === 0 || cachedMagic) {
      setMagicLoading(false);
      if (!cachedMagic) setInspectedMagic(null);
      return;
    }
    setMagicLoading(true);
    setInspectedMagic(null);
    void tauriApi
      .inspectEntryMagic({ entryKey: entry.entryId })
      .then((res) => {
        if (seq !== magicReqSeqRef.current) return;
        setInspectedMagic(res);
      })
      .catch(() => {
        if (seq !== magicReqSeqRef.current) return;
        setInspectedMagic(null);
      })
      .finally(() => {
        if (seq === magicReqSeqRef.current) {
          setMagicLoading(false);
        }
      });
  }, [showMagicMeta, entry?.entryId, entry?.size, canPreview, cachedMagic]);

  const loadPage = useCallback(
    async (targetEntry: EntryView, targetPage: number, targetEncoding: PreviewEncoding, checkImage: boolean) => {
      // 无论是否 0 字节，始终递增序号以作废任何在途的旧文件请求
      const seq = ++reqSeqRef.current;
      if (targetEntry.size === 0) {
        setPageData(null);
        setImageData(null);
        setLoading(false);
        setImageLoading(false);
        setErrorMsg(null);
        setIsImageMode(false);
        return;
      }
      if (checkImage) {
        // 提前登记已触发图片检测，防止并发渲染重复发起 previewFileImage
        imageCheckedEntryRef.current = targetEntry.entryId;
      }
      setLoading(true);
      setErrorMsg(null);
      try {
        const res = await tauriApi.previewFilePage({
          entryId: targetEntry.entryId,
          page: targetPage,
          pageBytes: PAGE_BYTES,
          encoding: targetEncoding,
        });
        if (seq !== reqSeqRef.current) return;
        hexRowRefs.current = {};
        setPageData(res);
        setLoading(false);

        if (checkImage) {
          const candidate = res.isImageCandidate || isLikelyImagePath(targetEntry.path);
          setIsImageMode(candidate);
          if (candidate) {
            setImageLoading(true);
            try {
              const imgRes = await tauriApi.previewFileImage({ entryId: targetEntry.entryId });
              if (seq !== reqSeqRef.current) return;
              setImageData(imgRes);
            } catch (imgErr) {
              if (seq !== reqSeqRef.current) return;
              setImageData({
                ok: false,
                error: `图片读取失败：${formatError(imgErr)}`,
                sourceNote: res.sourceNote,
              });
            } finally {
              if (seq === reqSeqRef.current) setImageLoading(false);
            }
          }
        }
      } catch (err) {
        if (seq !== reqSeqRef.current) return;
        setLoading(false);
        setImageLoading(false);
        setErrorMsg(`读取失败：${formatError(err)}`);
      }
    },
    []
  );

  // 统一响应文件切换、外部定位页号/字节偏移变化、翻页与编码切换，消除切文件时的双发 IPC 请求
  useEffect(() => {
    if (!entry || !canPreview) {
      reqSeqRef.current += 1;
      activeEntryIdRef.current = null;
      imageCheckedEntryRef.current = null;
      lastLoadedKeyRef.current = null;
      hexRowRefs.current = {};
      pendingScrollRef.current = null;
      setLoading(false);
      setImageLoading(false);
      setPageData(null);
      setImageData(null);
      setErrorMsg(null);
      setIsImageMode(false);
      setSelectedHexIdx(null);
      setManualJumpHighlight(null);
      setOffsetInput('');
      setOffsetError(null);
      return;
    }

    const entryChanged = activeEntryIdRef.current !== entry.entryId;
    const locateTriggered = locateToken > 0 && lastLocateTokenRef.current !== locateToken;
    const initialPageChanged = lastInitialPageRef.current !== initialPage;

    if (entryChanged) {
      activeEntryIdRef.current = entry.entryId;
      lastInitialPageRef.current = initialPage;
      lastLocateTokenRef.current = locateToken;
      imageCheckedEntryRef.current = null;
      hexRowRefs.current = {};
      setPageData(null);
      setErrorMsg(null);
      setImageData(null);
      setManualJumpHighlight(null);
      setOffsetInput('');
      setOffsetError(null);

      const hasByteLocate = highlightByteStart != null && highlightByteStart >= 0;
      const targetTab: 'primary' | 'hex' = hasByteLocate ? 'hex' : initialTab;
      const targetPage = hasByteLocate ? Math.floor(highlightByteStart / PAGE_BYTES) : initialPage;
      const targetRow = hasByteLocate
        ? Math.floor((highlightByteStart % PAGE_BYTES) / 16)
        : highlightHexRow;

      setSelectedHexIdx(targetRow);
      setActiveTab(targetTab);
      pendingScrollRef.current = targetRow != null ? { page: targetPage, row: targetRow } : null;

      const likelyImg = entry.size > 0 && targetTab !== 'hex' && isLikelyImagePath(entry.path);
      setIsImageMode(likelyImg);

      const loadKey = `${entry.entryId}|${targetPage}|${encoding}|${targetTab}`;
      lastLoadedKeyRef.current = loadKey;
      if (page !== targetPage) {
        setPage(targetPage);
      }
      const shouldCheckImage = targetTab !== 'hex';
      void loadPage(entry, targetPage, encoding, shouldCheckImage);
      return;
    }

    // 同一文件触发外部跨模块字节定位（例如连续点击同文件内不同搜索命中）
    if (locateTriggered && highlightByteStart != null && highlightByteStart >= 0) {
      lastLocateTokenRef.current = locateToken;
      const targetPage = Math.floor(highlightByteStart / PAGE_BYTES);
      const targetRow = Math.floor((highlightByteStart % PAGE_BYTES) / 16);
      setManualJumpHighlight(null);
      setActiveTab('hex');
      setSelectedHexIdx(targetRow);
      pendingScrollRef.current = { page: targetPage, row: targetRow };
      const loadKey = `${entry.entryId}|${targetPage}|${encoding}|hex`;
      if (lastLoadedKeyRef.current !== loadKey) {
        lastLoadedKeyRef.current = loadKey;
        if (page !== targetPage) {
          setPage(targetPage);
        }
        void loadPage(entry, targetPage, encoding, false);
      }
      return;
    }

    // 同一文件在外部切换目标定位页（如内容搜索命中弹窗切换同文件不同偏移）时同步页号
    if (initialPageChanged) {
      lastInitialPageRef.current = initialPage;
      const targetRow =
        highlightByteStart != null && highlightByteStart >= 0
          ? Math.floor((highlightByteStart % PAGE_BYTES) / 16)
          : highlightHexRow;
      setManualJumpHighlight(null);
      setSelectedHexIdx(targetRow);
      pendingScrollRef.current = targetRow != null ? { page: initialPage, row: targetRow } : null;
      const loadKey = `${entry.entryId}|${initialPage}|${encoding}|${initialTab}`;
      lastLoadedKeyRef.current = loadKey;
      if (page !== initialPage) {
        setPage(initialPage);
      }
      const shouldCheckImage = initialTab !== 'hex' && imageCheckedEntryRef.current !== entry.entryId;
      void loadPage(entry, initialPage, encoding, shouldCheckImage);
      return;
    }

    // 若上一次刚因切换文件已用相同参数发起加载，则跳过本次因 setPage 同步触发的冗余重入
    const loadKey = `${entry.entryId}|${page}|${encoding}|${activeTab}`;
    if (lastLoadedKeyRef.current === loadKey) {
      return;
    }
    lastLoadedKeyRef.current = loadKey;
    const shouldCheckImage = activeTab !== 'hex' && imageCheckedEntryRef.current !== entry.entryId;
    void loadPage(entry, page, encoding, shouldCheckImage);
  }, [
    entry?.entryId,
    canPreview,
    page,
    encoding,
    initialPage,
    initialTab,
    highlightHexRow,
    highlightByteStart,
    locateToken,
    activeTab,
    loadPage,
  ]);

  // 自动滚动至目标高亮十六进制行（兼容跨模块定位与手动字节偏移跳转）
  useEffect(() => {
    if (activeTab !== 'hex' || !pageData) return;
    const target = pendingScrollRef.current;
    if (target && pageData.page === target.page) {
      pendingScrollRef.current = null;
      setSelectedHexIdx(target.row);
      const node = hexRowRefs.current[target.row];
      if (node) {
        node.scrollIntoView({ block: 'center' });
      }
    }
  }, [activeTab, pageData, manualJumpHighlight?.seq, locateToken]);

  // 字节偏移快速跳转（支持 0x1A0 十六进制或十进制）
  const handleJumpByteOffset = useCallback(() => {
    if (!entry) return;
    const parsed = parseByteOffsetInput(offsetInput);
    if (parsed === null) {
      setOffsetError('请输入有效字节偏移，如 0x1A0 或 416');
      return;
    }
    const maxSize = Math.max(pageData?.size ?? 0, entry.size);
    if (maxSize > 0 && parsed >= maxSize) {
      setOffsetError(
        `超出文件大小（范围 0 ~ ${maxSize - 1} / 0x${(maxSize - 1).toString(16).toUpperCase()}）`
      );
      return;
    }
    setOffsetError(null);
    const targetPage = Math.floor(parsed / PAGE_BYTES);
    const targetRow = Math.floor((parsed % PAGE_BYTES) / 16);
    pendingScrollRef.current = { page: targetPage, row: targetRow };
    setManualJumpHighlight({
      start: parsed,
      length: 1,
      page: targetPage,
      row: targetRow,
      seq: Date.now(),
    });
    setActiveTab('hex');
    setSelectedHexIdx(targetRow);
    if (page !== targetPage) {
      setPage(targetPage);
    } else {
      const node = hexRowRefs.current[targetRow];
      if (node) {
        node.scrollIntoView({ block: 'center' });
      }
    }
  }, [entry, offsetInput, pageData?.size, page]);

  // 复制当前页文本或当前页 HEX
  const handleCopyCurrentPage = useCallback(async () => {
    if (!pageData) return;
    if (activeTab === 'hex') {
      const lines = pageData.hexRows.map(
        (r) => `${r.offsetHex}  ${r.bytesHex.padEnd(48, ' ')}  ${r.chars}`
      );
      const ok = await copyToClipboard(lines.join('\n'));
      if (ok) {
        setCopiedMode('hex');
        window.setTimeout(() => setCopiedMode((prev) => (prev === 'hex' ? null : prev)), 1800);
      }
    } else {
      const ok = await copyToClipboard(pageData.text ?? '');
      if (ok) {
        setCopiedMode('text');
        window.setTimeout(() => setCopiedMode((prev) => (prev === 'text' ? null : prev)), 1800);
      }
    }
  }, [activeTab, pageData]);

  // 合并当前生效的精确字节高亮范围（手动跳转优先于外部传入）
  const activeByteHighlight = useMemo(() => {
    if (manualJumpHighlight) {
      return { start: manualJumpHighlight.start, length: manualJumpHighlight.length };
    }
    if (highlightByteStart != null && highlightByteStart >= 0) {
      return {
        start: highlightByteStart,
        length: Math.max(1, highlightByteLength ?? 1),
      };
    }
    return null;
  }, [manualJumpHighlight, highlightByteStart, highlightByteLength]);

  if (!entry || !canPreview) {
    return (
      <div className="td-preview-empty">
        <UiIcon name="document_preview" size={32} color="var(--text-disabled)" />
        <div className="td-preview-empty-title">
          {entry && (entry.directory || entry.mode.startsWith('V/'))
            ? '请选择目录中的文件'
            : emptyMessage}
        </div>
        <div className="td-preview-empty-hint">
          单击文件即可只读预览文本、图片或原始十六进制字节
        </div>
      </div>
    );
  }

  const showingImage = isImageMode && activeTab === 'primary';
  const totalPages = Math.max(1, pageData?.totalPages ?? Math.ceil(Math.max(1, entry.size) / PAGE_BYTES));
  const hexRows: HexRowDto[] = pageData?.hexRows ?? [];

  let statusText = '';
  if (entry.size === 0) {
    statusText = entry.deleted ? '删除记录为 0 字节，无内容可显示' : '空文件（0 字节）';
  } else if (showingImage) {
    if (imageLoading) {
      statusText = '正在读取图片…';
    } else if (imageData?.ok) {
      statusText = [
        `图片 ${imageData.width ?? '?'} × ${imageData.height ?? '?'}`,
        imageData.animated ? '首帧' : '',
        imageData.sourceNote,
      ]
        .filter(Boolean)
        .join(' · ');
    } else if (imageData?.error) {
      statusText = [imageData.error, imageData.sourceNote].filter(Boolean).join(' · ');
    } else {
      statusText = '正在读取图片…';
    }
  } else if (loading) {
    statusText = '正在读取…';
  } else if (errorMsg) {
    statusText = errorMsg;
  } else if (pageData) {
    statusText = [
      `第 ${pageData.page + 1} / ${totalPages} 页`,
      pageData.sourceNote,
      pageData.readNote,
    ]
      .filter(Boolean)
      .join(' · ');
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      {/* 预览模式栏：文本/图片 | 十六进制 + 字节偏移跳转 + 复制当前页 + 编码选择 */}
      <div className="td-preview-mode-bar">
        <div className="td-preview-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'primary'}
            className={`td-preview-tab ${activeTab === 'primary' ? 'td-preview-tab--active' : ''}`}
            onClick={() => setActiveTab('primary')}
          >
            {isImageMode ? '图片' : '文本'}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'hex'}
            className={`td-preview-tab ${activeTab === 'hex' ? 'td-preview-tab--active' : ''}`}
            onClick={() => setActiveTab('hex')}
          >
            十六进制
          </button>
        </div>

        <div className="td-preview-tools">
          {entry.size > 0 && (
            <div className="td-preview-offset-jump">
              <input
                type="text"
                className={`td-input td-mono td-preview-offset-input ${offsetError ? 'td-input--error' : ''}`}
                placeholder="偏移 0x1A0 / 416"
                aria-label="字节偏移跳转"
                title={offsetError || '输入十六进制（如 0x1A0）或十进制字节偏移，按回车跳转至 HEX 对应字节'}
                value={offsetInput}
                disabled={loading}
                onChange={(e) => {
                  setOffsetInput(e.target.value);
                  if (offsetError) setOffsetError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleJumpByteOffset();
                  }
                }}
              />
              <button
                type="button"
                className="td-btn td-btn--compact"
                disabled={loading || !offsetInput.trim()}
                title="跳转到指定字节偏移并在十六进制视图中精确高亮"
                onClick={handleJumpByteOffset}
              >
                跳转
              </button>
            </div>
          )}

          {!showingImage && entry.size > 0 && (
            <button
              type="button"
              className="td-btn td-btn--compact"
              disabled={loading || !pageData || (activeTab === 'hex' ? hexRows.length === 0 : false)}
              title={activeTab === 'hex' ? '复制当前页十六进制转储内容' : '复制当前页解码后的文本内容'}
              onClick={() => void handleCopyCurrentPage()}
            >
              <UiIcon
                name={copiedMode ? 'check_circle' : 'copy'}
                size={12}
                color={copiedMode ? 'var(--ok-fg)' : 'var(--text-secondary)'}
              />
              {copiedMode === 'hex'
                ? '已复制 HEX'
                : copiedMode === 'text'
                  ? '已复制文本'
                  : activeTab === 'hex'
                    ? '复制当前页 HEX'
                    : '复制当前页文本'}
            </button>
          )}

          {!showingImage && (
            <div className="td-preview-encoding">
              <label htmlFor="td-preview-encoding-select">编码</label>
              <select
                id="td-preview-encoding-select"
                className="td-select"
                value={encoding}
                disabled={loading || entry.size === 0}
                onChange={(e) => setEncoding(e.target.value as PreviewEncoding)}
              >
                {PREVIEW_ENCODINGS.map((enc) => (
                  <option key={enc} value={enc}>
                    {enc}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>
      </div>

      {/* 字节偏移输入错误轻量提示条 */}
      {offsetError && (
        <div className="td-preview-offset-err">
          <UiIcon name="warning" size={13} color="var(--warn-fg)" />
          <span>{offsetError}</span>
        </div>
      )}

      {/* 预览顶部文件魔数元信息栏（支持伪装告警与一键记为取证发现） */}
      {showMagicMeta && entry.size > 0 && (magicLoading || effectiveMagic) && (
        <div
          className={`td-preview-magic-bar ${
            effectiveMagic?.mismatch
              ? effectiveMagic.severity === 'high'
                ? 'td-preview-magic-bar--danger'
                : 'td-preview-magic-bar--warn'
              : ''
          }`}
        >
          {magicLoading && !effectiveMagic ? (
            <span className="td-muted-text" style={{ fontSize: 11.5 }}>
              正在探测文件头魔数（Magic Bytes）…
            </span>
          ) : effectiveMagic?.mismatch ? (
            <>
              <span
                className={`td-pill ${
                  effectiveMagic.severity === 'high' ? 'td-pill--danger' : 'td-pill--warn'
                }`}
              >
                {effectiveMagic.severity === 'high'
                  ? `高危伪装 · 实为 ${effectiveMagic.detectedType || '未知'}`
                  : `疑似伪装 · 实为 ${effectiveMagic.detectedType || '未知'}`}
              </span>
              <span className="td-preview-magic-reason" title={effectiveMagic.reason}>
                {effectiveMagic.reason}
              </span>
              {effectiveMagic.magicHex && (
                <span className="td-preview-magic-hex td-mono" title="文件头前 16 字节魔数 HEX">
                  HEX: {effectiveMagic.magicHex}
                </span>
              )}
              {onRecordFindingWithPrefill && (
                <button
                  type="button"
                  className="td-btn td-btn--compact td-preview-magic-note-btn"
                  title="自动预填魔数伪装研判笔记并写入取证发现"
                  onClick={() =>
                    onRecordFindingWithPrefill(entry, buildMagicFindingPrefill(entry, effectiveMagic))
                  }
                >
                  <UiIcon name="note" size={12} color="var(--accent-soft-text)" />
                  记为取证发现
                </button>
              )}
            </>
          ) : effectiveMagic ? (
            <>
              <UiIcon name="magic" size={13} color="var(--accent)" />
              <span className="td-preview-magic-label">
                真实文件头：
                <strong>
                  {effectiveMagic.detectedLabel ||
                    effectiveMagic.detectedType ||
                    '纯文本 / 无特定二进制魔数'}
                </strong>
                {effectiveMagic.detectedType && effectiveMagic.detectedLabel
                  ? ` (${effectiveMagic.detectedType})`
                  : ''}
              </span>
              <span className="td-preview-magic-sep">·</span>
              <span className="td-muted-text">
                扩展名：{effectiveMagic.extension ? `.${effectiveMagic.extension.replace(/^\./, '')}` : '无'}
              </span>
              {effectiveMagic.magicHex && (
                <>
                  <span className="td-preview-magic-sep">·</span>
                  <span className="td-preview-magic-hex td-mono" title="文件头前 16 字节魔数 HEX">
                    前 16B：{effectiveMagic.magicHex}
                  </span>
                </>
              )}
            </>
          ) : null}
        </div>
      )}

      <div className="td-preview-body">
        {entry.size === 0 ? (
          <div className="td-preview-empty">
            <div className="td-preview-empty-title">{statusText}</div>
          </div>
        ) : showingImage ? (
          <div className="td-preview-image-wrap">
            {imageLoading ? (
              <span className="td-muted-text">正在读取图片…</span>
            ) : imageData?.ok && imageData.dataUrl ? (
              <img
                src={imageData.dataUrl}
                alt={entry.name}
                title="点击放大查看图片"
                onClick={() => setLightboxOpen(true)}
              />
            ) : (
              <div className="td-preview-image-error">
                <UiIcon name="warning" size={28} color="var(--warn-fg)" fill="var(--warn-bg)" />
                <div>
                  {imageData?.error || '图片损坏或格式不受支持'}；可切换十六进制查看原始字节。
                </div>
                <button
                  type="button"
                  className="td-btn td-btn--soft"
                  onClick={() => setActiveTab('hex')}
                >
                  切换到十六进制视图
                </button>
              </div>
            )}
          </div>
        ) : activeTab === 'primary' ? (
          <pre className="td-preview-text">
            {errorMsg ? errorMsg : loading && !pageData ? '正在读取…' : pageData?.text ?? ''}
          </pre>
        ) : (
          <div className="td-hex-container">
            <div className="td-hex-header">
              <div>文件偏移 (HEX)</div>
              <div>十六进制</div>
              <div>字符</div>
            </div>
            <div>
              {hexRows.map((row, idx) => {
                const parsedRowStart = Number.parseInt(row.offsetHex.replace(/^0x/i, ''), 16);
                const rowStart = Number.isNaN(parsedRowStart)
                  ? (pageData?.page ?? page) * PAGE_BYTES + idx * 16
                  : parsedRowStart;
                let hlStartCol = -1;
                let hlEndCol = -1;
                if (
                  activeByteHighlight &&
                  rowStart + 16 > activeByteHighlight.start &&
                  rowStart < activeByteHighlight.start + activeByteHighlight.length
                ) {
                  hlStartCol = Math.max(0, activeByteHighlight.start - rowStart);
                  hlEndCol = Math.min(
                    16,
                    activeByteHighlight.start + activeByteHighlight.length - rowStart
                  );
                }
                return (
                  <HexRowItem
                    key={row.offsetHex}
                    index={idx}
                    row={row}
                    selected={selectedHexIdx === idx}
                    hlStartCol={hlStartCol}
                    hlEndCol={hlEndCol}
                    onSelect={handleSelectHexRow}
                    registerRef={registerHexRowRef}
                  />
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div className="td-table-footer">
        {showingImage || entry.size === 0 ? (
          <span className="td-page-badge td-mono" title={statusText}>
            {statusText}
          </span>
        ) : (
          <Pagination
            page={page}
            totalPages={totalPages}
            disabled={loading}
            badgeText={statusText || `第 ${page + 1} / ${totalPages} 页`}
            allowJump={!loading && !errorMsg && totalPages > 1}
            layout="spread"
            onPageChange={(nextPage) => setPage(nextPage)}
          />
        )}
      </div>

      {lightboxOpen && imageData?.ok && imageData.dataUrl && (
        <LightboxDialog
          title={entry.path}
          caption={`${entry.path} · ${imageData.width ?? '?'} × ${imageData.height ?? '?'} px`}
          src={imageData.dataUrl}
          onClose={() => setLightboxOpen(false)}
        />
      )}
    </div>
  );
};
