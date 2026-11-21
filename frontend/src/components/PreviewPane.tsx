/**
 * 只读文件内容预览组件 (PreviewPane)：
 * - 支持 9 种文本编码切换（ASCII / UTF-8 / UTF-16LE / UTF-16BE / GBK / GB18030 / Big5 / Windows-1252 / ISO-8859-1）
 * - 十六进制分页视图：凹陷偏移槽 (#F7FAFD / #356391)、00 空字节弱化 (#A8B5C4)、不可打印占位符 · 弱化 (#B2BECA)、2.5px 晴空蓝选中导轨
 * - 图片预览：支持超限 (>32MiB / >40MP) 或损坏提示与一键切换十六进制，点击图片弹出高清 Lightbox
 * - 页码底栏：支持双击页码跳页 + 上一页 / 下一页
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { tauriApi } from '../api/tauri';
import {
  PREVIEW_ENCODINGS,
  type EntryView,
  type HexRowDto,
  type PreviewEncoding,
  type PreviewImageResponse,
  type PreviewPageResponse,
} from '../types/ipc';
import { formatError } from '../utils/assets';
import { UiIcon } from './Icons';
import { Pagination } from './Pagination';
import { LightboxDialog } from './dialogs/LightboxDialog';

const PAGE_BYTES = 4096;
const IMAGE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tif', 'tiff', 'ico']);

function isLikelyImagePath(path: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  return IMAGE_EXTENSIONS.has(ext);
}

interface PreviewPaneProps {
  entry: EntryView | null;
  /** 可选覆盖空态主文案（如“没有匹配项”、“请选择目录中的文件”） */
  emptyMessage?: string;
  /** 初始强制显示模式（内容搜索双击命中定位十六进制弹窗使用） */
  initialTab?: 'primary' | 'hex';
  /** 初始目标页号（0-based，用于搜索命中定位） */
  initialPage?: number;
  /** 高亮并滚动至目标十六进制行号（0..255） */
  highlightHexRow?: number | null;
}

const HexBytesLine: React.FC<{ bytesHex: string }> = React.memo(({ bytesHex }) => {
  const tokens = bytesHex.split(' ');
  return (
    <>
      {tokens.map((tok, i) => (
        <React.Fragment key={i}>
          {i > 0 ? ' ' : ''}
          {tok === '00' ? <span className="td-hex-null">00</span> : tok}
        </React.Fragment>
      ))}
    </>
  );
});

const HexCharsLine: React.FC<{ chars: string }> = React.memo(({ chars }) => {
  if (!chars.includes('·')) {
    return <>{chars}</>;
  }
  // 将连续的 '·' 与普通字符分段着色，保留原生复杂文字整形
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
});

export const PreviewPane: React.FC<PreviewPaneProps> = ({
  entry,
  emptyMessage = '请选择文件',
  initialTab = 'primary',
  initialPage = 0,
  highlightHexRow = null,
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

  const reqSeqRef = useRef(0);
  const imageCheckedEntryRef = useRef<string | null>(null);
  const activeEntryIdRef = useRef<string | null>(null);
  const hexRowRefs = useRef<Record<number, HTMLDivElement | null>>({});

  const canPreview = Boolean(
    entry && !entry.directory && !entry.mode.toLowerCase().startsWith('v/')
  );

  const loadPage = useCallback(
    async (targetEntry: EntryView, targetPage: number, targetEncoding: PreviewEncoding, checkImage: boolean) => {
      if (targetEntry.size === 0) {
        setPageData(null);
        setLoading(false);
        setIsImageMode(false);
        return;
      }
      const seq = ++reqSeqRef.current;
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
        setPageData(res);
        setLoading(false);

        if (checkImage) {
          imageCheckedEntryRef.current = targetEntry.entryId;
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
        setErrorMsg(`读取失败：${formatError(err)}`);
      }
    },
    []
  );

  // 统一响应文件切换、翻页与编码切换，避免切文件时发送旧页号或漏检图片
  useEffect(() => {
    if (!entry || !canPreview) {
      activeEntryIdRef.current = null;
      imageCheckedEntryRef.current = null;
      setPageData(null);
      setImageData(null);
      setErrorMsg(null);
      setIsImageMode(false);
      setSelectedHexIdx(null);
      return;
    }

    const entryChanged = activeEntryIdRef.current !== entry.entryId;
    if (entryChanged) {
      activeEntryIdRef.current = entry.entryId;
      imageCheckedEntryRef.current = null;
      setPage(initialPage);
      setPageData(null);
      setErrorMsg(null);
      setImageData(null);
      setSelectedHexIdx(highlightHexRow);
      setActiveTab(initialTab);
      const likelyImg = entry.size > 0 && initialTab !== 'hex' && isLikelyImagePath(entry.path);
      setIsImageMode(likelyImg);
      const shouldCheckImage = initialTab !== 'hex';
      void loadPage(entry, initialPage, encoding, shouldCheckImage);
      return;
    }

    const shouldCheckImage = initialTab !== 'hex' && imageCheckedEntryRef.current !== entry.entryId;
    void loadPage(entry, page, encoding, shouldCheckImage);
  }, [entry?.entryId, canPreview, page, encoding, initialPage, initialTab, highlightHexRow, loadPage]);

  // 自动滚动至高亮十六进制行
  useEffect(() => {
    if (activeTab === 'hex' && highlightHexRow != null && pageData && page === initialPage) {
      setSelectedHexIdx(highlightHexRow);
      const node = hexRowRefs.current[highlightHexRow];
      if (node) {
        node.scrollIntoView({ block: 'center' });
      }
    }
  }, [activeTab, highlightHexRow, pageData, page, initialPage]);

  if (!entry || !canPreview) {
    return (
      <div className="td-preview-empty">
        <UiIcon name="document_preview" size={32} color="var(--text-disabled)" />
        <div className="td-preview-empty-title">
          {entry && (entry.directory || entry.mode.toLowerCase().startsWith('v/'))
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

  const hexRows: HexRowDto[] = pageData?.hexRows ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
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
                const selected = selectedHexIdx === idx;
                return (
                  <div
                    key={row.offsetHex}
                    ref={(el) => {
                      hexRowRefs.current[idx] = el;
                    }}
                    className={`td-hex-row ${selected ? 'td-hex-row--selected' : ''}`}
                    onClick={() => setSelectedHexIdx(idx)}
                  >
                    <div className="td-hex-offset">{row.offsetHex}</div>
                    <div className="td-hex-bytes">
                      <HexBytesLine bytesHex={row.bytesHex} />
                    </div>
                    <div className="td-hex-chars">
                      <HexCharsLine chars={row.chars} />
                    </div>
                  </div>
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
