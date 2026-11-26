/**
 * 内容搜索命中双击十六进制精准定位弹窗：
 * - 自动跳转至 pos // 4096 页，精确高亮命中的字节范围（HEX 双字节格 + 右侧 ASCII 字符同步高亮）
 * - 支持一键「定位原文件」跳转至文件浏览并自动打开 HEX 视图定位该字节
 */
import React from 'react';
import type { EntryView, LocateEntryRequest, SearchHitDto } from '../../types/ipc';
import { UiIcon } from '../Icons';
import { PreviewPane } from '../PreviewPane';
import { Modal } from './Modal';

const PAGE_BYTES = 4096;

interface HexHitPreviewDialogProps {
  hit: SearchHitDto;
  encoding: string;
  needleHex: string;
  /** 精确高亮字节长度（默认根据 needleHex 推算） */
  highlightLength?: number;
  /** 跨模块一键跳转定位原文件回调 */
  onLocateEntry?: (req: LocateEntryRequest) => void;
  onClose: () => void;
}

/** 根据 needleHex 推算命中的精确字节长度 */
function inferHighlightLength(needleHex: string, explicitLength?: number): number {
  if (explicitLength && explicitLength > 0) {
    return explicitLength;
  }
  const cleanHex = needleHex.replace(/\s+/g, '');
  if (cleanHex.length >= 2 && cleanHex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleanHex)) {
    return cleanHex.length / 2;
  }
  return 1;
}

export const HexHitPreviewDialog: React.FC<HexHitPreviewDialogProps> = ({
  hit,
  encoding,
  needleHex,
  highlightLength,
  onLocateEntry,
  onClose,
}) => {
  const targetPage = Math.floor(hit.pos / PAGE_BYTES);
  const targetRow = Math.floor((hit.pos % PAGE_BYTES) / 16);
  const byteLen = inferHighlightLength(needleHex, highlightLength);

  const syntheticEntry: EntryView = {
    entryId: hit.entryId,
    name: hit.path.split('/').pop() || hit.path,
    path: hit.path,
    status: hit.deleted ? '已删除' : '现存',
    size: Math.max(hit.pos + byteLen + 16, PAGE_BYTES),
    inode: hit.inode,
    mtime: '—',
    atime: '—',
    ctime: '—',
    crtime: '—',
    offset: hit.offset,
    directory: false,
    deleted: Boolean(hit.deleted),
    mode: 'r/rrwxrwxrwx',
  };

  return (
    <Modal
      title={`${hit.path} · 命中字节 0x${hit.pos.toString(16).toUpperCase()}`}
      width={900}
      height={580}
      flushBody
      headerRight={
        onLocateEntry ? (
          <button
            type="button"
            className="td-btn td-btn--soft td-btn--compact"
            title="跳转到「文件浏览」定位原文件并自动高亮当前命中字节"
            onClick={() => {
              onClose();
              onLocateEntry({
                entryId: hit.entryId,
                offset: hit.offset,
                inode: hit.inode,
                path: hit.path,
                deleted: Boolean(hit.deleted),
                byteOffset: hit.pos,
                highlightLength: byteLen,
              });
            }}
          >
            <UiIcon name="locate" size={13} color="var(--accent-soft-text)" />
            定位原文件
          </button>
        ) : undefined
      }
      onClose={onClose}
    >
      <div className="td-panel-sub-bar td-mono" style={{ fontSize: 12, color: 'var(--text-secondary)', userSelect: 'text' }}>
        文件内偏移 {hit.pos}（0x{hit.pos.toString(16).toUpperCase()}） · 长度 {byteLen} 字节 · {encoding} · {needleHex.slice(0, 96)}
      </div>
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        <PreviewPane
          entry={syntheticEntry}
          initialTab="hex"
          initialPage={targetPage}
          highlightHexRow={targetRow}
          highlightByteStart={hit.pos}
          highlightByteLength={byteLen}
          showMagicMeta={false}
        />
      </div>
    </Modal>
  );
};
