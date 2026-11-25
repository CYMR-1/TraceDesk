/**
 * 内容搜索命中双击十六进制精准定位弹窗：
 * 自动跳转至 pos // 4096 页并高亮 pos % 4096 // 16 行。
 */
import React from 'react';
import type { EntryView, SearchHitDto } from '../../types/ipc';
import { PreviewPane } from '../PreviewPane';
import { Modal } from './Modal';

const PAGE_BYTES = 4096;

interface HexHitPreviewDialogProps {
  hit: SearchHitDto;
  encoding: string;
  needleHex: string;
  onClose: () => void;
}

export const HexHitPreviewDialog: React.FC<HexHitPreviewDialogProps> = ({
  hit,
  encoding,
  needleHex,
  onClose,
}) => {
  const targetPage = Math.floor(hit.pos / PAGE_BYTES);
  const targetRow = Math.floor((hit.pos % PAGE_BYTES) / 16);

  const syntheticEntry: EntryView = {
    entryId: hit.entryId,
    name: hit.path.split('/').pop() || hit.path,
    path: hit.path,
    status: hit.deleted ? '已删除' : '现存',
    size: Math.max(hit.pos + 16, PAGE_BYTES),
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
      width={880}
      height={560}
      flushBody
      onClose={onClose}
    >
      <div className="td-panel-sub-bar td-mono" style={{ fontSize: 12, color: 'var(--text-secondary)', userSelect: 'text' }}>
        文件内偏移 {hit.pos}（0x{hit.pos.toString(16).toUpperCase()}） · {encoding} · {needleHex.slice(0, 96)}
      </div>
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        <PreviewPane
          entry={syntheticEntry}
          initialTab="hex"
          initialPage={targetPage}
          highlightHexRow={targetRow}
        />
      </div>
    </Modal>
  );
};
