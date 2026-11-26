/**
 * 导出结果弹窗 (ExportResultDialog 1:1)：支持打开文件、打开所在目录、复制路径、SHA-256/大小展示及单文件导出后快捷记为取证发现
 */
import React, { useState } from 'react';
import { tauriApi } from '../../api/tauri';
import type { EntryView } from '../../types/ipc';
import { copyToClipboard, formatBytes, formatError } from '../../utils/assets';
import { UiIcon } from '../Icons';
import { Modal } from './Modal';

export interface ExportResultInfo {
  title: string;
  path: string;
  note?: string;
  /** 可选输出文件 SHA-256 摘要（如 HTML 报告生成结果） */
  sha256?: string;
  /** 可选输出文件字节大小 */
  bytes?: number;
  /** 可选生成时间（UTC+8） */
  generatedAt?: string;
  /** 单文件导出时附带原镜像条目，供弹窗快捷打开“记录取证发现” */
  entry?: EntryView;
}

interface ExportResultDialogProps extends ExportResultInfo {
  /** 导出单文件后快捷记为取证发现（传入时显示快捷按钮） */
  onRecordNote?: (entry: EntryView) => void;
  /** 可选覆盖图标名称，默认使用 note */
  noteIcon?: string;
  onClose: () => void;
}

export const ExportResultDialog: React.FC<ExportResultDialogProps> = ({
  title,
  path,
  note,
  sha256,
  bytes,
  generatedAt,
  entry,
  onRecordNote,
  noteIcon = 'note',
  onClose,
}) => {
  const [openErr, setOpenErr] = useState<string | null>(null);
  const [copiedPath, setCopiedPath] = useState(false);
  const [copiedSha, setCopiedSha] = useState(false);
  const isPartial = title === '部分导出';
  const showRecordNote = Boolean(entry && onRecordNote);

  const handleOpen = async (revealFolder: boolean) => {
    setOpenErr(null);
    try {
      const res = await tauriApi.openInOs({ path, revealFolder });
      if (!res.ok) {
        setOpenErr(`系统未能打开此${revealFolder ? '文件夹' : '文件'}：${path}`);
      }
    } catch (err) {
      setOpenErr(`无法打开：${formatError(err)}`);
    }
  };

  const handleCopyPath = async () => {
    const ok = await copyToClipboard(path);
    if (ok) {
      setCopiedPath(true);
      window.setTimeout(() => setCopiedPath(false), 1800);
    }
  };

  const handleCopySha = async () => {
    if (!sha256) return;
    const ok = await copyToClipboard(sha256);
    if (ok) {
      setCopiedSha(true);
      window.setTimeout(() => setCopiedSha(false), 1800);
    }
  };

  return (
    <Modal
      title={title}
      width={showRecordNote || sha256 ? 620 : 560}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="td-btn" onClick={() => void handleCopyPath()}>
            <UiIcon name={copiedPath ? 'check_circle' : 'copy'} size={13} color={copiedPath ? 'var(--ok-fg)' : 'var(--text-secondary)'} />
            {copiedPath ? '已复制路径' : '复制路径'}
          </button>
          <button type="button" className="td-btn" onClick={() => void handleOpen(false)}>
            打开文件
          </button>
          <button type="button" className="td-btn" onClick={() => void handleOpen(true)}>
            打开所在目录
          </button>
          <div className="td-modal-footer-spacer" />
          {entry && onRecordNote && (
            <button
              type="button"
              className="td-btn td-btn--soft"
              onClick={() => onRecordNote(entry)}
            >
              <UiIcon name={noteIcon} size={14} color="var(--accent-soft-text)" />
              记为取证发现
            </button>
          )}
          <button
            type="button"
            className="td-btn td-btn--accent"
            style={{ minWidth: 64 }}
            onClick={onClose}
            autoFocus
          >
            确定
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        <UiIcon
          name={isPartial ? 'warning' : 'check_shield'}
          size={36}
          color={isPartial ? 'var(--warn-fg)' : 'var(--ok-fg)'}
          fill={isPartial ? 'var(--warn-bg)' : 'var(--ok-bg)'}
        />
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>{title}</div>
          <div
            className="td-mono"
            style={{
              fontSize: 12,
              color: 'var(--text-primary)',
              wordBreak: 'break-all',
              userSelect: 'text',
              padding: '6px 9px',
              background: 'var(--chrome-bg)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 5,
            }}
          >
            {path}
          </div>
          {(sha256 || bytes !== undefined || generatedAt) && (
            <div className="td-export-meta-box">
              {sha256 && (
                <div className="td-export-meta-row">
                  <span className="td-export-meta-key">SHA-256</span>
                  <span className="td-export-meta-val td-mono">{sha256}</span>
                  <button
                    type="button"
                    className="td-btn td-btn--compact"
                    onClick={() => void handleCopySha()}
                  >
                    {copiedSha ? '已复制' : '复制'}
                  </button>
                </div>
              )}
              {bytes !== undefined && (
                <div className="td-export-meta-row">
                  <span className="td-export-meta-key">文件大小</span>
                  <span className="td-export-meta-val td-mono">
                    {formatBytes(bytes)} 字节
                    {bytes >= 1024 ? `（${(bytes / 1024).toFixed(1)} KiB）` : ''}
                  </span>
                </div>
              )}
              {generatedAt && (
                <div className="td-export-meta-row">
                  <span className="td-export-meta-key">生成时间</span>
                  <span className="td-export-meta-val td-mono">{generatedAt}</span>
                </div>
              )}
            </div>
          )}
          {note && (
            <div
              style={{
                fontSize: 12.5,
                color: 'var(--text-secondary)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                userSelect: 'text',
              }}
            >
              {note}
            </div>
          )}
          {openErr && <div className="td-banner td-banner--warning">{openErr}</div>}
        </div>
      </div>
    </Modal>
  );
};
