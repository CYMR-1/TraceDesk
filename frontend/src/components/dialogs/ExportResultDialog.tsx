/**
 * 导出结果弹窗 (ExportResultDialog 1:1)：支持打开文件、打开所在文件夹及单文件导出后快捷记为取证发现
 */
import React, { useState } from 'react';
import { tauriApi } from '../../api/tauri';
import type { EntryView } from '../../types/ipc';
import { formatError } from '../../utils/assets';
import { UiIcon } from '../Icons';
import { Modal } from './Modal';

export interface ExportResultInfo {
  title: string;
  path: string;
  note?: string;
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
  entry,
  onRecordNote,
  noteIcon = 'note',
  onClose,
}) => {
  const [openErr, setOpenErr] = useState<string | null>(null);
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

  return (
    <Modal
      title={title}
      width={showRecordNote ? 580 : 560}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="td-btn" onClick={() => void handleOpen(false)}>
            打开文件
          </button>
          <button type="button" className="td-btn" onClick={() => void handleOpen(true)}>
            打开文件所在文件夹
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
            OK
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
            }}
          >
            {path}
          </div>
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
