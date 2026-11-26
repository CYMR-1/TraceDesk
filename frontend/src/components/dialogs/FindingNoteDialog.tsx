/**
 * 添加取证笔记弹窗 (NoteDialog 1:1)
 */
import React, { useState } from 'react';
import { tauriApi } from '../../api/tauri';
import type { CaseSnapshot, EntryView } from '../../types/ipc';
import { formatError } from '../../utils/assets';
import { Modal } from './Modal';

interface FindingNoteDialogProps {
  entry: EntryView;
  /** 可选预填取证分析笔记（例如从魔数伪装检测告警一键带入） */
  initialNote?: string;
  onSaved: (snapshot: CaseSnapshot) => void;
  onClose: () => void;
}

export const FindingNoteDialog: React.FC<FindingNoteDialogProps> = ({
  entry,
  initialNote = '',
  onSaved,
  onClose,
}) => {
  const [note, setNote] = useState(initialNote);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    const trimmed = note.trim();
    if (!trimmed) {
      setError('请输入取证笔记内容。');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const res = await tauriApi.recordFindingNote({
        entryId: entry.entryId,
        note: trimmed,
      });
      onSaved(res.snapshot);
      onClose();
    } catch (err) {
      setError(`保存取证记录失败：${formatError(err)}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleSafeClose = () => {
    if (!submitting) {
      onClose();
    }
  };

  return (
    <Modal
      title="记录取证发现"
      subtitle={`分区偏移 ${entry.offset} · inode ${entry.inode}`}
      width={540}
      onClose={handleSafeClose}
      footer={
        <>
          <button type="button" className="td-btn" disabled={submitting} onClick={handleSafeClose}>
            取消
          </button>
          <div className="td-modal-footer-spacer" />
          <button
            type="button"
            className="td-btn td-btn--accent"
            disabled={submitting || !note.trim()}
            onClick={() => void handleSave()}
          >
            {submitting ? '正在写入审计链…' : '保存'}
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div className="td-mono" style={{ fontSize: 12, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
          {entry.path}
        </div>
        <textarea
          className="td-textarea"
          rows={6}
          placeholder="输入取证观察说明、关键线索或复核结论（将绑定镜像 SHA-256 写入审计链）"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          autoFocus
        />
        {error && <div className="td-banner td-banner--error">{error}</div>}
      </div>
    </Modal>
  );
};
