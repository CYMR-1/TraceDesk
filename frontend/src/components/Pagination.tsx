/**
 * 分页器与双击页码跳转弹窗 (1:1 对齐 forensic/ui/pagination.py)
 */
import React, { useEffect, useRef, useState } from 'react';
import { Modal } from './dialogs/Modal';

interface PageJumpDialogProps {
  currentPage: number; // 从 1 开始的页码
  totalPages: number;
  onJump: (pageIndexZeroBased: number) => void;
  onClose: () => void;
}

export const PageJumpDialog: React.FC<PageJumpDialogProps> = ({
  currentPage,
  totalPages,
  onJump,
  onClose,
}) => {
  const [value, setValue] = useState(String(currentPage));
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  const parsed = Number.parseInt(value.trim(), 10);
  const valid = /^\d+$/.test(value.trim()) && parsed >= 1 && parsed <= totalPages;

  const handleConfirm = () => {
    if (!valid) return;
    onJump(parsed - 1);
    onClose();
  };

  return (
    <Modal
      title="跳转页码"
      width={340}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="td-btn" onClick={onClose}>
            取消
          </button>
          <div className="td-modal-footer-spacer" />
          <button
            type="button"
            className="td-btn td-btn--accent"
            disabled={!valid}
            onClick={handleConfirm}
          >
            确定
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <label className="td-section-title" htmlFor="td-page-jump-input">
          目标页（1–{totalPages}）
        </label>
        <input
          id="td-page-jump-input"
          ref={inputRef}
          type="number"
          min={1}
          max={totalPages}
          className="td-input td-mono"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              handleConfirm();
            }
          }}
        />
      </div>
    </Modal>
  );
};

interface PaginationProps {
  /** 从 0 开始的页码索引 */
  page: number;
  totalPages: number;
  onPageChange: (nextPageZeroBased: number) => void;
  disabled?: boolean;
  /** 自定义徽标文本（例如预览底栏含读取说明）；不传则显示 "第 X / Y 页" */
  badgeText?: string;
  /** 是否允许双击跳页（默认 totalPages > 1） */
  allowJump?: boolean;
  /** 反转顺序：徽标在左，按钮在右（用于预览底栏） */
  layout?: 'centered' | 'spread';
}

export const Pagination: React.FC<PaginationProps> = ({
  page,
  totalPages,
  onPageChange,
  disabled = false,
  badgeText,
  allowJump,
  layout = 'centered',
}) => {
  const [jumpOpen, setJumpOpen] = useState(false);
  const safeTotal = Math.max(1, totalPages);
  const safePage = Math.max(0, Math.min(page, safeTotal - 1));
  const canJump = (allowJump ?? safeTotal > 1) && safeTotal > 1 && !disabled;
  const labelText = badgeText ?? `第 ${safePage + 1} / ${safeTotal} 页`;
  const tooltip = canJump ? `${labelText} · 双击页码跳转` : labelText;

  const badge = (
    <span
      className={`td-page-badge td-mono ${canJump ? 'td-page-badge--jumpable' : ''}`}
      title={tooltip}
      onDoubleClick={() => {
        if (canJump) setJumpOpen(true);
      }}
    >
      {labelText}
    </span>
  );

  const prevBtn = (
    <button
      type="button"
      className="td-btn td-btn--pager"
      disabled={disabled || safePage <= 0}
      onClick={() => onPageChange(safePage - 1)}
    >
      上一页
    </button>
  );

  const nextBtn = (
    <button
      type="button"
      className="td-btn td-btn--pager"
      disabled={disabled || safePage + 1 >= safeTotal}
      onClick={() => onPageChange(safePage + 1)}
    >
      下一页
    </button>
  );

  return (
    <>
      {layout === 'spread' ? (
        <div style={{ display: 'flex', alignItems: 'center', width: '100%', gap: 8 }}>
          {badge}
          <div style={{ flex: 1 }} />
          {prevBtn}
          {nextBtn}
        </div>
      ) : (
        <div className="td-pagination">
          {prevBtn}
          {badge}
          {nextBtn}
        </div>
      )}
      {jumpOpen && (
        <PageJumpDialog
          currentPage={safePage + 1}
          totalPages={safeTotal}
          onJump={onPageChange}
          onClose={() => setJumpOpen(false)}
        />
      )}
    </>
  );
};
