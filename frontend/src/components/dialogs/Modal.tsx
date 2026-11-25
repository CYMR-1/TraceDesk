/**
 * 统一桌面弹窗底座：标题栏 (#F7FAFD)、内容区 (#FFFFFF)、底栏 (#F7FAFD，取消在左、确认主按钮在右)
 */
import React, { useEffect, useRef } from 'react';

/** 维护已挂载弹窗的打开栈，确保按 Escape 时仅关闭最顶层弹窗（避免嵌套弹窗同时关闭） */
let nextModalId = 1;
const openModalStack: number[] = [];

interface ModalProps {
  title: string;
  subtitle?: string;
  width?: number | string;
  height?: number | string;
  flushBody?: boolean;
  headerRight?: React.ReactNode;
  footer?: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
}

export const Modal: React.FC<ModalProps> = ({
  title,
  subtitle,
  width = 560,
  height,
  flushBody = false,
  headerRight,
  footer,
  onClose,
  children,
}) => {
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const id = nextModalId++;
    openModalStack.push(id);

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && openModalStack[openModalStack.length - 1] === id) {
        e.stopPropagation();
        onCloseRef.current();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      const idx = openModalStack.lastIndexOf(id);
      if (idx >= 0) {
        openModalStack.splice(idx, 1);
      }
    };
  }, []);

  return (
    <div
      className="td-modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        className="td-modal"
        style={{
          width: typeof width === 'number' ? `${width}px` : width,
          height: height ? (typeof height === 'number' ? `${height}px` : height) : undefined,
        }}
      >
        <div className="td-modal-header">
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, minWidth: 0, flex: 1 }}>
            <span className="td-modal-title">{title}</span>
            {subtitle && (
              <span className="td-muted-text" style={{ fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {subtitle}
              </span>
            )}
          </div>
          {headerRight}
          <button
            type="button"
            className="td-modal-close"
            onClick={onClose}
            title="关闭 (Esc)"
            aria-label="关闭"
          >
            ×
          </button>
        </div>

        <div className={`td-modal-body ${flushBody ? 'td-modal-body--flush' : ''}`}>
          {children}
        </div>

        {footer && <div className="td-modal-footer">{footer}</div>}
      </div>
    </div>
  );
};
