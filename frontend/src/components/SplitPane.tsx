/**
 * 可拖拽分隔面板（水平 / 垂直），支持最小尺寸约束与双面板平滑缩放。
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';

interface SplitPaneProps {
  direction: 'horizontal' | 'vertical';
  /** 首面板初始尺寸（px）或比例（当 initialSize <= 1 时按百分比处理） */
  initialSize: number;
  minFirst?: number;
  minSecond?: number;
  first: React.ReactNode;
  second: React.ReactNode;
  /** 隐藏第二面板（例如详情区未展开时） */
  secondHidden?: boolean;
  className?: string;
}

export const SplitPane: React.FC<SplitPaneProps> = ({
  direction,
  initialSize,
  minFirst = 120,
  minSecond = 120,
  first,
  second,
  secondHidden = false,
  className = '',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [firstSize, setFirstSize] = useState<number | null>(initialSize > 1 ? initialSize : null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    if (firstSize === null && initialSize > 0 && initialSize <= 1 && containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      const total = direction === 'horizontal' ? rect.width : rect.height;
      if (total > 0) {
        setFirstSize(Math.max(minFirst, Math.round(total * initialSize)));
      }
    }
  }, [direction, firstSize, initialSize, minFirst]);

  const onMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      const container = containerRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const total = direction === 'horizontal' ? rect.width : rect.height;
      const startPos = direction === 'horizontal' ? e.clientX : e.clientY;
      const currentFirst =
        firstSize ?? Math.round(total * (initialSize <= 1 ? initialSize : 0.5));

      setDragging(true);

      const handleMove = (moveEvent: MouseEvent) => {
        const delta = (direction === 'horizontal' ? moveEvent.clientX : moveEvent.clientY) - startPos;
        const maxFirst = Math.max(minFirst, total - minSecond - 3);
        const next = Math.max(minFirst, Math.min(maxFirst, currentFirst + delta));
        setFirstSize(next);
      };

      const handleUp = () => {
        setDragging(false);
        window.removeEventListener('mousemove', handleMove);
        window.removeEventListener('mouseup', handleUp);
      };

      window.addEventListener('mousemove', handleMove);
      window.addEventListener('mouseup', handleUp);
    },
    [direction, firstSize, initialSize, minFirst, minSecond]
  );

  const firstStyle: React.CSSProperties = secondHidden
    ? { flex: 1 }
    : firstSize !== null
      ? {
          flexBasis: `${firstSize}px`,
          flexGrow: 0,
          flexShrink: 0,
        }
      : {
          flex: initialSize <= 1 ? `${initialSize} 1 0%` : `0 0 ${initialSize}px`,
        };

  return (
    <div
      ref={containerRef}
      className={`td-split td-split--${direction} ${className}`}
    >
      <div className="td-split-pane" style={firstStyle}>
        {first}
      </div>
      {!secondHidden && (
        <>
          <div
            className={`td-split-handle td-split-handle--${direction} ${dragging ? 'td-split-handle--dragging' : ''}`}
            onMouseDown={onMouseDown}
            role="separator"
            aria-orientation={direction === 'horizontal' ? 'vertical' : 'horizontal'}
          />
          <div className="td-split-pane" style={{ flex: 1 }}>
            {second}
          </div>
        </>
      )}
    </div>
  );
};
