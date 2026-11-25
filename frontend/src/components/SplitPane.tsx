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
  const dragCleanupRef = useRef<(() => void) | null>(null);

  // 组件卸载时确保清理正在进行的拖拽监听与动画帧
  useEffect(() => {
    return () => {
      dragCleanupRef.current?.();
      dragCleanupRef.current = null;
    };
  }, []);

  // 容器尺寸变化时：首次按比例初始化像素值，窗口缩小时动态钳制避免挤没第二面板
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const syncBounds = () => {
      const rect = el.getBoundingClientRect();
      const total = direction === 'horizontal' ? rect.width : rect.height;
      if (total <= 0) return;

      setFirstSize((prev) => {
        if (prev === null) {
          if (initialSize > 0 && initialSize <= 1) {
            const maxFirst = Math.max(minFirst, Math.round(total - minSecond - 3));
            return Math.min(maxFirst, Math.max(minFirst, Math.round(total * initialSize)));
          }
          return prev;
        }
        if (secondHidden) return prev;
        const maxFirst = Math.max(minFirst, Math.round(total - minSecond - 3));
        const clamped = Math.max(minFirst, Math.min(maxFirst, prev));
        return clamped === prev ? prev : clamped;
      });
    };

    syncBounds();
    if (typeof ResizeObserver !== 'undefined') {
      const obs = new ResizeObserver(syncBounds);
      obs.observe(el);
      return () => obs.disconnect();
    }
    window.addEventListener('resize', syncBounds);
    return () => window.removeEventListener('resize', syncBounds);
  }, [direction, initialSize, minFirst, minSecond, secondHidden]);

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

      dragCleanupRef.current?.();
      setDragging(true);

      let rafId: number | null = null;
      let latestPos = startPos;

      // 通过 requestAnimationFrame 合并高频 mousemove，降低拖拽过程中的同步重排开销
      const applySize = () => {
        rafId = null;
        const delta = latestPos - startPos;
        const maxFirst = Math.max(minFirst, total - minSecond - 3);
        const next = Math.max(minFirst, Math.min(maxFirst, Math.round(currentFirst + delta)));
        setFirstSize(next);
      };

      const handleMove = (moveEvent: MouseEvent) => {
        latestPos = direction === 'horizontal' ? moveEvent.clientX : moveEvent.clientY;
        if (rafId === null) {
          rafId = window.requestAnimationFrame(applySize);
        }
      };

      const cleanup = () => {
        if (rafId !== null) {
          window.cancelAnimationFrame(rafId);
          rafId = null;
        }
        window.removeEventListener('mousemove', handleMove);
        window.removeEventListener('mouseup', handleUp);
      };

      const handleUp = () => {
        cleanup();
        dragCleanupRef.current = null;
        setDragging(false);
      };

      dragCleanupRef.current = cleanup;
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
