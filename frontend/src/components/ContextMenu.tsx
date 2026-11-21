/**
 * 桌面风格右键菜单 / 悬浮菜单，自动避让视口边界并响应 Esc/外部点击关闭。
 */
import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';

export interface ContextMenuItem {
  key: string;
  label: string;
  disabled?: boolean;
  separator?: boolean;
  onClick?: () => void;
}

interface ContextMenuProps {
  x: number;
  y: number;
  items: ContextMenuItem[];
  onClose: () => void;
}

export const ContextMenu: React.FC<ContextMenuProps> = ({ x, y, items, onClose }) => {
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y });

  useLayoutEffect(() => {
    const el = menuRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const maxLeft = Math.max(8, window.innerWidth - rect.width - 8);
    const maxTop = Math.max(8, window.innerHeight - rect.height - 8);
    setPos({
      left: Math.min(x, maxLeft),
      top: Math.min(y, maxTop),
    });
  }, [x, y]);

  useEffect(() => {
    const handleMouseDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('mousedown', handleMouseDown, true);
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('blur', onClose);
    return () => {
      window.removeEventListener('mousedown', handleMouseDown, true);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('blur', onClose);
    };
  }, [onClose]);

  if (items.length === 0) return null;

  return (
    <div
      ref={menuRef}
      className="td-menu"
      style={{ left: pos.left, top: pos.top }}
      role="menu"
    >
      {items.map((item) =>
        item.separator ? (
          <div key={item.key} className="td-menu-sep" />
        ) : (
          <button
            key={item.key}
            type="button"
            className="td-menu-item"
            disabled={item.disabled}
            role="menuitem"
            onClick={() => {
              onClose();
              item.onClick?.();
            }}
          >
            {item.label}
          </button>
        )
      )}
    </div>
  );
};
