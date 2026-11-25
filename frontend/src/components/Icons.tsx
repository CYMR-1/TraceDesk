/**
 * 本地高 DPI 矢量图标组件，1:1 还原 forensic/ui/icons.py 中的全部操作图标与文件类型图标。
 */
import React from 'react';
import { assetUrl } from '../utils/assets';

export type UiIconName =
  | 'search'
  | 'import_disk'
  | 'verify'
  | 'check_shield'
  | 'export'
  | 'report'
  | 'bundle'
  | 'case_new'
  | 'case_open'
  | 'mcp'
  | 'help'
  | 'warning'
  | 'folder_up'
  | 'index'
  | 'expand'
  | 'collapse'
  | 'document_preview'
  | 'copy'
  | 'lock_open'
  | 'refresh'
  | 'trash'
  | 'check_circle'
  | 'x_circle'
  | 'activity'
  | 'settings'
  | 'list'
  | 'arrow_right';

export type EntryIconKind = 'folder' | 'disk' | 'file' | 'image' | 'table' | 'system';

interface UiIconProps {
  name: UiIconName | string;
  size?: number;
  color?: string;
  fill?: string;
  className?: string;
}

export const UiIcon: React.FC<UiIconProps> = ({
  name,
  size = 14,
  color = 'currentColor',
  fill,
  className,
}) => {
  const sw = size >= 28 ? 1.35 : 1.5;
  const softFill = fill ?? (size >= 24 ? 'rgba(38, 116, 196, 0.12)' : 'none');

  const renderShape = () => {
    switch (name) {
      case 'search':
        return (
          <>
            <circle cx="7.1" cy="7.1" r="4.2" fill="none" />
            <line x1="10.2" y1="10.2" x2="13.8" y2="13.8" />
          </>
        );
      case 'import_disk':
        return (
          <>
            <rect x="2.2" y="9.6" width="11.6" height="4.2" rx="1.4" fill="none" />
            <line x1="8" y1="2.2" x2="8" y2="8" />
            <polyline points="5.4,5.6 8,8.2 10.6,5.6" fill="none" />
            <circle cx="11.4" cy="11.7" r="0.7" fill={color} stroke="none" />
          </>
        );
      case 'verify':
      case 'check_shield':
        return (
          <>
            <path
              d="M8 1.8 L13.2 3.8 L13.2 7.7 C13.2 10.9 10.9 13.0 8 14.3 C5.1 13.0 2.8 10.9 2.8 7.7 L2.8 3.8 Z"
              fill={name === 'check_shield' ? softFill : (fill ?? 'none')}
            />
            <polyline points="5.5,8.1 7.3,9.9 10.7,6.2" fill="none" />
          </>
        );
      case 'export':
        return (
          <>
            <polyline points="2.8,10.4 2.8,13.2 13.2,13.2 13.2,10.4" fill="none" />
            <line x1="8" y1="9.8" x2="8" y2="2.8" />
            <polyline points="5.2,5.5 8,2.7 10.8,5.5" fill="none" />
          </>
        );
      case 'report':
        return (
          <>
            <rect x="3.2" y="1.8" width="9.6" height="12.4" rx="1.6" fill="none" />
            <line x1="5.5" y1="5.4" x2="10.5" y2="5.4" />
            <line x1="5.5" y1="8.2" x2="10.5" y2="8.2" />
            <line x1="5.5" y1="11.0" x2="8.7" y2="11.0" />
          </>
        );
      case 'bundle':
        return (
          <>
            <rect x="2.0" y="2.6" width="12.0" height="2.8" rx="1.0" fill="none" />
            <rect x="2.8" y="5.4" width="10.4" height="8.4" rx="1.4" fill="none" />
            <line x1="6.4" y1="8.6" x2="9.6" y2="8.6" />
          </>
        );
      case 'case_new':
        return (
          <>
            <path
              d="M2.2 5.0 L2.2 3.8 Q2.2 2.8 3.2 2.8 L6.4 2.8 L7.8 4.4 L12.8 4.4 Q13.8 4.4 13.8 5.4 L13.8 12.2 Q13.8 13.2 12.8 13.2 L3.2 13.2 Q2.2 13.2 2.2 12.2 Z"
              fill="none"
            />
            <line x1="8" y1="6.8" x2="8" y2="10.8" />
            <line x1="6" y1="8.8" x2="10" y2="8.8" />
          </>
        );
      case 'case_open':
        return (
          <>
            <path
              d="M2.2 12.2 L2.2 3.8 Q2.2 2.8 3.2 2.8 L6.4 2.8 L7.8 4.4 L12.4 4.4 Q13.2 4.4 13.2 5.2 L13.2 6.8"
              fill="none"
            />
            <path d="M2.2 12.6 L4.0 7.0 L14.2 7.0 L12.4 12.6 Z" fill="none" />
          </>
        );
      case 'mcp':
        return (
          <>
            <line x1="5.5" y1="7.2" x2="10.5" y2="4.8" />
            <line x1="5.5" y1="8.8" x2="10.5" y2="11.2" />
            <circle cx="4.0" cy="8.0" r="1.8" fill="none" />
            <circle cx="12.0" cy="4.0" r="1.8" fill="none" />
            <circle cx="12.0" cy="12.0" r="1.8" fill="none" />
          </>
        );
      case 'help':
        return (
          <>
            <circle cx="8" cy="8" r="6" fill="none" />
            <path d="M6.2 6.3 C6.2 4.8 9.8 4.8 9.8 6.5 C9.8 7.7 8.0 7.9 8.0 9.2" fill="none" />
            <circle cx="8" cy="11.5" r="0.85" fill={color} stroke="none" />
          </>
        );
      case 'warning':
        return (
          <>
            <path
              d="M8 2.2 L14.0 12.8 Q14.4 13.5 13.5 13.5 L2.5 13.5 Q1.6 13.5 2.0 12.8 Z"
              fill={softFill}
            />
            <line x1="8" y1="6.0" x2="8" y2="9.4" />
            <circle cx="8" cy="11.5" r="0.85" fill={color} stroke="none" />
          </>
        );
      case 'folder_up':
        return (
          <>
            <path d="M12.6 12.4 L12.6 8.4 Q12.6 6.2 10.4 6.2 L3.8 6.2" fill="none" />
            <polyline points="6.4,3.6 3.8,6.2 6.4,8.8" fill="none" />
          </>
        );
      case 'index':
        return (
          <>
            <ellipse cx="8" cy="4.2" rx="5" ry="1.8" fill="none" />
            <path d="M3 4.2 L3 8.2 C3 10.2 13 10.2 13 8.2 L13 4.2" fill="none" />
            <path d="M3 8.2 L3 12.0 C3 14.0 13 14.0 13 12.0 L13 8.2" fill="none" />
          </>
        );
      case 'expand':
        return (
          <>
            <polyline points="4.4,6.0 8.0,2.6 11.6,6.0" fill="none" />
            <polyline points="4.4,10.0 8.0,13.4 11.6,10.0" fill="none" />
          </>
        );
      case 'collapse':
        return (
          <>
            <polyline points="4.4,3.0 8.0,6.4 11.6,3.0" fill="none" />
            <polyline points="4.4,13.0 8.0,9.6 11.6,13.0" fill="none" />
          </>
        );
      case 'document_preview':
        return (
          <>
            <path
              d="M8.2 13.4 L4.0 13.4 Q2.8 13.4 2.8 12.2 L2.8 3.2 Q2.8 2.0 4.0 2.0 L9.8 2.0 Q11.0 2.0 11.0 3.2 L11.0 6.6"
              fill="none"
            />
            <line x1="5.0" y1="5.2" x2="8.8" y2="5.2" />
            <line x1="5.0" y1="7.8" x2="7.4" y2="7.8" />
            <circle cx="10.4" cy="10.4" r="2.6" fill="none" />
            <line x1="12.3" y1="12.3" x2="14.0" y2="14.0" />
          </>
        );
      case 'copy':
        return (
          <>
            <rect x="5.6" y="5.2" width="7.6" height="8.6" rx="1.3" fill="none" />
            <path
              d="M10.4 5.2 L10.4 3.4 Q10.4 2.2 9.2 2.2 L4.0 2.2 Q2.8 2.2 2.8 3.4 L2.8 9.6 Q2.8 10.8 4.0 10.8 L5.6 10.8"
              fill="none"
            />
          </>
        );
      case 'lock_open':
        return (
          <>
            <rect x="3.2" y="7.4" width="9.6" height="6.4" rx="1.5" fill="none" />
            <path d="M5.4 7.4 L5.4 4.9 C5.4 2.2 10.2 2.0 10.7 4.5" fill="none" />
            <circle cx="8.0" cy="10.6" r="0.9" fill={color} stroke="none" />
          </>
        );
      case 'refresh':
        return (
          <>
            <path d="M13.2 8.0 A5.2 5.2 0 1 1 11.7 4.3" fill="none" />
            <polyline points="11.9,2.1 11.9,4.7 9.3,4.7" fill="none" />
          </>
        );
      case 'trash':
        return (
          <>
            <line x1="2.8" y1="4.2" x2="13.2" y2="4.2" />
            <path d="M5.8 4.2 L6.3 2.5 L9.7 2.5 L10.2 4.2" fill="none" />
            <path d="M4.2 4.2 L4.8 12.6 Q4.9 13.6 5.9 13.6 L10.1 13.6 Q11.1 13.6 11.2 12.6 L11.8 4.2" fill="none" />
            <line x1="6.8" y1="6.8" x2="6.8" y2="11.0" />
            <line x1="9.2" y1="6.8" x2="9.2" y2="11.0" />
          </>
        );
      case 'check_circle':
        return (
          <>
            <circle cx="8" cy="8" r="5.8" fill={softFill} />
            <polyline points="5.4,8.2 7.2,10.0 10.8,6.2" fill="none" />
          </>
        );
      case 'x_circle':
        return (
          <>
            <circle cx="8" cy="8" r="5.8" fill={softFill} />
            <line x1="5.8" y1="5.8" x2="10.2" y2="10.2" />
            <line x1="10.2" y1="5.8" x2="5.8" y2="10.2" />
          </>
        );
      case 'activity':
        return (
          <polyline points="1.8,8.4 4.6,8.4 6.4,3.4 9.6,12.6 11.4,8.4 14.2,8.4" fill="none" />
        );
      case 'settings':
        return (
          <>
            <circle cx="8" cy="8" r="2.2" fill="none" />
            <path
              d="M8 2.2 L8 3.6 M8 12.4 L8 13.8 M2.2 8 L3.6 8 M12.4 8 L13.8 8 M3.9 3.9 L4.9 4.9 M11.1 11.1 L12.1 12.1 M12.1 3.9 L11.1 4.9 M4.9 11.1 L3.9 12.1"
              fill="none"
            />
          </>
        );
      case 'list':
        return (
          <>
            <circle cx="3.2" cy="4.4" r="0.8" fill={color} stroke="none" />
            <line x1="5.6" y1="4.4" x2="13.2" y2="4.4" />
            <circle cx="3.2" cy="8.0" r="0.8" fill={color} stroke="none" />
            <line x1="5.6" y1="8.0" x2="13.2" y2="8.0" />
            <circle cx="3.2" cy="11.6" r="0.8" fill={color} stroke="none" />
            <line x1="5.6" y1="11.6" x2="13.2" y2="11.6" />
          </>
        );
      case 'arrow_right':
        return (
          <>
            <line x1="3.0" y1="8.0" x2="12.6" y2="8.0" />
            <polyline points="9.2,4.6 12.8,8.0 9.2,11.4" fill="none" />
          </>
        );
      default:
        return <circle cx="8" cy="8" r="4" fill="none" />;
    }
  };

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      stroke={color}
      strokeWidth={sw}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={{ flexShrink: 0, display: 'inline-block', verticalAlign: 'middle' }}
      aria-hidden="true"
    >
      {renderShape()}
    </svg>
  );
};

const OUTLINE_PALETTE: Record<EntryIconKind, [string, string]> = {
  folder: ['#B4781E', '#FEF5E2'],
  disk: ['#2674C4', '#EAF4FF'],
  file: ['#4A6682', '#F2F6FA'],
  image: ['#B4466B', '#FDF0F5'],
  table: ['#1F7A4D', '#ECF9F2'],
  system: ['#6447B3', '#F4F0FD'],
};

export const EntryIcon: React.FC<{ kind: EntryIconKind; size?: number }> = ({ kind, size = 16 }) => {
  const [stroke, fill] = OUTLINE_PALETTE[kind] || OUTLINE_PALETTE.file;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      stroke={stroke}
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ flexShrink: 0, display: 'inline-block' }}
      aria-hidden="true"
    >
      {kind === 'folder' && (
        <>
          <path
            d="M3.5 9.5 L3.5 6.8 Q3.5 4.8 5.5 4.8 L12.2 4.8 L15.2 8.0 L26.5 8.0 Q28.5 8.0 28.5 10.0 L28.5 24.8 Q28.5 26.8 26.5 26.8 L5.5 26.8 Q3.5 26.8 3.5 24.8 Z"
            fill={fill}
          />
          <line x1="4.2" y1="11.4" x2="27.8" y2="11.4" />
        </>
      )}
      {kind === 'disk' && (
        <>
          <rect x="3.5" y="5.5" width="25" height="21" rx="3.6" fill={fill} />
          <line x1="4.2" y1="19.6" x2="27.8" y2="19.6" />
          <path d="M10.4 13.8 A4.8 4.4 0 0 1 17.8 11.2" fill="none" />
          <circle cx="23.5" cy="23.0" r="1.2" fill={stroke} stroke="none" />
          <circle cx="19.6" cy="23.0" r="1.2" fill={stroke} stroke="none" />
        </>
      )}
      {kind === 'image' && (
        <>
          <rect x="4.5" y="5.5" width="23" height="21" rx="3.2" fill={fill} />
          <circle cx="10.8" cy="11.2" r="2.1" fill="none" />
          <polyline points="6.8,23.2 12.6,16.6 16.6,20.4 20.6,15.2 25.2,23.2" fill="none" />
        </>
      )}
      {kind === 'table' && (
        <>
          <rect x="4.5" y="5.5" width="23" height="21" rx="3.2" fill={fill} />
          <line x1="5.0" y1="11.2" x2="27.0" y2="11.2" />
          <line x1="5.0" y1="16.4" x2="27.0" y2="16.4" />
          <line x1="5.0" y1="21.6" x2="27.0" y2="21.6" />
          <line x1="12.5" y1="11.2" x2="12.5" y2="26.0" />
        </>
      )}
      {kind === 'system' && (
        <>
          <rect x="6.2" y="3.6" width="19.6" height="24.8" rx="3.0" fill={fill} />
          <circle cx="16" cy="16" r="3.8" fill="none" />
          <line x1="16" y1="10.4" x2="16" y2="12.2" />
          <line x1="16" y1="19.8" x2="16" y2="21.6" />
          <line x1="10.4" y1="16" x2="12.2" y2="16" />
          <line x1="19.8" y1="16" x2="21.6" y2="16" />
          <circle cx="16" cy="16" r="1.2" fill={stroke} stroke="none" />
        </>
      )}
      {kind === 'file' && (
        <>
          <path
            d="M6.5 3.8 L19.5 3.8 L25.5 9.8 L25.5 26.2 Q25.5 28.2 23.5 28.2 L8.5 28.2 Q6.5 28.2 6.5 26.2 Z"
            fill={fill}
          />
          <polyline points="19.2,4.0 19.2,10.0 25.2,10.0" fill="none" />
          <line x1="10.5" y1="14.5" x2="21.5" y2="14.5" />
          <line x1="10.5" y1="19.0" x2="21.5" y2="19.0" />
          <line x1="10.5" y1="23.5" x2="17.5" y2="23.5" />
        </>
      )}
    </svg>
  );
};

export function inferEntryIconKind(entry: { directory?: boolean; mode?: string; path?: string; iconKind?: EntryIconKind }): EntryIconKind {
  if (entry.iconKind) return entry.iconKind;
  if (entry.directory) return 'folder';
  if ((entry.mode || '').toLowerCase().startsWith('v/')) return 'system';
  const ext = (entry.path || '').split('.').pop()?.toLowerCase() || '';
  if (['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tif', 'tiff', 'svg', 'ico'].includes(ext)) {
    return 'image';
  }
  if (['csv', 'tsv', 'xls', 'xlsx', 'ods'].includes(ext)) {
    return 'table';
  }
  return 'file';
}

export const BrandLogo: React.FC<{ size?: number; className?: string }> = ({ size = 28, className }) => (
  <img
    src={assetUrl('assets/tracedesk.svg')}
    alt="TraceDesk"
    width={size}
    height={size}
    className={className}
    draggable={false}
  />
);
