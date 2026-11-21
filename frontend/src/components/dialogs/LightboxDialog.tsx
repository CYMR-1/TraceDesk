/**
 * 高清图片放大查看器 Lightbox（支持适应窗口 / 原始尺寸 100% 切换与分辨率显示）
 */
import React, { useState } from 'react';
import { Modal } from './Modal';

interface LightboxDialogProps {
  title: string;
  caption?: string;
  src: string;
  onClose: () => void;
}

export const LightboxDialog: React.FC<LightboxDialogProps> = ({ title, caption, src, onClose }) => {
  const [fitMode, setFitMode] = useState(true);
  const [naturalSize, setNaturalSize] = useState<{ w: number; h: number } | null>(null);

  const cleanCaption = (caption || title).replace('（点击查看大图）', '').trim();

  return (
    <Modal
      title={cleanCaption}
      width="88vw"
      height="86vh"
      flushBody
      onClose={onClose}
      headerRight={
        <button
          type="button"
          className="td-btn td-btn--soft"
          onClick={() => setFitMode((prev) => !prev)}
        >
          {fitMode ? '原始尺寸 (100%)' : '适应窗口'}
        </button>
      }
      footer={
        <>
          <span className="td-muted-text" style={{ fontSize: 12 }}>
            {naturalSize ? `原始分辨率：${naturalSize.w} × ${naturalSize.h} px` : '正在载入图片…'}
          </span>
          <div className="td-modal-footer-spacer" />
          <button type="button" className="td-btn td-btn--accent" onClick={onClose}>
            关闭
          </button>
        </>
      }
    >
      <div className={`td-lightbox-scroll ${fitMode ? '' : 'td-lightbox-scroll--full'}`}>
        <img
          src={src}
          alt={cleanCaption}
          className={fitMode ? 'td-lightbox-img--fit' : 'td-lightbox-img--full'}
          onLoad={(e) =>
            setNaturalSize({
              w: e.currentTarget.naturalWidth,
              h: e.currentTarget.naturalHeight,
            })
          }
        />
      </div>
    </Modal>
  );
};
