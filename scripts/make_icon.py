"""将原创 SVG 渲染为 PNG 和多尺寸 Windows ICO；仅使用项目 PySide6。"""
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# 离屏渲染无需启动桌面窗口，也适用于自动构建环境。
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ASSETS = ROOT / 'forensic' / 'assets'
SIZES = (16, 20, 24, 32, 48, 64, 128, 256)


def render_png(renderer, size):
    """每个尺寸直接从矢量渲染，保留透明圆角和清晰边缘。"""
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(0)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buffer, 'PNG'):
        raise OSError(f'无法生成 {size} 像素图标')
    buffer.close()
    return bytes(data)


def write_ico(path, frames):
    """ICO 图像目录指向各尺寸的 PNG 数据；256 在目录中编码为 0。"""
    offset = 6 + 16 * len(frames)
    directory = bytearray(struct.pack('<HHH', 0, 1, len(frames)))
    payload = bytearray()
    for size, png in frames:
        dimension = 0 if size == 256 else size
        directory.extend(struct.pack('<BBBBHHII', dimension, dimension, 0, 0,
                                     1, 32, len(png), offset))
        payload.extend(png)
        offset += len(png)
    path.write_bytes(directory + payload)


def build():
    # 持有 QGuiApplication，确保平台和图像插件在整个渲染期间有效。
    app = QGuiApplication.instance() or QGuiApplication([])
    renderer = QSvgRenderer(str(ASSETS / 'tracedesk.svg'))
    if not renderer.isValid():
        raise ValueError('图标 SVG 无法解析')
    frames = [(size, render_png(renderer, size)) for size in SIZES]
    ASSETS.mkdir(parents=True, exist_ok=True)
    write_ico(ASSETS / 'tracedesk.ico', frames)
    (ASSETS / 'tracedesk.png').write_bytes(frames[-1][1])
    for name in ('tracedesk.ico', 'tracedesk.png'):
        output = ASSETS / name
        print(f'{output}: {output.stat().st_size:,} bytes')
    return app


if __name__ == '__main__':
    build()
