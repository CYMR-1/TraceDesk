"""普通文件按逻辑偏移读取，NTFS 属性类型和 ID 沿用 fls 清单。"""
from pathlib import Path
import re

import pyewf
import pytsk3

from .ewf import segments


class EwfImage(pytsk3.Img_Info):
    def __init__(self, path):
        self.media = pyewf.handle()
        self.media.open([str(p) for p in segments(path)])
        try:
            super().__init__('', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
        except BaseException:
            self.media.close()
            raise

    def get_size(self):
        return self.media.get_media_size()

    def read(self, offset, size):
        return self.media.read_buffer_at_offset(size, offset)


class VolumeReader:
    """一个读取线程独占一个镜像句柄，跨文件复用当前文件系统解析结果。"""
    def __init__(self, path):
        self.image = (EwfImage(path) if Path(path).suffix.lower() == '.e01'
                      else pytsk3.Img_Info(str(path), type=pytsk3.TSK_IMG_TYPE_RAW))
        self.offset = self.fs = None

    def close(self):
        self.fs = None
        self.image.close()
        if isinstance(self.image, EwfImage):
            self.image.media.close()

    def open_entry(self, entry):
        if entry.get('deleted') or not entry['mode'].startswith('r/'):
            raise ValueError('此记录需要 icat 恢复读取')
        match = re.fullmatch(r'(\d+)(?:-(\d+)-(\d+))?', str(entry['inode']))
        if not match:
            raise ValueError('无法定位文件属性')
        if self.offset != entry['offset']:
            self.fs = pytsk3.FS_Info(self.image, offset=entry['offset'] * 512)
            self.offset = entry['offset']
        file = self.fs.open_meta(inode=int(match[1]))
        attr = (int(match[2]), int(match[3])) if match[2] else ()
        if attr:
            size = next((a.info.size for a in file if (a.info.type, a.info.id) == attr), None)
        else:
            size = file.info.meta.size
        if size != entry['size']:
            raise ValueError('文件或属性长度与清单不符')

        def read_at(offset, length):
            if not length:
                return b''
            block = file.read_random(offset, length, *attr)
            if len(block) != length:
                raise OSError('原始文件内容短读')
            return block
        return read_at
