"""在测试目录生成含相同路径、不同内容的多分区镜像。"""
import struct
import tempfile
from pathlib import Path

from scripts.make_demo import create


def create_multi_partition_image(path, *, unreadable=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=path.parent) as folder:
        volume_path = Path(folder) / 'volume.dd'
        create(volume_path, False)
        volume = volume_path.read_bytes()
    offsets = [2048, 20480]
    sectors = len(volume) // 512
    size = (38912 + 2048) if unreadable else offsets[-1] + sectors
    image = bytearray(size * 512)
    image[510:512] = b'\x55\xaa'
    expected = {}
    for index, offset in enumerate(offsets):
        data = bytearray(volume)
        struct.pack_into('<I', data, 28, offset)
        # 两个卷的 README 路径和 inode 相同，用不同内容验证分区定位。
        if index:
            start = (1 + 2 * 64 + 32) * 512
            data[start:start + 9] = b'SECOND FS'
        image[offset * 512:(offset + sectors) * 512] = data
        image[446 + index * 16:462 + index * 16] = struct.pack(
            '<B3sB3sII', 0, b'\0\2\0', 6, b'\xff\xff\xff', offset, sectors)
        start = (1 + 2 * 64 + 32) * 512
        expected[offset] = bytes(data[start:start + 65])
    if unreadable:
        image[478:494] = struct.pack('<B3sB3sII', 0, b'\0\2\0', 0x83, b'\xff\xff\xff', 38912, 2048)
    with path.open('xb') as stream:
        stream.write(image)
    return expected
