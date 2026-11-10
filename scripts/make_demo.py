"""用标准库生成确定性的 FAT16 RAW 镜像；不触碰真实磁盘。"""
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def create(path, partitioned=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sectors, fat_size, root_sectors, offset = 16384, 64, 32, 2048 if partitioned else 0
    image = bytearray((sectors + offset) * 512)
    if partitioned:
        image[446:462] = struct.pack('<B3sB3sII', 0, b'\0\2\0', 6, b'\xff\xff\xff', offset, sectors)
        image[510:512] = b'\x55\xaa'
    start = offset * 512
    boot = bytearray(512)
    boot[:3], boot[3:11] = b'\xeb\x3c\x90', b'TRACEDSK'
    struct.pack_into('<HBHBHHBHHHII', boot, 11, 512, 1, 1, 2, 512, sectors, 0xf8, fat_size, 32, 64, offset, 0)
    boot[36:39] = b'\x80\0\x29'
    struct.pack_into('<I', boot, 39, 20261107)
    boot[43:54], boot[54:62], boot[510:512] = b'TRACE DEMO ', b'FAT16   ', b'\x55\xaa'
    image[start:start+512] = boot
    fat = bytearray(fat_size * 512)
    struct.pack_into('<HH', fat, 0, 0xfff8, 0xffff)
    root = start + (1 + 2*fat_size)*512
    data = root + root_sectors * 512
    payloads = {'README.TXT': b'TraceDesk forensic demonstration.\r\nRead-only evidence workflow.\r\n',
                'NOTES.TXT': '取证演示：证据固定、审计、文件导出。\r\n'.encode('utf-8'),
                'EVENTS.CSV': b'time,event\r\n2026-09-01T08:00:00Z,login\r\n2026-09-01T08:05:00Z,copy\r\n',
                'PAYLOAD.BIN': bytes(range(256))*6}
    date, time = ((2026-1980)<<9) | (9<<5) | 1, (8<<11) | (5<<5)
    def entry(name, cluster, size, attr=0x20):
        record = bytearray(32)
        parts = name.split('.')
        record[:11] = (parts[0].ljust(8) + (parts[1] if len(parts)>1 else '').ljust(3)).encode('ascii')
        record[11] = attr
        struct.pack_into('<HHH', record, 14, time, date, date)
        struct.pack_into('<HHHI', record, 22, time, date, cluster, size)
        return record
    cluster = 2
    for i, (name, content) in enumerate(payloads.items()):
        first = cluster
        count = (len(content)+511)//512
        for n in range(count):
            struct.pack_into('<H', fat, cluster*2, cluster+1 if n<count-1 else 0xffff)
            image[data+(cluster-2)*512:data+(cluster-2)*512+len(content[n*512:(n+1)*512])] = content[n*512:(n+1)*512]
            cluster += 1
        image[root+i*32:root+(i+1)*32] = entry(name, first, len(content))
    # 增加真实子目录及其中的文件，以验证递归浏览。
    folder_cluster, child_cluster = cluster, cluster+1
    for c in (folder_cluster, child_cluster):
        struct.pack_into('<H', fat, c*2, 0xffff)
    i = len(payloads)
    image[root+i*32:root+(i+1)*32] = entry('DOCS', folder_cluster, 0, 0x10)
    pos = data+(folder_cluster-2)*512
    dot = entry('DOCS', folder_cluster, 0, 0x10)
    dot[:11] = b'.          '
    image[pos:pos+32] = dot
    dotdot = bytearray(dot)
    dotdot[:11] = b'..         '
    struct.pack_into('<H', dotdot, 26, 0)
    image[pos+32:pos+64] = dotdot
    content = b'Case note inside a nested directory.\r\n'
    image[pos+64:pos+96] = entry('CASE.TXT', child_cluster, len(content))
    image[data+(child_cluster-2)*512:data+(child_cluster-2)*512+len(content)] = content
    payloads['DOCS/CASE.TXT'] = content
    for copy in range(2):
        begin = start + (1 + copy*fat_size)*512
        image[begin:begin+len(fat)] = fat
    # 不覆盖已有镜像，防止误改正在取证的演示证据。
    with path.open('xb') as stream:
        stream.write(image)
    manifest = {name: dict(size=len(content), sha256=hashlib.sha256(content).hexdigest()) for name,content in payloads.items()}
    path.with_suffix('.manifest.json').write_text(json.dumps(dict(image_sha256=hashlib.sha256(image).hexdigest(), files=manifest), ensure_ascii=False, indent=2), encoding='utf-8')
    return manifest


if __name__ == '__main__':
    for name, partitioned in [('demo.dd',True),('demo_volume.dd',False)]:
        path = ROOT / 'evidence' / name
        if path.exists():
            print('已存在，保留：', path)
        else:
            create(path, partitioned)
            print('已生成：', path)
