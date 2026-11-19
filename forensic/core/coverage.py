"""依据镜像内的声明判断覆盖范围；不把长度或摘要当作原盘采集证明。"""
import re
import struct
from pathlib import Path


def assess(image, partitions, layout='', *, logical_size=None, boot_reader=None):
    size = Path(image).stat().st_size if logical_size is None else logical_size
    ends = {int(start): (int(end) + 1) * 512 for start, end in re.findall(
        r'^\s*\d+:\s+\d+(?::\d+)?\s+(\d+)\s+(\d+)\s+\d+', layout, re.M)}
    rows = []
    with open(image, 'rb') as source:
        for part in partitions:
            offset = part['offset']
            start = offset * 512
            if boot_reader:
                boot = boot_reader(offset) if start < size else b''
            else:
                source.seek(start)
                boot = source.read(512)
            volume_end = None
            kind = '未知'
            if len(boot) == 512 and boot[510:] == b'\x55\xaa':
                sector = struct.unpack_from('<H', boot, 11)[0]
                sectors = 0
                if boot[3:11] == b'NTFS    ':
                    kind = 'NTFS'
                    sectors = struct.unpack_from('<Q', boot, 40)[0]
                elif boot[54:62] in (b'FAT12   ', b'FAT16   ') or boot[82:90] == b'FAT32   ':
                    kind = 'FAT'
                    sectors = struct.unpack_from('<H', boot, 19)[0] or struct.unpack_from('<I', boot, 32)[0]
                if sectors and sector in (512, 1024, 2048, 4096):
                    volume_end = start + sectors * sector
            end = ends.get(offset)
            declared = max(end or 0, volume_end or 0)
            if start >= size or declared > size:
                status = '声明范围超出镜像'
            elif end and volume_end and volume_end > end:
                status = '卷声明超出分区边界'
            elif volume_end:
                status = '声明范围已覆盖'
            else:
                status = '无法判定卷范围'
            rows.append(dict(offset=offset, filesystem=kind, partition_end=end, volume_end=volume_end,
                             missing_bytes=max(0, declared - size), status=status))
    return dict(bytes=size, volumes=rows)


def coverage_text(result):
    if not result:
        return '尚未评估；请运行完整性校验'
    return '；'.join(f"偏移 {r['offset']} 扇区：{r['status']}（{r['filesystem']}，声明结束字节位置 "
                    f"{max(r['volume_end'] or 0, r['partition_end'] or 0) or '未知'}，镜像 {result['bytes']} 字节）"
                    for r in result['volumes']) + '。仅判断可识别的声明范围，不能证明原盘无坏扇区或已完整采集。'


SOURCE_FIELDS = {'evidence_id': '证据编号', 'source': '来源 / 交付方', 'acquired': '采集时间与时区',
                 'tool': '采集工具与版本', 'expected_sha256': '交付方 SHA-256'}


def source_status(evidence):
    expected = evidence.get('provenance', {}).get('expected_sha256')
    if not evidence.get('sha256'):
        return '本机整镜像 SHA-256 待固定'
    if not expected:
        return '未提供交付方摘要，仅有本机固定值'
    return '交付方摘要与本机固定值一致' if expected.lower() == evidence['sha256'].lower() else '警告：交付方摘要与本机固定值不一致'
