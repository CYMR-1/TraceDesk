"""把 FAT12/16/32 的根目录、未分配簇与未关联的已分配簇列为只读区域。"""
import mmap
import os
import re
import struct


def fat_regions(image, offset, fsstat, entries):
    match = re.search(r'^File System Type: FAT(12|16|32)\s*$', fsstat, re.M)
    if not match:
        return []
    bits = int(match[1])
    base = offset * 512
    with open(image, 'rb') as source:
        source.seek(base)
        boot = source.read(512)
        if len(boot) != 512:
            raise ValueError('无法完整读取 FAT 引导扇区')
        sector, per_cluster, reserved, copies, root_items, total = struct.unpack_from('<HBHBHH', boot, 11)
        fat_sectors = struct.unpack_from('<H', boot, 22)[0] or struct.unpack_from('<I', boot, 36)[0]
        total = total or struct.unpack_from('<I', boot, 32)[0]
        if sector not in (512, 1024, 2048, 4096) or per_cluster not in (1, 2, 4, 8, 16, 32, 64, 128):
            raise ValueError('FAT 扇区或簇大小无效')
        root_sectors = (root_items * 32 + sector - 1) // sector
        directory_sector = reserved + copies * fat_sectors
        data_sector = directory_sector + root_sectors
        clusters = (total - data_sector) // per_cluster
        table_length = ((clusters + 2) * bits + 7) // 8
        if (clusters <= 0 or not reserved or not copies or table_length > fat_sectors * sector
                or base + total * sector > os.fstat(source.fileno()).st_size):
            raise ValueError('FAT 布局超出镜像或分配表边界')

        table_start = base + reserved * sector
        if bits == 32:
            flags = struct.unpack_from('<H', boot, 40)[0]
            if flags & 0x80:
                active = flags & 0x0f
                if active >= copies:
                    raise ValueError('FAT 活动分配表编号无效')
                table_start += active * fat_sectors * sector
        delta = table_start % mmap.ALLOCATIONGRANULARITY
        with mmap.mmap(source.fileno(), delta + table_length, access=mmap.ACCESS_READ,
                       offset=table_start - delta) as table:
            def next_cluster(cluster):
                if bits == 32:
                    return struct.unpack_from('<I', table, delta + 4 * cluster)[0] & 0x0fffffff
                if bits == 16:
                    return struct.unpack_from('<H', table, delta + 2 * cluster)[0]
                value = struct.unpack_from('<H', table, delta + cluster * 3 // 2)[0]
                return (value >> 4 if cluster % 2 else value) & 0xfff

            # 每个可达簇只遍历一次，交叉链或环形链也会终止。
            owned = bytearray((clusters + 9) // 8)
            def claim(cluster):
                count = 0
                while 2 <= cluster < clusters + 2:
                    byte, bit = divmod(cluster, 8)
                    if owned[byte] & (1 << bit):
                        break
                    owned[byte] |= 1 << bit
                    count += 1
                    cluster = next_cluster(cluster)
                return count

            cluster_size = per_cluster * sector
            root_size = root_sectors * sector
            if bits == 32:
                root_size = claim(struct.unpack_from('<I', boot, 44)[0]) * cluster_size

            # TSK 的 FAT inode 3 对应首个数据扇区的首个 32 字节目录项。
            for entry in entries:
                if not entry['mode'].startswith(('r/', 'd/')):
                    continue
                slot = int(entry['inode']) - 3
                if not 0 <= slot < (total - directory_sector) * sector // 32:
                    raise ValueError('FAT 目录项超出分区边界')
                source.seek(base + directory_sector * sector + slot * 32)
                record = source.read(32)
                if len(record) != 32:
                    raise ValueError('无法完整读取 FAT 目录项')
                if record[11] & 0x08:  # 卷标、长文件名记录没有文件簇链。
                    continue
                first = struct.unpack_from('<H', record, 26)[0]
                if bits == 32:
                    first |= (struct.unpack_from('<H', record, 20)[0] & 0xfff) << 16
                if entry.get('deleted'):
                    if 2 <= first < clusters + 2 and next_cluster(first) != 0:
                        entry['start_cluster_allocated'] = True
                else:
                    claim(first)

            free, idle = [], []
            reserved_value = {12: 0xff0, 16: 0xfff0, 32: 0xffffff0}[bits]
            for cluster in range(2, clusters + 2):
                value = next_cluster(cluster)
                if value == 0:
                    ranges = free
                elif (value == 1 or reserved_value <= value < reserved_value + 8
                      or owned[cluster // 8] & (1 << (cluster % 8))):
                    continue
                else:
                    ranges = idle
                start = base + data_sector * sector + (cluster - 2) * cluster_size
                if ranges and sum(ranges[-1]) == start:
                    ranges[-1][1] += cluster_size
                else:
                    ranges.append([start, cluster_size])

    common = dict(mode='v/v---------', directory=False, offset=offset, atime=0, mtime=0, ctime=0, crtime=0)
    regions = [dict(common, path='(根目录)', inode='2', size=root_size)]
    for name, ranges in [('空余空间（未分配簇）', free), ('闲置空间（已分配未关联簇）', idle)]:
        regions.append(dict(common, path=name, inode='', size=sum(size for _, size in ranges), extents=ranges))
    return regions
