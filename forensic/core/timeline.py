"""按数字时间戳排序，仅为正在查看的事件构造显示记录。"""
from array import array
from collections.abc import Sequence
from functools import lru_cache

from .formatting import display_time
from ..engines.tsk import entry_status


FIELDS = (('mtime', 'M 内容修改'), ('atime', 'A 访问'), ('ctime', 'C 元数据变更'), ('crtime', 'B 创建'))


@lru_cache(maxsize=4096)
def timestamp(value):
    return display_time(value)


class TimelineEvents(Sequence):
    def __init__(self, entries):
        self.entries = entries
        positions = [i * 4 + j for i, entry in enumerate(entries)
                     for j, (field, _) in enumerate(FIELDS) if entry[field] > 0]
        positions.sort(key=lambda pos: entries[pos // 4][FIELDS[pos % 4][0]])
        self.positions = array('Q', positions)

    def __len__(self):
        return len(self.positions)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        pos = self.positions[index]
        entry = self.entries[pos // 4]
        field, label = FIELDS[pos % 4]
        return dict(time=timestamp(entry[field]), event=label, path=entry['path'],
                    inode=entry['inode'], offset=entry['offset'], status=entry_status(entry))

    def matching(self, query):
        hits = array('Q')
        for i, event in enumerate(self):
            text = ' '.join(str(v) for v in event.values()).casefold()
            if query in text or query in event['time'].replace('T', ' ').casefold():
                hits.append(i)
        return hits
