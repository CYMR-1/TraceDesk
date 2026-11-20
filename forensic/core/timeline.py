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
        self._options_cache = None

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

    def filter_options(self):
        """返回 (事件选项, 状态选项, 分区偏移选项)，供时间线表头下拉筛选使用。"""
        if self._options_cache is None:
            events_seen = set()
            statuses = set()
            offsets = set()
            for entry in self.entries:
                has_time = False
                for field, label in FIELDS:
                    if entry[field] > 0:
                        events_seen.add(label)
                        has_time = True
                if has_time:
                    statuses.add(entry_status(entry))
                    offsets.add(entry['offset'])
            events = [label for _, label in FIELDS if label in events_seen]
            self._options_cache = (events, sorted(statuses), [str(o) for o in sorted(offsets)])
        return self._options_cache

    def matching(self, query='', filters=None):
        query = (query or '').strip().casefold()
        filters = filters or {}
        event_filter = filters.get(2)
        status_filter = filters.get(3)
        offset_filter = int(filters[4]) if filters.get(4) is not None else None
        hits = array('Q')
        entries = self.entries
        for index, pos in enumerate(self.positions):
            entry = entries[pos // 4]
            if offset_filter is not None and entry['offset'] != offset_filter:
                continue
            field, label = FIELDS[pos % 4]
            if event_filter is not None and label != event_filter:
                continue
            status = entry_status(entry)
            if status_filter is not None and status != status_filter:
                continue
            if query:
                formatted = timestamp(entry[field])
                if (query not in entry['path'].casefold()
                        and query not in str(entry['inode']).casefold()
                        and query not in str(entry['offset'])
                        and query not in label.casefold()
                        and query not in status.casefold()
                        and query not in formatted.casefold()
                        and query not in formatted.replace('T', ' ').casefold()):
                    continue
            hits.append(index)
        return hits
