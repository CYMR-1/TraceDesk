"""只处理清单数据，允许在后台构建；目录查询不再遍历整案。"""
def prepare(entries):
    ordered = sorted(entries, key=lambda e: (e['offset'], e['path'].count('/'), e['mode'].lower().startswith('v/'),
                     not e['directory'], e['path'], e.get('deleted', False)))
    branches, children, by_id = {}, {}, {}
    directories = {(r['offset'], r['path'].strip('/')) for r in ordered if r['directory']}
    for row in ordered:
        offset, path = row['offset'], row['path'].strip('/')
        by_id[id(row)] = row
        parent = path.rpartition('/')[0]
        children.setdefault((offset, parent), []).append(row)
        branches.setdefault((offset, parent), []).append((path, row))
        while parent and (offset, parent) not in directories:
            directories.add((offset, parent))
            ancestor = parent.rpartition('/')[0]
            branches.setdefault((offset, ancestor), []).append((parent, None))
            parent = ancestor
    return ordered, branches, children, by_id
