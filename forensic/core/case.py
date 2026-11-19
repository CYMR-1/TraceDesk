"""案件隔离、证据固定、追加审计与报告。所有证据文件均以 rb 打开。"""
import msvcrt
import tempfile
import hashlib
import gzip
import json
import os
import re
import threading
import uuid
from itertools import count
from pathlib import Path
from .formatting import EAST_8, now, display_time, deleted_export_summary
from .reporting import render_report
from .coverage import assess, SOURCE_FIELDS
from ..engines.fat import fat_regions
from ..engines import ewf
from ..engines.tsk import TSK, can_export, entry_name, entry_status


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def save_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def sha256(path, progress=None):
    """固定 1 MiB 缓冲区，检查读取期间的文件身份和元数据变化。"""
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        before = os.fstat(source.fileno())
        done = 0
        while block := source.read(1024 * 1024):
            digest.update(block)
            done += len(block)
            if progress:
                progress(done, before.st_size)
        after = os.fstat(source.fileno())
    fields = ('st_size', 'st_mtime_ns', 'st_ino', 'st_dev')
    current = Path(path).stat()
    if any(getattr(before, f) != getattr(snapshot, f) for snapshot in (after, current) for f in fields):
        raise RuntimeError('哈希计算期间证据发生变化，请停止分析')
    return digest.hexdigest()


def within(path, parent):
    return Path(path).resolve().is_relative_to(Path(parent).resolve())


def windows_filename(name, max_units=255):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    device = name.partition('.')[0].rstrip(' ').upper()
    if re.fullmatch(r'CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9¹²³]', device):
        name = '_' + name
    # Windows 的单个文件名最多有 255 个 UTF-16 码元。
    name = name.encode('utf-16-le')[:2 * max_units].decode('utf-16-le', errors='ignore')
    return name.rstrip(' .') or 'file'


def export_filename(source_path):
    return windows_filename(source_path.rsplit('/', 1)[-1])


def case_folder_name(*fields):
    parts = [field.strip() for field in fields]
    name = '-'.join(parts)
    if len(name.encode('utf-16-le')) > 510:
        # 超长时为三个字段分别分配空间，每段最多 84 个 UTF-16 码元。
        name = '-'.join(p.encode('utf-16-le')[:168].decode('utf-16-le', 'ignore') for p in parts)
    return windows_filename(name)


class Case:
    def __init__(self, folder, actor=None):
        self.folder = Path(folder).resolve()
        metadata = self.folder / 'case.json'
        if not metadata.is_file():
            raise ValueError('缺少案件元数据 case.json')
        self._lease = (self.folder / 'case.lock').open('a+b')
        try:
            self._lease.seek(0)
            msvcrt.locking(self._lease.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            self.close()
            raise RuntimeError('案件已被占用或无法加锁') from error
        try:
            self.data = json.loads(metadata.read_text(encoding='utf-8'))
            self._index = self.data.pop('inventory_file', None)
            if self._index is not None:
                if not re.fullmatch(r'inventory-[0-9a-f]{32}\.jsonl\.gz', self._index):
                    raise ValueError('清单文件名无效')
                with gzip.open(self.folder / self._index, 'rt', encoding='utf-8') as stream:
                    self.data['inventory'] = [json.loads(line) for line in stream]
                if len(self.data['inventory']) != self.data.pop('inventory_count'):
                    raise ValueError('案件清单数量不匹配')
            for key in ('id', 'examiner', 'number', 'target', 'created'):
                if not isinstance(self.data[key], str) or not self.data[key].strip():
                    raise ValueError(key)
            if not all(isinstance(self.data[k], list) for k in ('inventory', 'exports')):
                raise ValueError('案件清单格式错误')
            evidence = self.data['evidence']
            if evidence is not None:
                if not all(k in evidence for k in ('path','sha256','layout','partitions','fixed_at','size')):
                    raise ValueError('证据信息不完整')
            if not all((self.folder / k).is_dir() for k in ('reports','exports')):
                raise ValueError('案件输出目录缺失')
            self.actor = actor or self.data['examiner']
            self.lock = threading.RLock()
            self.check_audit()
            if not self._index and self.data['inventory']:
                self.save(inventory=self.data['inventory'])
        except (KeyError, TypeError, ValueError) as error:
            self.close()
            raise ValueError(f'案件数据损坏：{error}') from error
        except Exception:
            self.close()
            raise

    def close(self):
        self._lease.close()

    @classmethod
    def create(cls, root, number, examiner, target, *, folder_name=None):
        fields = (number, examiner, target)
        if not all(isinstance(field, str) and field.strip() for field in fields):
            raise ValueError('案件编号、取证人员和取证对象不能为空')
        root = Path(root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        name = folder_name if folder_name is not None else case_folder_name(*fields)
        if not name or name != windows_filename(name):
            raise ValueError('案件文件夹名称含有无效字符')
        for index in count(1):
            suffix = '' if index == 1 else f' ({index})'
            folder = root / (windows_filename(name, 255 - len(suffix)) + suffix)
            try:
                folder.mkdir()
                break
            except FileExistsError:
                continue
        (folder / 'exports').mkdir()
        (folder / 'reports').mkdir()
        save_json(folder / 'case.json', dict(id=uuid.uuid4().hex, number=number, examiner=examiner,
                  target=target, created=now(), evidence=None, inventory=[], exports=[]))
        (folder / 'audit.jsonl').touch()
        case = cls(folder)
        case.log('CASE_CREATE', number, '成功')
        return case

    def save(self, **changes):
        if self._lease.closed:
            raise RuntimeError('案件已关闭')
        candidate = {**self.data, **changes}
        previous = self._index
        index = previous
        metadata = dict(candidate)
        if 'inventory' in changes and candidate['inventory']:
            index = f'inventory-{uuid.uuid4().hex}.jsonl.gz'
            try:
                with gzip.open(self.folder / index, 'xt', encoding='utf-8', compresslevel=1, newline='\n') as stream:
                    for entry in candidate['inventory']:
                        stream.write(canonical(entry) + '\n')
            except BaseException:
                (self.folder / index).unlink(missing_ok=True)
                raise
        if not candidate['inventory']:
            index = None
        if index:
            metadata['inventory_file'] = index
            metadata['inventory_count'] = len(metadata.pop('inventory'))
        try:
            save_json(self.folder / 'case.json', metadata)
        except BaseException:
            if index and index != previous:
                (self.folder / index).unlink(missing_ok=True)
            raise
        self._index = index
        self.data = candidate
        if previous and previous != index:
            try:
                (self.folder / previous).unlink()
            except OSError:
                pass

    def check_audit(self):
        previous = '0' * 64
        records = []
        for index, line in enumerate((self.folder / 'audit.jsonl').read_text(encoding='utf-8').splitlines(), 1):
            record = json.loads(line)
            signature = record.pop('hash')
            if record['seq'] != index or record['previous'] != previous or hashlib.sha256(canonical(record).encode()).hexdigest() != signature:
                raise RuntimeError(f'审计链第 {index} 条记录不完整或被修改')
            record['hash'] = signature
            previous = signature
            records.append(record)
        # 尾部锚点可发现直接截断日志；不能抵抗有权限者同时重写日志和锚点。
        anchor = self.folder / 'audit.head'
        if anchor.exists() and anchor.read_text().strip() != previous:
            raise RuntimeError('审计日志尾部锚点不匹配，可能被截断')
        if records and not anchor.exists():
            raise RuntimeError('审计尾部锚点缺失')
        return records

    def log(self, action, subject, result, **details):
        if self._lease.closed:
            raise RuntimeError('案件已关闭')
        with self.lock:
            records = self.check_audit()
            record = dict(seq=len(records)+1, timestamp=now(), actor=self.actor, action=action,
                          subject=str(subject), result=result, details=details,
                          previous=records[-1]['hash'] if records else '0'*64)
            record['hash'] = hashlib.sha256(canonical(record).encode()).hexdigest()
            # 日志只有追加入口，落盘后更新锚点。异常断电产生不一致时失败关闭。
            with (self.folder / 'audit.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(canonical(record)+'\n')
                stream.flush()
                os.fsync(stream.fileno())
            (self.folder / 'audit.head').write_text(record['hash'], encoding='ascii')

    def load(self, image, tsk=None, progress=None):
        if self.data['evidence']:
            raise ValueError('本原型每案固定一个镜像；请新建案件分析其他镜像')
        image = Path(image).resolve(strict=True)
        # 镜像必须位于整个案件库之外，防止落入当前案件或其他案件的输出目录。
        if not image.is_file() or within(image, self.folder.parent):
            raise ValueError('镜像必须是案件库目录之外的普通文件')
        self.log('IMAGE_LOAD_BEGIN', image, '开始')
        try:
            tsk = tsk or TSK()
            is_ewf = image.suffix.casefold() == '.e01'
            if re.fullmatch(r'\.e\d\d', image.suffix, re.I) and not is_ewf:
                raise ValueError('请从首段 E01 打开')
            extra = {}
            size = image.stat().st_size
            boot_reader = None
            if is_ewf:
                parts = ewf.segments(image)
                stamp = ewf.snapshot(parts)
                info = tsk.text('img_stat', ['-i','ewf',image])
                length = re.search(r'Size of data in bytes:\s*(\d+)', info)
                sector = re.search(r'Sector size:\s*(\d+)', info)
                if not length or not sector or int(sector[1]) != 512:
                    raise ValueError('无法确定受支持的 EWF 逻辑大小或扇区大小')
                size = int(length[1])
                baseline = ewf.logical(tsk, image, size, progress)
                extra = dict(format='EWF', segments=ewf.physical(parts, sha256, progress),
                             provenance=ewf.acquisition_info(image))
                def boot_reader(offset):
                    result = tsk.run('img_cat', ['-i','ewf','-s',offset,'-e',offset,image], capture_output=True)
                    return result.stdout if result.returncode == 0 else b''
            else:
                baseline = sha256(image, progress)
            self.log('HASH_FIXED', image, '成功', sha256=baseline)
            layout, partitions = tsk.inspect(image)
            evidence = dict(path=str(image), size=size, sha256=baseline,
                            fixed_at=now(), partitions=partitions, layout=layout, **extra)
            evidence['coverage'] = assess(image, partitions, layout, logical_size=size, boot_reader=boot_reader)
            if is_ewf and ewf.snapshot(ewf.segments(image)) != stamp:
                raise ValueError('分析期间 EWF 分段发生变化')
            self.save(evidence=evidence)
            self.log('IMAGE_LOAD', image, '成功', sha256=baseline, partitions=partitions)
        except Exception as error:
            self.log('IMAGE_LOAD', image, '失败', error=str(error))
            raise

    def image(self):
        if not self.data['evidence']:
            raise ValueError('请先加载镜像')
        return self.data['evidence']['path']

    def register_source(self, values):
        self.image()
        source = {key: values.get(key, '').strip() for key in SOURCE_FIELDS}
        if source['expected_sha256'] and not re.fullmatch('[0-9a-fA-F]{64}', source['expected_sha256']):
            raise ValueError('交付方 SHA-256 应为 64 位十六进制字符')
        self.log('SOURCE_REGISTER', self.image(), '登记', **source)
        self.save(evidence={**self.data['evidence'], 'provenance': source})

    def verify(self, progress=None):
        try:
            evidence = self.data['evidence']
            if evidence.get('format') == 'EWF':
                parts = ewf.segments(self.image())
                before = ewf.snapshot(parts)
                ok = (ewf.physical(parts, sha256, progress) == evidence['segments']
                      and before == ewf.snapshot(ewf.segments(self.image())))
                method = '逐段复算封装 SHA-256，与首次逻辑流校验时的全部分段比对'
                actual = evidence['sha256'] if ok else None
            else:
                actual = sha256(self.image(), progress)
                ok = actual == evidence['sha256']
                method = '复算 RAW SHA-256'
            changes = {}
            if ok and not evidence.get('coverage'):
                changes['evidence'] = {**evidence, 'coverage': assess(self.image(), evidence['partitions'], evidence['layout'])}
            self.save(verification=dict(time=now(), actual=actual, ok=ok, method=method), **changes)
            self.log('HASH_VERIFY', self.image(), '通过' if ok else '不匹配', actual=actual, method=method)
            return ok
        except Exception as error:
            self.log('HASH_VERIFY', self.data.get('evidence'), '失败', error=str(error))
            raise

    def scan(self, offset, tsk=None):
        allowed = [p['offset'] for p in self.data['evidence']['partitions']] if self.data['evidence'] else []
        if offset not in allowed:
            raise ValueError('请选择已识别分区')
        try:
            if not self.verify():
                raise RuntimeError('镜像校验失败，禁止扫描')
            tool = tsk or TSK()
            info, entries = self._read_partition(tool, offset)
            if not self.verify():
                raise RuntimeError('扫描期间镜像变化，文件清单未保存')
            self.save(inventory=entries, fsstat=info, offset=offset,
                      partition_scans=[dict(offset=offset, status='ready', count=len(entries))])
            self.log('FILE_BROWSE', f'{self.image()}@{offset}', '成功', count=len(entries))
            return entries
        except Exception as error:
            self.log('FILE_BROWSE', str(offset), '失败', error=str(error))
            raise

    def _read_partition(self, tool, offset):
        info = tool.text('fsstat', ['-i', 'raw', '-o', offset, self.image()])
        entries = tool.files(self.image(), offset)
        match = re.search(r'^File System Type:\s*(\S+)', info, re.M)
        for entry in entries:
            entry['filesystem'] = match[1] if match else ''
        try:
            if self.data['evidence'].get('format') != 'EWF':
                entries.extend(fat_regions(self.image(), offset, info, entries))
        except (ValueError, OSError, OverflowError) as error:
            info += f'\nFAT 空间区域未能映射：{error}'
        return info, entries

    def needs_partition_scan(self):
        evidence = self.data['evidence']
        if not evidence:
            return False
        expected = {p['offset'] for p in evidence['partitions']}
        scanned = {p['offset'] for p in self.data.get('partition_scans', [])}
        return expected != scanned

    def scan_all(self, tsk=None, progress=None):
        """汇总全部分区；单个分区不可读时保留失败状态，不影响其他分区。"""
        image = self.image()
        def verify_stage(label):
            return self.verify((lambda done, total: progress(label, done, total)) if progress else None)
        try:
            if not verify_stage('扫描前校验'):
                raise RuntimeError('镜像校验失败，禁止扫描')
            tool = tsk or TSK()
            inventory, scans, sections = [], [], []
            for partition in self.data['evidence']['partitions']:
                offset = partition['offset']
                if progress:
                    progress(f'扫描分区（偏移 {offset} 扇区）', 0, 0)
                try:
                    info, entries = self._read_partition(tool, offset)
                except (RuntimeError, OSError, ValueError, OverflowError) as error:
                    scans.append(dict(offset=offset, status='error', count=0, error=str(error)))
                    info = f'无法读取此分区：{error}'
                    self.log('FILE_BROWSE', f'{image}@{offset}', '失败', error=str(error))
                else:
                    inventory.extend(entries)
                    scans.append(dict(offset=offset, status='ready', count=len(entries)))
                    self.log('FILE_BROWSE', f'{image}@{offset}', '成功', count=len(entries))
                sections.append(f'分区偏移 {offset} 扇区 · {partition["description"]}\n{info}')
            if not verify_stage('扫描后校验'):
                raise RuntimeError('扫描期间镜像变化，文件清单未保存')
            if progress:
                progress('保存文件清单', 0, 0)
            self.save(inventory=inventory, partition_scans=scans, offset=None,
                      fsstat='\n\n'.join(sections))
            failed = sum(p['status'] == 'error' for p in scans)
            self.log('PARTITIONS_SCAN', image, '部分分区不可读' if failed else '成功',
                     partitions=len(scans), failed=failed, count=len(inventory))
            return inventory
        except Exception as error:
            self.log('PARTITIONS_SCAN', image, '失败', error=str(error))
            raise

    def filtered(self, suffix='', keyword=''):
        suffix = suffix.strip().lower()
        if suffix and not suffix.startswith('.'):
            suffix = '.' + suffix
        items = [f for f in self.data['inventory'] if (not suffix or f['path'].lower().endswith(suffix))
                 and (keyword.lower() in f['path'].lower() or keyword.lower() in entry_name(f).lower())]
        self.log('FILE_FILTER', suffix or '*', '成功', keyword=keyword, count=len(items))
        return items

    def export(self, entry, tsk=None):
        with self.lock:
            return self._export(entry, tsk)

    def _export(self, entry, tsk):
        if entry not in self.data['inventory'] or not can_export(entry):
            raise ValueError('请选择当前文件清单中的普通文件或已删除文件')
        name = export_filename(entry['path'])
        folder = self.folder / 'exports'
        destination = folder / name
        duplicate_folder = None
        committed = False
        published = False
        try:
            if not self.verify():
                raise RuntimeError('原始镜像完整性校验失败，禁止导出')
            with tempfile.TemporaryDirectory(dir=folder) as staging:
                partial = Path(staging) / 'copy'
                tool = tsk or TSK()
                deleted = entry.get('deleted', False)
                read_note = ''
                if deleted:
                    read_note = tool.export_deleted(self.image(), entry, partial)
                else:
                    tool.export(self.image(), entry['offset'], entry['inode'], partial)
                size = partial.stat().st_size
                if not deleted and size != entry['size']:
                    raise RuntimeError('导出大小与文件元数据不一致')
                digest = sha256(partial)
                if not self.verify():
                    raise RuntimeError('导出期间原始镜像变化，副本不可采信')
                try:
                    partial.rename(destination)  # Windows 原子重命名，目标已存在时失败。
                except FileExistsError:
                    duplicate_folder = Path(tempfile.mkdtemp(prefix='同名副本-', dir=folder))
                    destination = duplicate_folder / name
                    partial.rename(destination)
                published = True
            record = dict(path=str(destination), source=entry['path'], inode=entry['inode'],
                          offset=entry['offset'], sha256=digest, size=size, time=now())
            if deleted:
                record.update(deleted=True, recorded_size=entry['size'], read_note=read_note,
                              reallocated=entry.get('reallocated', False),
                              start_cluster_allocated=entry.get('start_cluster_allocated', False))
            self.save(exports=[*self.data['exports'], record])
            committed = True
            self.log('FILE_EXPORT', entry['path'], '部分导出' if size < entry['size'] else '成功', **record)
            return destination
        except Exception as error:
            if published and not committed:
                destination.unlink(missing_ok=True)
            if duplicate_folder is not None and not committed:
                duplicate_folder.rmdir()
            self.log('FILE_EXPORT', entry['path'], '失败', error=str(error), inode=entry['inode'],
                     offset=entry['offset'], deleted=entry.get('deleted', False))
            raise

    def timeline_events(self):
        events = []
        for entry in self.data['inventory']:
            for field, label in [('mtime','M 内容修改'), ('atime','A 访问'), ('ctime','C 元数据变更'), ('crtime','B 创建')]:
                if entry[field] > 0:
                    events.append(dict(time=display_time(entry[field]),
                                       event=label, path=entry['path'], inode=entry['inode'],
                                       offset=entry['offset'], status=entry_status(entry)))
        return sorted(events, key=lambda row: row['time'])

    def timeline(self):
        events = self.timeline_events()
        self.log('TIMELINE', self.image(), '成功', count=len(events))
        return events

    def report(self):
        try:
            return self._write_report()
        except Exception as error:
            self.log('REPORT_GENERATE', 'Markdown', '失败', error=str(error))
            raise

    def _write_report(self):
        if not self.verify():
            conclusion = '不通过：镜像当前 SHA-256 与固定值不一致。'
        else:
            conclusion = ('通过：每个 EWF 分段摘要均与首次解码固定时一致。' if self.data['evidence'].get('format') == 'EWF'
                          else '通过：本次报告生成时镜像 SHA-256 与初始固定值一致。')
        self.log('REPORT_GENERATE', 'Markdown', '开始')
        records = self.check_audit()
        content = render_report(self.data, records, conclusion)
        destination = self.folder / 'reports' / ('report_' + uuid.uuid4().hex[:12] + '.md')
        destination.write_text(content, encoding='utf-8')
        self.log('REPORT_GENERATE', destination, '成功', sha256=sha256(destination))
        return destination
