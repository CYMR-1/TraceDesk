"""分段 EWF 的物理封装与解码后介质是不同的哈希对象。"""
import hashlib
import re
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .tsk import buffered_output, tsk_error


def segments(image):
    first = Path(image).resolve()
    if first.suffix.upper() != '.E01':
        raise ValueError('请选择首段 .E01')
    numbered = {}
    other_extensions = set()
    for path in first.parent.iterdir():
        if path.stem.casefold() != first.stem.casefold():
            continue
        suffix = path.suffix[1:].upper()
        if re.fullmatch(r'E[0-9]{2}', suffix):
            number = int(suffix[1:])
        elif re.fullmatch('[E-Z][A-Z]{2}', suffix):
            # .TXT 和 .LOG 等随附材料也可能同名，按 EWF1 文件头辨别。
            number = 100 + (ord(suffix[0]) - ord('E')) * 676 + (ord(suffix[1]) - 65) * 26 + ord(suffix[2]) - 65
            if not path.is_file():
                continue
            with path.open('rb') as source:
                if source.read(8) != bytes.fromhex('455646090d0aff00'):
                    other_extensions.add(number)
                    continue
        else:
            continue
        numbered[number] = path
    if not numbered or sorted(numbered) != list(range(1, len(numbered) + 1)):
        raise ValueError('E01 分段缺失或编号不连续')
    if len(numbered) + 1 in other_extensions:
        raise ValueError('EWF 字母续段文件头无效')
    return [numbered[i] for i in range(1, len(numbered) + 1)]


def snapshot(parts):
    return [(p.name, s.st_size, s.st_mtime_ns, s.st_ino) for p in parts for s in [p.stat()]]


def physical(parts, hash_file, progress=None):
    sizes = {path: path.stat().st_size for path in parts}
    total = sum(sizes.values())
    lock = threading.Lock()
    done = 0

    def hash_part(path):
        previous = 0
        def report(count, _):
            nonlocal previous, done
            with lock:
                done += count - previous
                previous = count
                progress(done, total)
        digest = hash_file(path, report if progress else None)
        return dict(name=path.name, size=sizes[path], sha256=digest)

    # 每个封装段有独立摘要；限制同时读取的段数并按原始顺序返回。
    with ThreadPoolExecutor(max_workers=min(3, len(parts))) as pool:
        return list(pool.map(hash_part, parts))


def logical(tool, image, size, progress=None):
    digest = hashlib.sha256()
    done = 0
    args = ['-i', 'ewf', image]
    with tempfile.TemporaryFile() as errors, buffered_output(tool, 'img_cat', args, errors, size) as (proc, source):
        try:
            while block := source.read(4 << 20):
                digest.update(block)
                done += len(block)
                if progress:
                    progress(done, size)
            if proc.wait() or done != size:
                errors.seek(0)
                raise OSError(f'EWF 解码失败，读取 {done}/{size} 字节：' + tsk_error(errors.read(512)))
        finally:
            proc.kill()
    return digest.hexdigest()


def acquisition_info(image):
    path = Path(image).with_suffix('.info')
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        return {}
    text = path.read_bytes().decode('utf-8', errors='replace')
    match = re.search(r'^SHA256 hash\s*:\s*([0-9a-f]{64})\b', text, re.M | re.I)
    if not match:
        return {}
    result = dict(expected_sha256=match[1].lower(), source=f'随附采集记录：{path.name}')
    version = re.search(r'^Version\s*:\s*([^\r\n]+)', text, re.M)
    started = re.search(r'^Acquisition started\s*:\s*([^\r\n(]+)', text, re.M)
    if version and 'GUYMAGER ACQUISITION INFO FILE' in text:
        result['tool'] = 'Guymager ' + version[1].strip()
    if started:
        result['acquired'] = started[1].strip() + '（按采集记录原文）'
    return result
