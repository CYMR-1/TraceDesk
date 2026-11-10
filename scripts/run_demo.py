"""运行真实取证闭环并保留教学案件；--gui 直接展示生成的案件。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from forensic.core import Case
from scripts.make_demo import create


def run():
    image = ROOT / 'evidence' / 'demo.dd'
    if not image.exists():
        create(image)
    case = Case.create(ROOT / 'cases', 'DEMO-2026-001', '演示取证人员', '自建 FAT16 测试镜像')
    case.load(image)
    entries = case.scan(2048)
    assert case.verify(), '原镜像哈希不一致'
    entry = next(e for e in entries if e['path'] == 'DOCS/CASE.TXT')
    exported = case.export(entry)
    case.timeline()
    report = case.report()
    print('案件：', case.folder)
    print('导出：', exported)
    print('报告：', report)
    (ROOT / 'docs' / 'latest-demo.txt').write_text(str(case.folder), encoding='utf-8')
    return case


if __name__ == '__main__':
    case = run()
    if '--gui' in sys.argv:
        from forensic.gui import main
        main(case)
    case.close()
