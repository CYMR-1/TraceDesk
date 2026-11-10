"""生成可提交源码工程包；不打包含绝对路径的运行案件与缓存。"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent.parent


def build():
    output = ROOT / 'dist' / '学号_姓名_ForensicTool.zip'
    output.parent.mkdir(exist_ok=True)
    selected = [ROOT / name for name in ('main.py', '启动取证工作台.bat', 'README.md',
                                         'THIRD_PARTY_NOTICES.md', 'requirements.txt', '.gitignore', 'AGENTS.md')]
    for name in ('forensic', 'tests', 'scripts', 'docs', 'evidence', 'tools/sleuthkit-4.15.0-win32'):
        selected.extend((ROOT / name).rglob('*'))
    with ZipFile(output, 'w', compression=ZIP_DEFLATED) as archive:
        for path in selected:
            if not path.is_file() or '__pycache__' in path.parts or path.suffix == '.pyc' or path.name == 'latest-demo.txt':
                continue
            archive.write(path, Path('ForensicTool') / path.relative_to(ROOT))
        archive.writestr('ForensicTool/cases/.gitkeep', '')
    print(output)
    print(f'{output.stat().st_size:,} bytes')


if __name__ == '__main__':
    build()
