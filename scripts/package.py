"""生成可提交源码工程包；不打包含绝对路径的运行案件与缓存。"""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parent.parent
DOC_FILES = ('README.md', '目录结构.md', '设计与验收说明.md' ,'validation/test-results.txt')
DEMO_FILES = ('demo.dd', 'demo.manifest.json', 'demo_volume.dd', 'demo_volume.manifest.json')


def package_files(root):
    """明确区分项目资料与本地证据、案件、环境及缓存。"""
    selected = [root / name for name in
                ('main.py', 'mcp_server.py', '启动取证工作台.bat', 'README.md', 'requirements.txt', '.gitignore')]
    for name in ('forensic', 'tests', 'scripts', 'tools/sleuthkit-4.15.0-win32'):
        selected.extend(sorted((root / name).rglob('*')))
    selected.extend(root / 'docs' / name for name in DOC_FILES)
    selected.extend(root / 'evidence' / name for name in DEMO_FILES)
    for path in selected:
        if (not path.is_file() or path.is_symlink() or '__pycache__' in path.parts
                or path.suffix == '.pyc' or path.name == 'latest-demo.txt'
                or path.name.casefold() in ('agent.md', 'agents.md', 'desktop.ini', 'thumbs.db')):
            continue
        yield path


def build(output=None):
    output = Path(output) if output is not None else ROOT / 'dist' / '学号_姓名_ForensicTool.zip'
    output.parent.mkdir(exist_ok=True)
    with ZipFile(output, 'w', compression=ZIP_DEFLATED) as archive:
        for path in package_files(ROOT):
            archive.write(path, Path('ForensicTool') / path.relative_to(ROOT))
        archive.writestr('ForensicTool/cases/.gitkeep', '')
    print(output)
    print(f'{output.stat().st_size:,} bytes')
    return output


if __name__ == '__main__':
    build()
