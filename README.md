# TraceDesk 电子数据取证工作台

依据本目录《取证软件开发的要求和评估文档》实现的中文桌面教学原型。PySide6（Qt 6）提供桌面界面，Python 标准库负责案件、SHA-256、审计和报告，The Sleuth Kit 4.15.0 负责真实 RAW 镜像解析与文件读取。取证操作在本地执行，不上传证据。

## 启动

Windows 已安装 Python 3.10+ 时，双击 **启动取证工作台.bat**。脚本会切换到项目目录，首次运行创建本目录 `.venv`，缺少 PySide6 时通过清华镜像安装 `requirements.txt` 中的依赖，再通过 `.venv\Scripts\python.exe main.py` 启动界面。首次安装依赖需要联网；依赖已安装后直接启动，不重复联网安装。保留终端窗口，运行失败时暂停以便查看错误。也可在本目录手动执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

已有虚拟环境并安装依赖后，可直接执行 `.\.venv\Scripts\python.exe main.py`。程序初始化失败和未处理的 Qt 界面回调错误会弹窗提示，并记录到 `logs/startup.log`。

当前工程已经包含官方 Windows TSK 程序和两份演示镜像，TSK 无需通过 pip 安装。若 TSK 文件丢失，运行 `powershell -File scripts/install_tsk.ps1`，或将环境变量 `TSK_BIN` 指向完整 TSK `bin` 目录。需要保留 DLL 与 licenses，不要只复制四个 exe。

界面统一使用 PySide6 原生控件，采用浅色主题，以暖米白、砂岩与棕金配色。Qt 6 自动处理高 DPI 和逻辑像素缩放；中文优先使用微软雅黑，十六进制预览使用等宽字体。文件树、预览和文本页均支持横向滚动，工具栏会随窗口宽度换行。所有 Python 第三方依赖只安装到本项目 `.venv`，使用清华镜像：

```powershell
.\.venv\Scripts\python.exe -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
```

若已有精简虚拟环境没有 pip，可先运行 `.\.venv\Scripts\python.exe -m ensurepip --upgrade`；BAT 启动器也会在依赖缺失时自动补齐 pip。

## 完整操作

1. 新建案件，填写编号、取证人员、对象，选择 `cases` 为案件库。案件目录按“案件编号-取证人员-取证对象”命名，重名时依次添加 ` (2)`、` (3)`。
2. 加载 `evidence/demo.dd`，自动固定 SHA-256 并显示 DOS 分区表。
3. 选择 2048 扇区的 FAT16 分区，点击“读取文件树”。`evidence/demo_volume.dd` 用于测试无分区表的卷镜像，偏移为 0。
4. 展开 DOCS 查看 CASE.TXT；可按 `.txt` 后缀或路径关键词筛选。界面和新生成的报告使用东八区（UTC+8），FAT 等无时区元数据按 UTC 解释，真实分析需预先核对源设备时区；未记录的时间不会显示成 1970 年。
5. 点击“校验完整性”，再选择现存或已删除的文件导出。副本以原文件名保存到案件的 `exports` 目录。遇到重名时，新副本保存在独立子目录中，仍使用原文件名。导出前后均校验原镜像，并记录副本哈希。
6. 在“审计日志”“MAC 时间线”中查看过程；点击“生成 Markdown 报告”，在案件 `reports` 中查看 `.md` 文件。
7. 重启后通过“打开案件”选择该案件 `case.json`。

“读取文件树”会刷新所选分区的清单。同名删除记录按 inode 分行显示，可按后缀或路径筛选。选中已删除文件可预览并导出镜像中仍可读的字节，支持十六进制、ASCII 和 UTF-8。预览栏会提示部分读取、inode 重分配或扫描时发现的 FAT 起始簇占用。导出记录保留目录记录大小、实际写入字节数和副本哈希；遇到短读时只保存可读部分。FAT 分区还可查看根目录数据、FAT 表、引导扇区，以及按簇计算的未分配空间和已分配但未关联的空间。

快速生成一个保留在 `cases` 的完整演示案件并打开界面：

```powershell
.\.venv\Scripts\python.exe scripts/run_demo.py --gui
```

每次运行建立新案，不清空既有数据。可重复创建测试镜像：`.\.venv\Scripts\python.exe scripts/make_demo.py`，已存在文件会保留。

## 实现与验证

- 七项基本功能均实现；自动化测试真实调用 TSK，不用模拟解析器替代。
- 扩展：审计哈希链及尾部锚点、MAC/B 时间线、路径关键词筛选、导出副本 SHA-256、导出前后原镜像校验。
- `.\.venv\Scripts\python.exe -m unittest discover -s tests -v` 运行测试；实际记录见 `docs/test-results.txt`。
- 设计、评分对应、限制与 AI 参与说明见 `docs/设计与验收说明.md`；录屏流程见 `docs/演示脚本.md`。
- 面向对象结构：`ApplicationLauncher` 管理入口和异常报告，`App` 协调操作，`WorkbenchView` / `FileBrowserView` 管理布局和文件树，`DesktopAppearance` 管理 DPI 与主题，`TaskRunner` 管理后台任务，`FilePreview` / `PreviewReader` 分离预览显示与读取，`Case` 和 `TSK` 保留原有取证业务接口。案件格式和取证流程保持不变。
- 代码入口 `main.py`；控制器 `forensic/gui.py`；视图 `forensic/workspace.py` 与 `forensic/views.py`；外观 `forensic/appearance.py`；后台任务 `forensic/tasks.py`；案件逻辑 `forensic/core.py`；TSK 适配 `forensic/tsk.py`。
- 标题栏与任务栏使用原创棕金色“证据文件＋放大镜”图标，资源位于 `forensic/assets`。修改 SVG 后，可运行 `.\.venv\Scripts\python.exe scripts/make_icon.py` 重建 PNG 和多尺寸 ICO；重启程序生效。
- `.\.venv\Scripts\python.exe scripts/package.py` 生成 `dist/学号_姓名_ForensicTool.zip`，提交前将文件名中的姓名和学号替换为本人信息。包内不含本地运行案件，解压后可重新运行演示脚本。

## 证据保护边界

源镜像只读打开；TSK 只允许 mmls、fsstat、fls、icat 四种读取命令。案件库外部镜像与案件输出分目录，拒绝加载位于整个案件库中的镜像。程序不实施硬件写阻断，也不阻止其他程序写入镜像。要求不同物理介质时，请将案件库与源镜像分别存放到不同设备。

日志不提供修改、删除入口。哈希链及本地锚点可检测日志单独修改和截断，但不能防止有写权限者同时重写日志、锚点和案件元数据。本原型不是通过 SF/T 0146-2023 认证的产品。

范围限定：一个案件固定一份非分段 RAW 镜像、512 字节扇区；分区及文件系统兼容性取决于 TSK，实际验收覆盖 FAT16；不实现 E01、无目录项的文件雕刻、硬件写保护、多用户签名或异常分区修复。分析期间应确保源镜像稳定。TSK 调用 300 秒超时，文件清单目前整体载入内存，面向课程小镜像。

## 第三方依赖与 AI 参与

The Sleuth Kit 4.15.0 Windows 官方发行包来自：
https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0-win32.zip

本次下载文件 SHA-256：`C2EBAB8105B893D97BD8CE35B88E01985E2A106EFC97F03ADF95840A631B20CE`。
此值为本工程实际下载记录，未执行独立 GPG 签名认证。安装脚本使用它检测后续下载变化。

上游源码：https://github.com/sleuthkit/sleuthkit/tree/sleuthkit-4.15.0

发行包的许可证及第三方组件许可证完整保留于 `tools/sleuthkit-4.15.0-win32/licenses/`，分发时必须一并保留。TSK 未作二进制修改；通过独立进程调用。

桌面界面使用 Qt for Python 官方 PySide6（Qt 6）及其随包依赖，由 `requirements.txt` 安装到项目 `.venv`。官方文档与许可入口：[Qt for Python](https://doc.qt.io/qtforpython-6/)、[Commercial Use](https://doc.qt.io/qtforpython-6/commercial/index.html)。上游提供 LGPLv3/GPLv3 和商业许可选项，具体组件适用许可及第三方声明以安装包所附文件为准。本工程通过 Python 导入使用，未修改 PySide6 或 Qt 二进制文件；源码工程包不包含 `.venv`，运行前需安装依赖，若另行分发运行库应一并保留其许可证和声明。

AI 使用说明：Codex 主要用于辅助代码实现与调试、界面调整、测试及技术文档整理。个人学习心得、姓名学号和对项目的理解由本人据实补充。
