# 第三方依赖与 AI 参与

The Sleuth Kit 4.15.0 Windows 官方发行包来自：
https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0-win32.zip

本次下载文件 SHA-256：`C2EBAB8105B893D97BD8CE35B88E01985E2A106EFC97F03ADF95840A631B20CE`。
此值为本工程实际下载记录，未执行独立 GPG 签名认证。安装脚本使用它检测后续下载变化。

上游源码：https://github.com/sleuthkit/sleuthkit/tree/sleuthkit-4.15.0

发行包的许可证及第三方组件许可证完整保留于 `tools/sleuthkit-4.15.0-win32/licenses/`，分发时必须一并保留。TSK 未作二进制修改；通过独立进程调用。

桌面界面使用 Qt for Python 官方 PySide6（Qt 6）及其随包依赖，由 `requirements.txt` 安装到项目 `.venv`。官方文档与许可入口：[Qt for Python](https://doc.qt.io/qtforpython-6/)、[Commercial Use](https://doc.qt.io/qtforpython-6/commercial/index.html)。上游提供 LGPLv3/GPLv3 和商业许可选项，具体组件适用许可及第三方声明以安装包所附文件为准。本工程通过 Python 导入使用，未修改 PySide6 或 Qt 二进制文件；源码工程包不包含 `.venv`，运行前需安装依赖，若另行分发运行库应一并保留其许可证和声明。

AI 参与范围：需求梳理、架构、PySide6 界面、案件及审计逻辑、TSK 封装、FAT16 测试夹具、自动测试、Markdown 使用和设计文档由 Codex 协助编写并在当前环境执行验证。TSK 为官方预编译第三方组件。个人学习心得、姓名学号及理解程度需要学生本人补充，不由程序虚构。
