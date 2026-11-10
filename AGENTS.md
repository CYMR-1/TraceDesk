# 项目工作约定

- 使用 Python 时，必须先在本项目目录创建并使用 `.venv`；所有项目第三方依赖均安装到该虚拟环境，不安装到全局 Python 环境。
- 运行脚本、测试和依赖管理时，使用 `.venv\Scripts\python.exe`；安装依赖使用清华镜像 `https://pypi.tuna.tsinghua.edu.cn/simple`。
- 每次完成代码或文档改动后，都要执行 `git commit`，提交消息使用中文。
- 界面使用 PySide6，采用浅色主题，避免蓝白配色。
- 开始改动前检查 `git status`，保留用户已有的未提交内容，不覆盖或回退无关改动。
