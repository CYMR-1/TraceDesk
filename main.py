"""应用入口；双击启动取证工作台.bat 使用项目虚拟环境运行。"""
from forensic.launcher import ApplicationLauncher

if __name__ == '__main__':
    raise SystemExit(ApplicationLauncher().run())
