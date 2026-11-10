@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)

".venv\Scripts\python.exe" -c "from PySide6.QtWidgets import QApplication" >nul 2>&1
if errorlevel 1 goto install_dependencies
goto run

:install_dependencies
echo 正在为项目虚拟环境安装界面依赖...
".venv\Scripts\python.exe" -m pip --version >nul 2>&1
if not errorlevel 1 goto pip_ready
".venv\Scripts\python.exe" -m ensurepip --upgrade
if errorlevel 1 goto failed

:pip_ready
".venv\Scripts\python.exe" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
if errorlevel 1 goto failed

:run
".venv\Scripts\python.exe" main.py
if errorlevel 1 goto failed
exit /b 0

:failed
pause
exit /b 1
