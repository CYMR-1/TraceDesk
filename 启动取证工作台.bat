@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "APP_EXE=target\release\tracedesk-desktop.exe"
if exist "%APP_EXE%" goto run

echo 未检测到已编译的原生桌面工作台，开始自动构建...

if not exist "frontend\dist\index.html" (
    echo [1/2] 正在安装依赖并构建前端界面资源 ^(frontend\dist^)...
    pushd frontend
    call npm.cmd ci
    if errorlevel 1 (
        popd
        goto failed
    )
    call npm.cmd run build
    if errorlevel 1 (
        popd
        goto failed
    )
    popd
)

echo [2/2] 正在编译 TraceDesk 原生桌面工作台 ^(Rust Release^)...
cargo build --release -p tracedesk-desktop
if errorlevel 1 goto failed

if not exist "%APP_EXE%" (
    echo 构建完成但未找到 %APP_EXE%。
    goto failed
)

:run
start "" "%~dp0%APP_EXE%"
exit /b 0

:failed
echo.
echo 启动或构建 TraceDesk 失败，请检查 Rust ^(cargo^)、Node.js ^(npm^) 与 MSVC 构建工具配置。
pause
exit /b 1
