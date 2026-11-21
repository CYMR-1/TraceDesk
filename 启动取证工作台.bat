@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

set "ROOT_DIR=%~dp0"
set "APP_EXE=%~dp0target\release\tracedesk-desktop.exe"
set "LOG_FILE=%~dp0logs\startup.log"
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if exist "%APP_EXE%" goto run

echo [TraceDesk] 未检测到已编译的原生桌面工作台，开始自动构建...

if exist "%~dp0frontend\dist\index.html" goto build_rust

where npm.cmd >nul 2>&1
if errorlevel 1 (
    echo [TraceDesk] 错误：未找到 Node.js ^(npm.cmd^)，请先安装 Node.js v20+ 后重试。
    goto failed
)
echo [TraceDesk] [1/2] 正在安装依赖并构建前端界面资源 ^(frontend\dist^)...
pushd "%~dp0frontend"
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

:build_rust
where cargo >nul 2>&1
if errorlevel 1 (
    echo [TraceDesk] 错误：未找到 Rust 工具链 ^(cargo^)，请先安装 Rust 1.85+ 与 MSVC 构建工具。
    goto failed
)

echo [TraceDesk] [2/2] 正在编译 TraceDesk 原生桌面工作台 ^(Rust Release^)...
cargo build --release -p tracedesk-desktop
if errorlevel 1 goto failed

if not exist "%APP_EXE%" (
    echo [TraceDesk] 错误：编译完成但未找到 %APP_EXE%。
    goto failed
)

:run
echo [TraceDesk] 正在启动原生桌面工作台...
set "TRACEDESK_LAUNCH_EXE=%APP_EXE%"
set "TRACEDESK_LAUNCH_DIR=%ROOT_DIR%"
set "TRACEDESK_LOG_FILE=%LOG_FILE%"

if not exist "%PS_EXE%" goto run_fallback

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "$exe = $env:TRACEDESK_LAUNCH_EXE; $dir = $env:TRACEDESK_LAUNCH_DIR; try { $p = Start-Process -FilePath $exe -WorkingDirectory $dir -PassThru -ErrorAction Stop } catch { Write-Host ('[TraceDesk] 启动进程失败: ' + $_.Exception.Message); exit 3 }; for ($i = 0; $i -lt 40; $i++) { Start-Sleep -Milliseconds 200; $p.Refresh(); if ($p.HasExited) { Write-Host ('[TraceDesk] 桌面工作台启动后异常退出，退出码: ' + $p.ExitCode); exit 2 }; if ($p.MainWindowHandle -ne 0) { exit 0 } }; $p.Refresh(); if ($p.HasExited) { Write-Host ('[TraceDesk] 桌面工作台启动后异常退出，退出码: ' + $p.ExitCode); exit 2 }; exit 0"
if errorlevel 1 goto launch_failed

echo [TraceDesk] 原生桌面工作台已启动。
exit /b 0

:run_fallback
start "" /D "%ROOT_DIR%" "%APP_EXE%"
if errorlevel 1 goto launch_failed
exit /b 0

:launch_failed
echo.
echo [TraceDesk] 原生桌面工作台未能正常启动。
if not exist "%LOG_FILE%" goto no_log
echo [TraceDesk] 最近启动日志 ^(%LOG_FILE%^):
echo ------------------------------------------------------------
if exist "%PS_EXE%" (
    "%PS_EXE%" -NoProfile -Command "Get-Content -LiteralPath $env:TRACEDESK_LOG_FILE -Tail 20 -Encoding UTF8"
) else (
    type "%LOG_FILE%"
)
echo ------------------------------------------------------------
goto pause_fail

:no_log
echo [TraceDesk] 未检测到启动日志文件，请确认系统已安装 Microsoft Edge WebView2 Runtime。
goto pause_fail

:failed
echo.
echo [TraceDesk] 启动或构建 TraceDesk 失败，请检查 Rust ^(cargo^)、Node.js ^(npm^) 与 MSVC 构建工具配置。

:pause_fail
echo.
pause
exit /b 1
