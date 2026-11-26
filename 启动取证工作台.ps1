<#
.SYNOPSIS
    TraceDesk 电子数据取证工作台 PowerShell 7 一键构建与启动脚本。
.DESCRIPTION
    定位当前仓库根目录下的原生桌面端 Release 可执行文件（target\release\tracedesk-desktop.exe）。
    若二进制缺失或指定 -Rebuild，则按需构建前端资源（frontend\dist）并编译 Rust Release 桌面端；
    随后拉起原生桌面工作台并轮询确认主窗口句柄已就绪。
.PARAMETER Rebuild
    强制重新构建前端资源（npm.cmd ci + npm.cmd run build）与 Rust Release 二进制后再启动。
.PARAMETER BuildOnly
    仅执行构建检查（缺失或配合 -Rebuild 时执行构建），完成后退出，不拉起桌面窗口。
.PARAMETER NoWait
    拉起桌面工作台进程后立即返回，跳过最长 8 秒的主窗口句柄等待。
.EXAMPLE
    pwsh -File .\启动取证工作台.ps1
    直接启动原生桌面工作台；若尚未编译则自动构建后启动。
.EXAMPLE
    pwsh -File .\启动取证工作台.ps1 -Rebuild
    强制重新构建前端与 Rust Release 桌面端后启动。
.EXAMPLE
    pwsh -File .\启动取证工作台.ps1 -BuildOnly
    仅执行构建检查，不拉起桌面窗口。
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Rebuild,
    [switch]$BuildOnly,
    [switch]$NoWait
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

# 统一将控制台与外部命令管道编码设为 UTF-8，确保中文输出及日志不乱码
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
try {
    [Console]::InputEncoding = $utf8NoBom
    [Console]::OutputEncoding = $utf8NoBom
} catch {
    # 非控制台或流重定向场景下安全忽略编码设置异常
}
$OutputEncoding = $utf8NoBom

# 解析项目根目录与关键文件路径
$RootDir = $PSScriptRoot
$FrontendDir = Join-Path -Path $RootDir -ChildPath 'frontend'
$FrontendIndex = Join-Path -Path $FrontendDir -ChildPath (Join-Path 'dist' 'index.html')
$AppExe = Join-Path -Path $RootDir -ChildPath (Join-Path 'target' (Join-Path 'release' 'tracedesk-desktop.exe'))
$LogFile = Join-Path -Path $RootDir -ChildPath (Join-Path 'logs' 'startup.log')

function Test-IsInteractiveTerminal {
    <#
    .SYNOPSIS
        判断当前是否处于可等待用户按回车确认的交互式终端。
    #>
    if (-not [Environment]::UserInteractive) {
        return $false
    }
    try {
        if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) {
            return $false
        }
    } catch {
        return $false
    }
    return $true
}

function Wait-OnFailure {
    <#
    .SYNOPSIS
        在交互式终端发生失败时提示按回车退出，避免双击或独立窗口瞬闪关闭。
    #>
    if (Test-IsInteractiveTerminal) {
        Write-Host ''
        [void](Read-Host -Prompt '按回车键退出')
    }
}

function Show-StartupLog {
    <#
    .SYNOPSIS
        若存在 logs\startup.log 则以 UTF-8 输出最近 20 行诊断日志。
    #>
    if (-not (Test-Path -LiteralPath $LogFile -PathType Leaf)) {
        Write-Host '[TraceDesk] 未检测到启动日志文件，请确认系统已安装 Microsoft Edge WebView2 Runtime。'
        return
    }

    Write-Host "[TraceDesk] 最近启动日志 ($LogFile):"
    Write-Host '------------------------------------------------------------'
    try {
        Get-Content -LiteralPath $LogFile -Tail 20 -Encoding utf8 | ForEach-Object {
            Write-Host $_
        }
    } catch {
        Write-Host "[TraceDesk] 读取启动日志失败：$($_.Exception.Message)"
    }
    Write-Host '------------------------------------------------------------'
}

function Invoke-ExternalStep {
    <#
    .SYNOPSIS
        在指定工作目录中执行外部构建命令，并在返回非零退出码时抛出中文错误。
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [Parameter(Mandatory)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory)]
        [string]$StepName
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $FilePath @Arguments
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "${StepName}失败（退出码：${exitCode}）。"
        }
    } finally {
        Pop-Location
    }
}

function Exit-WithBuildFailure {
    <#
    .SYNOPSIS
        统一输出构建阶段中文诊断信息并以非零状态码退出。
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[TraceDesk] 错误：$Message"
    Write-Host ''
    Write-Host '[TraceDesk] 启动或构建 TraceDesk 失败，请检查 Rust (cargo)、Node.js (npm.cmd) 与 MSVC 构建工具配置。'
    Wait-OnFailure
    exit 1
}

function Exit-WithLaunchFailure {
    <#
    .SYNOPSIS
        统一输出启动阶段中文诊断信息、最近启动日志并以非零状态码退出。
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[TraceDesk] $Message"
    Write-Host ''
    Write-Host '[TraceDesk] 原生桌面工作台未能正常启动。'
    Show-StartupLog
    Wait-OnFailure
    exit 2
}

# 阶段一：检查是否需要构建前端与 Rust Release 桌面端
$hasAppExe = Test-Path -LiteralPath $AppExe -PathType Leaf
$needBuild = $Rebuild.IsPresent -or (-not $hasAppExe)

if ($needBuild) {
    try {
        if ($Rebuild.IsPresent) {
            Write-Host '[TraceDesk] 已指定 -Rebuild，开始强制重新构建前端与原生桌面工作台...'
        } else {
            Write-Host '[TraceDesk] 未检测到已编译的原生桌面工作台，开始自动构建...'
        }

        $hasFrontendDist = Test-Path -LiteralPath $FrontendIndex -PathType Leaf
        $needFrontendBuild = $Rebuild.IsPresent -or (-not $hasFrontendDist)

        if ($needFrontendBuild) {
            $npmCmd = Get-Command -Name 'npm.cmd' -ErrorAction SilentlyContinue
            if (-not $npmCmd) {
                throw '未找到 Node.js (npm.cmd)，请先安装 Node.js v20+ 后重试。'
            }

            Write-Host '[TraceDesk] [1/2] 正在安装依赖并构建前端界面资源 (frontend\dist)...'
            Invoke-ExternalStep -FilePath $npmCmd.Source -Arguments @('ci') -WorkingDirectory $FrontendDir -StepName '安装前端依赖 (npm.cmd ci)'
            Invoke-ExternalStep -FilePath $npmCmd.Source -Arguments @('run', 'build') -WorkingDirectory $FrontendDir -StepName '构建前端资源 (npm.cmd run build)'
        } else {
            Write-Host '[TraceDesk] 已检测到前端构建产物 (frontend\dist\index.html)，跳过前端编译。'
        }

        $cargoCmd = Get-Command -Name 'cargo' -ErrorAction SilentlyContinue
        if (-not $cargoCmd) {
            throw '未找到 Rust 工具链 (cargo)，请先安装 Rust 1.85+ 与 MSVC 构建工具。'
        }

        Write-Host '[TraceDesk] [2/2] 正在编译 TraceDesk 原生桌面工作台 (Rust Release)...'
        Invoke-ExternalStep -FilePath $cargoCmd.Source -Arguments @('build', '--release', '-p', 'tracedesk-desktop') -WorkingDirectory $RootDir -StepName '编译原生桌面工作台 (cargo build --release -p tracedesk-desktop)'

        if (-not (Test-Path -LiteralPath $AppExe -PathType Leaf)) {
            throw "编译完成但未找到目标可执行文件：$AppExe"
        }
    } catch {
        Exit-WithBuildFailure -Message $_.Exception.Message
    }
} elseif ($BuildOnly.IsPresent) {
    Write-Host "[TraceDesk] 已检测到原生桌面工作台二进制：$AppExe"
}

# 若指定 -BuildOnly，仅完成构建检查并正常返回，不拉起 GUI 窗口
if ($BuildOnly.IsPresent) {
    Write-Host '[TraceDesk] 构建检查完成（-BuildOnly 模式，未启动桌面窗口）。'
    exit 0
}

# 阶段二：拉起原生桌面工作台并按需轮询主窗口句柄（最长 8 秒）
Write-Host '[TraceDesk] 正在启动原生桌面工作台...'
try {
    $process = Start-Process -FilePath $AppExe -WorkingDirectory $RootDir -PassThru -ErrorAction Stop
} catch {
    Exit-WithLaunchFailure -Message "启动进程失败：$($_.Exception.Message)"
}

if ($NoWait.IsPresent) {
    Write-Host "[TraceDesk] 已拉起原生桌面工作台进程（PID: $($process.Id)，已跳过主窗口等待）。"
    exit 0
}

try {
    $windowReady = $false
    # 每 200ms 轮询一次，最长等待 8 秒（40 次）确认主窗口句柄已创建且进程未异常退出
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 200
        $process.Refresh()
        if ($process.HasExited) {
            Exit-WithLaunchFailure -Message "桌面工作台启动后异常退出，退出码：$($process.ExitCode)"
        }
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) {
            $windowReady = $true
            break
        }
    }

    $process.Refresh()
    if ($process.HasExited) {
        Exit-WithLaunchFailure -Message "桌面工作台启动后异常退出，退出码：$($process.ExitCode)"
    }

    if ($windowReady) {
        Write-Host "[TraceDesk] 原生桌面工作台已启动（PID: $($process.Id)）。"
    } else {
        Write-Host "[TraceDesk] 原生桌面工作台进程运行中（PID: $($process.Id)），主窗口仍在初始化。"
    }
    exit 0
} catch {
    Exit-WithLaunchFailure -Message "监控桌面工作台启动状态失败：$($_.Exception.Message)"
}
