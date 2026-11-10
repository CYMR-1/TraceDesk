$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $projectRoot 'tools'
New-Item -ItemType Directory -Force -Path $toolRoot | Out-Null
$archive = Join-Path $toolRoot 'sleuthkit-4.15.0-win32.zip'
$expected = 'C2EBAB8105B893D97BD8CE35B88E01985E2A106EFC97F03ADF95840A631B20CE'
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest -Uri 'https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0-win32.zip' -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw '发行包 SHA-256 与本工程记录不一致。请核对官方发行信息。'
}
Expand-Archive -LiteralPath $archive -DestinationPath $toolRoot -Force
Write-Output 'TSK 依赖已就绪。哈希为本工程下载记录，非独立签名认证。'
