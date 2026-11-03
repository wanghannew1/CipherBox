# =============================================================================
# deploy/server_start.ps1 — cipherbox 服务器日常启动（HTTPS 8443，仅 TLS）
#
# 由 deploy/server_setup_uv.ps1 部署完成后使用：
#   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\server_start.ps1
# 可选参数: -Port 9443 -Host 0.0.0.0
# =============================================================================
[CmdletBinding()]
param(
    [string]$Host_ = "0.0.0.0",
    [int]$Port = 8443
)
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$VenvPython = "server\.venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[server] 虚拟环境不存在，先运行: deploy\server_setup_uv.ps1" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path "server\audit-hmac.key")) {
    Write-Host "[server] 缺 server\audit-hmac.key，先运行: deploy\server_setup_uv.ps1" -ForegroundColor Red
    exit 1
}

$env:CIPHERBOX_HMAC_KEY_FILE = Join-Path $RepoRoot "server\audit-hmac.key"
Write-Host "[server] HTTPS https://${Host_}:${Port}  (无 HTTP 监听；CA=server\certs\ca.crt)" -ForegroundColor Cyan
& $VenvPython -m uvicorn server.app:create_app --factory `
    --host $Host_ --port $Port `
    --ssl-certfile server\certs\server.crt --ssl-keyfile server\certs\server.key
