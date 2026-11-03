# =============================================================================
# deploy/client_start.ps1 — cipherbox 客户端日常启动（LO 加密服务 + 常驻 Agent）
#
# 幂等：LO 服务已监听则直接复用（start_soffice.ps1 自身幂等，重复调用退出 0）；
#   Agent 有单实例互斥体，重复启动会在新窗口打印明确提示后退出（预期行为）。
#   1. 检查保密卷（默认 S:\）
#   2. 启动/复用 LO 常驻加密服务（调用 lo-encryption-demo\start_soffice.ps1，不重复造轮子）
#   3. 在新的可见控制台窗口启动常驻 Agent（用户能看到 recovery/keys/watcher/pipe）
#   4. 打印验证方法
#
# 用法（普通用户即可，无需管理员）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\client_start.ps1
#   powershell ... -File deploy\client_start.ps1 -Volume "S:\"     # 其他卷
# =============================================================================
[CmdletBinding()]
param(
    [string]$Volume = "S:\",
    [string]$RepoRoot = ""
)
$ErrorActionPreference = "Stop"
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = $RepoRoot.TrimEnd('\')
Set-Location $RepoRoot
$VenvPython = Join-Path $RepoRoot "agent\.venv\Scripts\python.exe"

function Step($msg) { Write-Host "[start] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[start] $msg" -ForegroundColor Green }

# -- 1. 保密卷 -------------------------------------------------------------------
$volBase = $Volume.TrimEnd('\')
if (-not (Test-Path -LiteralPath "$volBase\")) {
    Write-Host "[start] 错误: 卷 $Volume 未挂载。" -ForegroundColor Red
    Write-Host "  真实环境: 先用 VeraCrypt 挂载保密卷到 $Volume，再重跑本脚本。"
    Write-Host "  纯测试机: subst $volBase C:\某个测试目录 建立模拟卷（见 docs\部署实测指南.md 第 1 节）。"
    exit 1
}
Ok "卷已就绪: $Volume"

# -- 1.5 部署产物检查（给可执行的指引，而不是晦涩报错）--------------------------------
if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Host "[start] 错误: 未找到 $VenvPython" -ForegroundColor Red
    Write-Host "  处理: 先运行一键部署: powershell -NoProfile -ExecutionPolicy Bypass -File deploy\client_setup_uv.ps1"
    exit 1
}
foreach ($f in @("config\client.json", "config\employee_token.dpapi")) {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot $f))) {
        Write-Host "[start] 错误: 缺少 $f" -ForegroundColor Red
        Write-Host "  处理: 先运行一键部署 deploy\client_setup_uv.ps1（令牌步骤需要 -EmployeeToken）。"
        exit 1
    }
}
Ok "部署产物齐全 (agent\.venv + config\client.json + config\employee_token.dpapi)"

# -- 2. LO 常驻加密服务（幂等，已监听则直接复用）--------------------------------------
Step "启动/复用 LO 常驻加密服务 ..."
$sofficeArgs = @("-Volume", $Volume)
if ($env:CIPHERBOX_LO_PYTHON) { $sofficeArgs += @("-BundledPython", $env:CIPHERBOX_LO_PYTHON) }
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "lo-encryption-demo\start_soffice.ps1") @sofficeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "[start] LO 加密服务启动失败（见上方诊断输出）。" -ForegroundColor Red
    Write-Host "  常见原因: LibreOffice 非默认路径 -> 设 CIPHERBOX_LO_PYTHON; 或卷内 profile 目录损坏。"
    exit 1
}
Ok "LO 加密服务就绪 (named pipe: cipherbox-service)"

# -- 3. 常驻 Agent（新开可见控制台窗口；单实例互斥体保证幂等）----------------------------
$pipes = @()
try { $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") } catch [System.IO.IOException] { }
if (@($pipes) -match "cipherbox-open") {
    Write-Host "[start] 提示: 管道 \\.\pipe\cipherbox-open 已存在 —— 可能已有 Agent 在运行。" -ForegroundColor Yellow
    Write-Host "  新窗口若打印 another resident agent already owns the instance mutex 属预期（单实例互斥体）。"
}
# 用 -EncodedCommand 传递内嵌命令：路径含空格也安全（PS 5.1 的 ArgumentList 不自动加引号）
$ConfigJson = Join-Path $RepoRoot "config\client.json"
$TokenFile = Join-Path $RepoRoot "config\employee_token.dpapi"
$inner = "Set-Location -LiteralPath '$RepoRoot'; & '$VenvPython' -m agent --config '$ConfigJson' --token-file '$TokenFile'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
Start-Process powershell -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit", "-EncodedCommand", $encoded) | Out-Null
Ok "Agent 已在新控制台窗口启动（保持该窗口开启; 停止用 client_stop.ps1 或在窗口 Ctrl+C）"

# -- 完成 ---------------------------------------------------------------------------
Write-Host ""
Ok "客户端已启动。验证方法："
Write-Host "  1) Agent 窗口应依次出现 4 行:"
Write-Host "     [agent] recovery: ... -> [agent] keys: N version(s), current=vN -> [agent] watcher: ... -> [agent] pipe: listening"
Write-Host "  2) 受控打开测试: agent\.venv\Scripts\python.exe -m agent.launcher <文件.cbx>（或双击 .cbx，如已 -Associate）"
Write-Host "  3) 停止: powershell -NoProfile -ExecutionPolicy Bypass -File deploy\client_stop.ps1"
