# =============================================================================
# deploy/server_setup_uv.ps1 — cipherbox 服务器一键部署（uv 虚拟环境版）
#
# 幂等：重复执行安全（已完成的步骤自动跳过）。
#   1. 检查/安装 uv（-InstallUv 自动装）
#   2. uv venv 创建 server\.venv（-Recreate 重建）
#   3. uv pip 安装 server\requirements.txt
#   4. 生成自签 CA/服务器证书（已存在则跳过，需 OpenSSL 在 PATH）
#   5. 种子数据库 + HMAC 审计密钥（已存在则跳过；-Reseed 重新签发令牌）
#   6. 打印日常启动/健康检查命令
#
# 用法（管理员或普通用户均可，无需管理员）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\server_setup_uv.ps1
#   powershell ... -File deploy\server_setup_uv.ps1 -InstallUv    # uv 缺失时
#   powershell ... -File deploy\server_setup_uv.ps1 -Recreate     # 重建虚拟环境
#   powershell ... -File deploy\server_setup_uv.ps1 -Reseed       # 重新签发令牌
# =============================================================================
[CmdletBinding()]
param(
    [switch]$InstallUv,
    [switch]$Recreate,
    [switch]$Reseed,
    [string]$PythonVersion = "3.11"
)
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
$VenvPython = "server\.venv\Scripts\python.exe"

function Step($msg) { Write-Host "[setup] $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[setup] $msg" -ForegroundColor Green }

# -- 0. 国内镜像默认（npmmirror 同步 python-build-standalone，TUNA 同步 PyPI）----------
if (-not $env:UV_PYTHON_INSTALL_MIRROR) {
    $env:UV_PYTHON_INSTALL_MIRROR = "https://registry.npmmirror.com/-/binary/python-build-standalone"
}
if (-not $env:UV_DEFAULT_INDEX) {
    $env:UV_DEFAULT_INDEX = "https://pypi.tuna.tsinghua.edu.cn/simple"
}

# -- 1. uv -------------------------------------------------------------------
$uvCmd = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uvCmd) {
    if (-not $InstallUv) {
        Write-Host "[setup] 未找到 uv。二选一：" -ForegroundColor Yellow
        Write-Host '  a) 重新运行并加 -InstallUv 自动安装'
        Write-Host '  b) 手动安装: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
        exit 1
    }
    Step "安装 uv ..."
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    if ($LASTEXITCODE -ne 0) { Write-Host "[setup] uv 安装失败" -ForegroundColor Red; exit 1 }
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
    $uvCmd = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uvCmd) { Write-Host "[setup] uv 安装后仍不可用（重开终端再试）" -ForegroundColor Red; exit 1 }
}
Ok "uv $(uv --version)"

# -- 2. 虚拟环境 ----------------------------------------------------------------
if ($Recreate -and (Test-Path "server\.venv")) {
    Step "删除旧虚拟环境（-Recreate）..."
    Remove-Item -Recurse -Force "server\.venv"
}
if (-not (Test-Path $VenvPython)) {
    Step "uv venv 创建 server\.venv (python $PythonVersion) ..."
    & uv venv server\.venv --python $PythonVersion
    if ($LASTEXITCODE -ne 0) { Write-Host "[setup] venv 创建失败" -ForegroundColor Red; exit 1 }
} else {
    Ok "虚拟环境已存在: $VenvPython"
}

# -- 3. 依赖 ---------------------------------------------------------------------
Step "uv pip 安装 server\requirements.txt ..."
& uv pip install --python $VenvPython -r "server\requirements.txt"
if ($LASTEXITCODE -ne 0) { Write-Host "[setup] 依赖安装失败" -ForegroundColor Red; exit 1 }

# -- 4. 证书 -----------------------------------------------------------------------
if (Test-Path "server\certs\server.crt") {
    Ok "证书已存在: server\certs\（跳过；删目录或 -Force 语义见 gen_certs.py --force）"
} else {
    if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
        Write-Host "[setup] 未找到 openssl（gen_certs.py 依赖）。安装 OpenSSL 后重跑。" -ForegroundColor Red
        exit 1
    }
    Step "生成自签 CA + 服务器证书 ..."
    & $VenvPython deploy\gen_certs.py
    if ($LASTEXITCODE -ne 0) { Write-Host "[setup] 证书生成失败" -ForegroundColor Red; exit 1 }
}

# -- 5. 种子数据库 -------------------------------------------------------------------
if ((Test-Path "server\cipherbox.db") -and (-not $Reseed)) {
    Ok "数据库已存在: server\cipherbox.db（跳过；-Reseed 重新签发令牌）"
} else {
    if ($Reseed) { Step "重新签发令牌（旧令牌仍有效，建议先 /admin/revoke）..." }
    else { Step "种子数据库 + HMAC 审计密钥 ..." }
    & $VenvPython deploy\seed_local.py --db server\cipherbox.db --hmac-out server\audit-hmac.key
    if ($LASTEXITCODE -ne 0) { Write-Host "[setup] 种子失败" -ForegroundColor Red; exit 1 }
}

# -- 完成 ---------------------------------------------------------------------------
Write-Host ""
Ok "服务器部署完成。日常操作："
Write-Host "  启动:   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\server_start.ps1"
Write-Host "  健康检查: curl.exe -k https://127.0.0.1:8443/health"
Write-Host "  审计校验: $VenvPython -m server.verify_audit server\cipherbox.db server\audit-hmac.key"
Write-Host "  令牌只打印过一次——丢失请用 -Reseed 重新签发。"
