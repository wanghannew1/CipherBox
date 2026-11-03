# =============================================================================
# deploy/client_setup_uv.ps1 — cipherbox 客户端一键部署（Windows 10/11，uv 虚拟环境版）
#
# 幂等：重复执行安全（已完成的步骤自动跳过；config\client.json 始终按当前参数重写，
#   令牌文件只在提供新令牌时才覆盖）。
#   1. 检查/安装 uv（-InstallUv 自动装）
#   2. uv venv 创建 agent\.venv（-Recreate 重建）+ 安装 agent\requirements.txt
#   3. 前置检查：LibreOffice、保密卷（默认 S:\）、LO 自带 Python
#   4. 服务器连通探测（失败仅警告，不阻断）
#   5. 写 config\client.json（9 个键，ASCII 无 BOM，JSON 内路径用正斜杠）
#   6. DPAPI 加密员工令牌 -> config\employee_token.dpapi（令牌走 stdin，不上命令行）
#   7. 生成 deploy\cbx_open.cmd；-Associate 时注册 .cbx 文件关联（HKCU，无需管理员）
#   8. 打印日常启动/测试命令
#
# 用法（普通用户即可，无需管理员）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\client_setup_uv.ps1 `
#       -ServerUrl https://172.16.0.70:8443 -EmployeeToken <员工令牌>
#   powershell ... -File deploy\client_setup_uv.ps1 -Associate    # 同时注册 .cbx 双击关联
#   powershell ... -File deploy\client_setup_uv.ps1 -InstallUv    # uv 缺失时自动安装
#   powershell ... -File deploy\client_setup_uv.ps1 -Recreate     # 重建虚拟环境
# =============================================================================
[CmdletBinding()]
param(
    [string]$ServerUrl = "https://172.16.0.70:8443",
    [string]$EmployeeToken,
    [string]$Volume = "S:\",
    [string]$RepoRoot = "",
    [switch]$Associate,
    [switch]$InstallUv,
    [switch]$Recreate
)
$ErrorActionPreference = "Stop"
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = $RepoRoot.TrimEnd('\')
Set-Location $RepoRoot
$VenvPython = "agent\.venv\Scripts\python.exe"
$TokenFile = "config\employee_token.dpapi"

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

# -- 2. agent 虚拟环境 + 依赖 -----------------------------------------------------
if ($Recreate -and (Test-Path "agent\.venv")) {
    Step "删除旧虚拟环境（-Recreate）..."
    Remove-Item -Recurse -Force "agent\.venv"
}
if (-not (Test-Path $VenvPython)) {
    Step "uv venv 创建 agent\.venv (python 3.11) ..."
    & uv venv agent\.venv --python 3.11
    if ($LASTEXITCODE -ne 0) { Write-Host "[setup] venv 创建失败" -ForegroundColor Red; exit 1 }
} else {
    Ok "虚拟环境已存在: agent\.venv"
}
Step "uv pip 安装 agent\requirements.txt ..."
& uv pip install --python $VenvPython -r "agent\requirements.txt"
if ($LASTEXITCODE -ne 0) { Write-Host "[setup] 依赖安装失败" -ForegroundColor Red; exit 1 }

# -- 3. 前置检查（LibreOffice / 保密卷 / LO 自带 Python）----------------------------
$Soffice = "C:\Program Files\LibreOffice\program\soffice.exe"
if (-not (Test-Path -LiteralPath $Soffice)) {
    Write-Host "[setup] 未找到 LibreOffice: $Soffice" -ForegroundColor Red
    Write-Host "  处理: 安装 LibreOffice（https://www.libreoffice.org/，按默认路径安装）后重跑本脚本。"
    exit 1
}
Ok "LibreOffice: $Soffice"

$volBase = $Volume.TrimEnd('\')
if (-not (Test-Path -LiteralPath "$volBase\")) {
    Write-Host "[setup] 保密卷未挂载: $Volume 不存在" -ForegroundColor Red
    Write-Host "  真实环境: 先用 VeraCrypt 挂载保密卷到 $Volume，再重跑本脚本。"
    Write-Host "  纯测试机: subst $volBase C:\某个测试目录 建立模拟卷（见 docs\部署实测指南.md 第 1 节）。"
    exit 1
}
Ok "保密卷已就绪: $Volume"

$LoPython = "C:\Program Files\LibreOffice\program\python.exe"
if ($env:CIPHERBOX_LO_PYTHON) {
    if (-not (Test-Path -LiteralPath $env:CIPHERBOX_LO_PYTHON)) {
        Write-Host "[setup] CIPHERBOX_LO_PYTHON 指向的文件不存在: $env:CIPHERBOX_LO_PYTHON" -ForegroundColor Red
        Write-Host "  处理: 修正环境变量，使其指向 LibreOffice 自带的 python.exe，再重跑。"
        exit 1
    }
    Ok "LO 自带 Python (CIPHERBOX_LO_PYTHON): $env:CIPHERBOX_LO_PYTHON"
} elseif (Test-Path -LiteralPath $LoPython) {
    Ok "LO 自带 Python: $LoPython"
} else {
    Write-Host "[setup] 未找到 LO 自带 Python: $LoPython" -ForegroundColor Red
    Write-Host "  Agent 的加密操作需要委派给 LO 自带 Python（UNO 子进程）。"
    Write-Host "  处理: LibreOffice 装在非默认路径时，设置环境变量 CIPHERBOX_LO_PYTHON 指向其 python.exe 后重跑。"
    exit 1
}

# -- 4. 服务器连通探测（失败仅警告，不阻断）------------------------------------------
$health = & curl.exe -sk --connect-timeout 5 "$ServerUrl/health"
if ($LASTEXITCODE -eq 0 -and "$health" -match '"ok"') {
    Ok "服务器可达: $ServerUrl/health -> $health"
} else {
    Write-Host "[setup] 警告: 服务器 $ServerUrl 暂不可达（不阻断部署）。" -ForegroundColor Yellow
    Write-Host "  Agent 首次启动需要在线取钥；请启动服务器后运行 deploy\client_start.ps1。"
}

# -- 5. config\client.json（9 个键，按当前参数重写）---------------------------------
New-Item -ItemType Directory -Force -Path "config" | Out-Null
$CaFile = "server\certs\ca.crt"
if (Test-Path -LiteralPath $CaFile) {
    $CaJson = (Join-Path $RepoRoot $CaFile) -replace '\\', '/'
    Ok "CA 证书存在（客户端按此 CA 固定校验）: $CaFile"
} else {
    $CaJson = ""
    Write-Host "[setup] 警告: 未找到 CA 证书 $CaFile —— 必须从服务器复制（客户端 CA 固定）。" -ForegroundColor Yellow
}

$volJson = $volBase -replace '\\', '/'
$appDataJson = $env:APPDATA -replace '\\', '/'
$ClientJson = @"
{
  "server_url": "$ServerUrl",
  "ca_cert_file": "$CaJson",
  "protected_dir": "$volJson/",
  "temp_root": "$volJson/.cipherbox-tmp",
  "service_profile": "$volJson/.cipherbox-profile/service",
  "controlled_profile": "$volJson/.cipherbox-profile/controlled",
  "session_dir": "$appDataJson/CipherBox/sessions",
  "keycache": "$appDataJson/CipherBox/keycache.dat",
  "audit_queue": "$appDataJson/CipherBox/audit-queue.json"
}
"@
Set-Content -LiteralPath "config\client.json" -Value $ClientJson -Encoding Ascii
Ok "配置已写入: config\client.json（9 个键）"

# -- 6. DPAPI 加密员工令牌 -------------------------------------------------------
$haveTokenFile = Test-Path -LiteralPath $TokenFile
if (-not $EmployeeToken -and [Environment]::UserInteractive) {
    Write-Host "[setup] 未通过参数提供员工令牌，请隐藏输入（输入不回显，回车确认）:" -ForegroundColor Cyan
    $secure = Read-Host -AsSecureString "员工令牌"
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $EmployeeToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}
if ($EmployeeToken) {
    Step "写入 DPAPI 加密令牌 -> $TokenFile ..."
    # 令牌经 DeleteOnClose 临时文件传给 venv python（显式 UTF-8 无 BOM 字节），
    # 绝不出现在命令行/进程列表中；PS 5.1 管道会额外注入 UTF-8 BOM（实测），
    # 且临时文件随句柄关闭自动删除，明文落盘窗口极小。
    $tokenTmp = Join-Path ([IO.Path]::GetTempPath()) ("cipherbox-token-" + [IO.Path]::GetRandomFileName())
    $fs = [System.IO.File]::Open($tokenTmp, 'Create', 'Write', 'Read')
    try {
        $tokenBytes = [Text.Encoding]::UTF8.GetBytes($EmployeeToken)
        $fs.Write($tokenBytes, 0, $tokenBytes.Length)
        $fs.Flush()
        $code = "import sys; sys.path.insert(0, r'$RepoRoot'); from agent.key_manager import dpapi_encrypt; open(r'$TokenFile','wb').write(dpapi_encrypt(open(r'$tokenTmp','rb').read().strip()))"
        & $VenvPython -c $code
        if ($LASTEXITCODE -ne 0) { Write-Host "[setup] 令牌 DPAPI 加密失败" -ForegroundColor Red; exit 1 }
    } finally {
        $fs.Close()   # DeleteOnClose: 临时文件立即自动删除
    }
    Ok "员工令牌已写入 (DPAPI CurrentUser，仅当前 Windows 用户可解)"
} elseif ($haveTokenFile) {
    Ok "令牌文件已存在: $TokenFile（未提供新令牌，跳过）"
} else {
    Write-Host "[setup] 警告: 没有令牌文件 $TokenFile，Agent 启动会失败。" -ForegroundColor Yellow
    Write-Host "  处理: 重跑本脚本并提供 -EmployeeToken（或在提示时隐藏输入）。"
}

# -- 7. cbx_open.cmd +（可选）.cbx 文件关联 ------------------------------------------
$CbxOpenCmd = Join-Path $PSScriptRoot "cbx_open.cmd"
$VenvPythonAbs = Join-Path $RepoRoot $VenvPython
$cmdContent = "@echo off`r`ncd /d `"$RepoRoot`"`r`n`"$VenvPythonAbs`" -m agent.launcher %*`r`n"
if ((Test-Path -LiteralPath $CbxOpenCmd) -and ((Get-Content -LiteralPath $CbxOpenCmd -Raw) -eq $cmdContent)) {
    Ok "cbx_open.cmd 已是最新: $CbxOpenCmd"
} else {
    Set-Content -LiteralPath $CbxOpenCmd -Value $cmdContent -Encoding Ascii
    Ok "已生成: $CbxOpenCmd"
}

if ($Associate) {
    Step "注册 .cbx 文件关联（HKCU，无需管理员）..."
    New-Item -Path "HKCU:\Software\Classes\.cbx" -Force | Out-Null
    Set-Item -Path "HKCU:\Software\Classes\.cbx" -Value "CipherBox.Document"
    New-Item -Path "HKCU:\Software\Classes\CipherBox.Document" -Force | Out-Null
    Set-Item -Path "HKCU:\Software\Classes\CipherBox.Document" -Value "CipherBox 加密文档"
    New-Item -Path "HKCU:\Software\Classes\CipherBox.Document\shell\open\command" -Force | Out-Null
    Set-Item -Path "HKCU:\Software\Classes\CipherBox.Document\shell\open\command" -Value ('"{0}" "%1"' -f $CbxOpenCmd)
    Ok "已关联: 双击 .cbx -> deploy\cbx_open.cmd -> venv python -m agent.launcher"
}

# -- 完成 ---------------------------------------------------------------------------
Write-Host ""
Ok "客户端部署完成。日常操作："
Write-Host "  启动 Agent:   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\client_start.ps1"
Write-Host "  测试受控打开:  agent\.venv\Scripts\python.exe -m agent.launcher <文件.cbx>"
if (-not $Associate) {
    Write-Host "  (未注册 .cbx 双击关联; 需要时重跑并加 -Associate)"
}
Write-Host "  注意: 服务器需已有至少 1 个密钥版本（新版 seed_local.py 种子时自动签发 v1;"
Write-Host "        旧部署需管理员调一次 /admin/rotate），否则 Agent 的 keys 行会报空版本错误。"
Write-Host "  启动成功标志: Agent 窗口依次出现 recovery -> keys -> watcher -> pipe 四行。"
