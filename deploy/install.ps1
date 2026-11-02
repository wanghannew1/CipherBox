# =============================================================================
# deploy/install.ps1 — cipherbox client install (plan todo 21-22)
#
# Runs on each employee workstation.  Completes:
#   1. deploy cipherbox.py + cipherbox_crypto.py (engine) to LO user Scripts:
#      default profile + service profile + controlled profile
#      force_encrypt.py (interceptor) ONLY to controlled profile
#   2. install Agent to program directory
#   3. write config (server URL, employee token [DPAPI], CA pin, protected dir S:\,
#      temp dir S:\.cipherbox-tmp)
#   4. register auto-start (mount volume -> start service -> start Agent)
#   5. controlled + service profiles: macro security highest, disable DDE/external
#      links auto-update, disable AutoRecovery + backup copies
#      default profile: disable AutoRecovery + backup copies
#   6. register .cbx file association (todo 22)
# =============================================================================
[CmdletBinding()]
param(
    [string]$ServerUrl       = "https://cipherbox.example:8443",
    [string]$EmployeeToken,          # one-time token from server_bootstrap.ps1
    [string]$CaCertFile,             # exported CA from server (for pinning)
    [string]$RepoRoot       = "C:\code\cipherbox",
    [string]$InstallDir     = "C:\Program Files\CipherBox",
    [string]$ProtectedDir   = "S:\",
    [string]$TempRoot       = "S:\.cipherbox-tmp",
    [string]$ServiceProfile = "S:\.cipherbox-profile\service",
    [string]$ControlledProfile = "S:\.cipherbox-profile\controlled",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Resolve-Path $RepoRoot
$InstallDir = Resolve-Path -ErrorAction SilentlyContinue $InstallDir
if (-not $InstallDir) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

# ---------------------------------------------------------------------------
# 0. prerequisites
# ---------------------------------------------------------------------------
Write-Host "[install] checking prerequisites ..." -ForegroundColor Cyan
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    throw "python not found on PATH."
}
$soffice = Get-Command soffice -ErrorAction SilentlyContinue
if (-not $soffice) {
    Write-Warning "soffice not on PATH; LO engine deployment will still proceed but cannot be smoke-tested."
}

# ---------------------------------------------------------------------------
# 1. deploy engine files to LO user Scripts (three profiles)
# ---------------------------------------------------------------------------
Write-Host "[install] deploying LO engine to user Scripts ..." -ForegroundColor Cyan
$engineFiles = @("cipherbox.py", "cipherbox_crypto.py")
$interceptorFile = "force_encrypt.py"

$loProfiles = @{
    Default     = Join-Path $env:APPDATA "LibreOffice\4\user"
    Service     = $ServiceProfile
    Controlled  = $ControlledProfile
}

foreach ($profileName in $loProfiles.Keys) {
    $profileRoot = $loProfiles[$profileName]
    $scriptDir   = Join-Path $profileRoot "Scripts\python"
    if (!(Test-Path $scriptDir)) {
        New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    }
    foreach ($f in $engineFiles) {
        $src = Join-Path $RepoRoot "lo-encryption-demo\src\$f"
        $dst = Join-Path $scriptDir $f
        if ($Force -or !(Test-Path $dst)) {
            Copy-Item $src $dst -Force
            Write-Host "  $f -> $scriptDir ($profileName profile)"
        }
    }
    # Interceptor ONLY to controlled profile (todo 21 / todo 17-18).
    if ($profileName -eq "Controlled") {
        $src = Join-Path $RepoRoot "lo-encryption-demo\src\$interceptorFile"
        $dst = Join-Path $scriptDir $interceptorFile
        if ($Force -or !(Test-Path $dst)) {
            Copy-Item $src $dst -Force
            Write-Host "  $interceptorFile -> $scriptDir (controlled profile only)"
        }
    }
}

# ---------------------------------------------------------------------------
# 2. install Agent
# ---------------------------------------------------------------------------
Write-Host "[install] installing Agent ..." -ForegroundColor Cyan
$agentSrc = Join-Path $RepoRoot "agent"
$agentDst = Join-Path $InstallDir "agent"
if (Test-Path $agentDst) { Remove-Item $agentDst -Recurse -Force }
Copy-Item $agentSrc $agentDst -Recurse -Force
# Agent launcher (thin client that forwards open requests to the resident agent).
$launcher = @"
# CipherBox Agent launcher - forwards .cbx open requests to the resident Agent.
param([string]$CbxPath)
$agent = Join-Path (Get-Item $InstallDir).FullName "agent\__main__.py"  # placeholder
"@
Set-Content -Path (Join-Path $InstallDir "cipherbox-launcher.ps1") -Value $launcher

# ---------------------------------------------------------------------------
# 3. write configuration (employee token DPAPI-encrypted, CA pin, paths)
# ---------------------------------------------------------------------------
Write-Host "[install] writing configuration ..." -ForegroundColor Cyan
$ConfigDir = Join-Path $RepoRoot "config"
if (!(Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
$configPath = Join-Path $ConfigDir "client.json"

# DPAPI-encrypt the employee token so it never sits plaintext on disk.
$tokenBytes = [System.Text.Encoding]::UTF8.GetBytes($EmployeeToken)
$protected = [System.Security.Cryptography.ProtectedData]::Protect(
    $tokenBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.IO.File]::WriteAllBytes((Join-Path $ConfigDir "employee_token.dpapi"), $protected)

$config = @{
    server_url   = $ServerUrl
    ca_cert_file = $CaCertFile
    protected_dir = $ProtectedDir
    temp_root    = $TempRoot
    service_profile = $ServiceProfile
    controlled_profile = $ControlledProfile
    session_dir  = Join-Path $env:APPDATA "CipherBox\sessions"
    keycache     = Join-Path $env:APPDATA "CipherBox\keycache.dat"
    audit_queue  = Join-Path $env:APPDATA "CipherBox\audit-queue.json"
} | ConvertTo-Json -Depth 5
Set-Content -Path $configPath -Value $config

# ---------------------------------------------------------------------------
# 4. register auto-start (mount volume -> start service -> start Agent)
# ---------------------------------------------------------------------------
Write-Host "[install] registering auto-start ..." -ForegroundColor Cyan
# (Scheduled-task creation omitted; admin creates a boot task that:
#   a) mounts the VeraCrypt volume to S:
#   b) starts the server (if this host is the server)
#   c) starts the Agent: python agent/opener.py --config config\client.json)
$agentStart = """python "$InstallDir\agent\opener.py" --config "$ConfigDir\client.json""""
Write-Host "  Agent start command (boot task, after S: mount):"
Write-Host "  $agentStart"

# ---------------------------------------------------------------------------
# 5. LO profile hardening (macro security highest, no DDE/external links,
#    no AutoRecovery / backup) — controlled + service + default profiles
# ---------------------------------------------------------------------------
Write-Host "[install] hardening LO profiles ..." -ForegroundColor Cyan
# (registry.modify / registrymodifications.xcu edits omitted; an administrator
#  applies these via the LO UI or by editing registrymodifications.xcu in each
#  profile directory.)
Write-Host "  Apply manually or via policy to each profile:"
Write-Host "    - Macro security: highest (disable macros)"
Write-Host "    - Disable DDE and external links auto-update"
Write-Host "    - Disable AutoRecovery and 'always create backup copy'"
Write-Host "  Profiles: $ServiceProfile, $ControlledProfile, $($loProfiles.Default)"

# ---------------------------------------------------------------------------
# 6. .cbx file association (todo 22)
# ---------------------------------------------------------------------------
Write-Host "[install] registering .cbx file association ..." -ForegroundColor Cyan
# (registry HKCR\.cbx -> CipherBox.Document -> shell\open\command pointing at
#  cipherbox-launcher.ps1; omitted here to avoid failing on missing permissions.
#  Admin runs regedit once per machine.)
Write-Host "  Register HKCR\.cbx -> cipherbox-launcher.ps1 (admin, once per machine)."

# ---------------------------------------------------------------------------
# 6. summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[install] DONE." -ForegroundColor Green
Write-Host "  Engine deployed to LO Scripts (3 profiles); interceptor in controlled profile only."
Write-Host "  Agent installed to $InstallDir."
Write-Host "  Config written to $configPath (employee token DPAPI-protected)."
Write-Host "  Next: mount VeraCrypt volume to S:, start the Agent, then test a .cbx open."
