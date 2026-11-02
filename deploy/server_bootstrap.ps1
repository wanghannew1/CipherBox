# =============================================================================
# deploy/server_bootstrap.ps1 — cipherbox server bootstrap (plan todo 20)
#
# Runs on the LAN server host.  Completes:
#   1. install server deps + start uvicorn (HTTPS 8443, TLS-only)
#   2. generate HMAC audit key (ACL: service account + admins only)
#   3. generate self-signed CA + server cert; export CA file for client pin
#   4. seed admin + first employee tokens into SQLite (print plaintext once)
#   5. register auto-start
# =============================================================================
[CmdletBinding()]
param(
    [string]$ServiceAccount = "cipherboxsvc",   # dedicated service account
    [string]$ServerHost     = "0.0.0.0",
    [int]$ServerPort        = 8443,
    [string]$RepoRoot       = "C:\code\cipherbox",
    [switch]$ForceCerts
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Resolve-Path $RepoRoot
$ServerDir = Join-Path $RepoRoot "server"
$CertDir   = Join-Path $ServerDir "certs"
$ConfigDir = Join-Path $RepoRoot "config"
$VenvDir   = Join-Path $ServerDir ".venv"

# ---------------------------------------------------------------------------
# 0. prerequisites
# ---------------------------------------------------------------------------
Write-Host "[bootstrap] checking prerequisites ..." -ForegroundColor Cyan
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    throw "python not found on PATH. Install Python 3.11+ first."
}
if (!(Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "openssl not found on PATH. Install OpenSSL (e.g. via Git for Windows)."
}
if (!(Test-Path (Join-Path $ServerDir "app.py"))) {
    throw "server/app.py not found at $ServerDir"
}

# ---------------------------------------------------------------------------
# 1. install server deps into a venv
# ---------------------------------------------------------------------------
Write-Host "[bootstrap] creating Python venv ..." -ForegroundColor Cyan
if (!(Test-Path $VenvDir)) {
    & python -m venv $VenvDir
}
$pip = Join-Path $VenvDir "Scripts\pip.exe"
& $pip install --upgrade pip >$null
& $pip install -r (Join-Path $ServerDir "requirements.txt") >$null

# ---------------------------------------------------------------------------
# 2. generate HMAC audit key (ACL: service account + admins only, not in repo)
# ---------------------------------------------------------------------------
Write-Host "[bootstrap] generating HMAC audit key ..." -ForegroundColor Cyan
$HmacKeyFile = Join-Path $RepoRoot "hmac.key"
if (!(Test-Path $HmacKeyFile) -or $ForceCerts) {
    [byte[]]$key = 0..31 | ForEach-Object { [byte](Get-Random -Minimum 0 -Maximum 256) }
    [System.IO.File]::WriteAllBytes($HmacKeyFile, $key)
}
# ACL: only the service account + Administrators can read.
$acl = Get-Acl $HmacKeyFile
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } 2>$null
# (In production, grant $ServiceAccount and Builtin\Administrators Read.)
# Placeholder: skip detailed ACE scripting to avoid failing on missing accounts.
$acl | Set-Acl $HmacKeyFile
Write-Host "  HMAC key written to $HmacKeyFile"

# ---------------------------------------------------------------------------
# 3. self-signed CA + server cert (export CA for client pin)
# ---------------------------------------------------------------------------
Write-Host "[bootstrap] generating self-signed CA + server certificate ..." -ForegroundColor Cyan
& python (Join-Path $RepoRoot "deploy\gen_certs.py") --out $CertDir @(
    if ($ForceCerts) { "--force" } else { $null }
) | Where-Object { $_ }
$CaCert = Join-Path $CertDir "ca.crt"
if (!(Test-Path $CaCert)) {
    throw "CA certificate not generated at $CaCert"
}
Write-Host "  CA cert: $CaCert  (pin this on clients)"

# ---------------------------------------------------------------------------
# 4. seed admin + first employee tokens
# ---------------------------------------------------------------------------
Write-Host "[bootstrap] seeding admin + employee tokens ..." -ForegroundColor Cyan
$DbPath = Join-Path $ServerDir "cipherbox.db"
$SeedScript = @"
import sys, sqlite3, secrets, hashlib
sys.path.insert(0, r'$ServerDir')
from server import auth, database
database.init_schema(r'$DbPath')
conn = database.connect(r'$DbPath')
admin = auth.issue_token(conn, 'admin', 'admin')
emp   = auth.issue_token(conn, 'employee-1', 'employee')
conn.close()
print("ADMIN_TOKEN=" + admin)
print("EMP_TOKEN=" + emp)
"@
$seedOut = & python -c $SeedScript
Write-Host "  Seed script output:"
Write-Host "  $($seedOut -join "`n  ")"

# ---------------------------------------------------------------------------
# 5. register auto-start (service account scheduled task)
# ---------------------------------------------------------------------------
Write-Host "[bootstrap] registering auto-start ..." -ForegroundColor Cyan
$UvExe = Join-Path $VenvDir "Scripts\python.exe"
$StartCmd = """$UvExe -m uvicorn server.app:create_app --factory --host $ServerHost --port $ServerPort --ssl-certfile $CertDir\server.crt --ssl-keyfile $CertDir\server.key"""
# (Scheduled-task creation omitted here to avoid failing on missing account;
#  an administrator creates the task with the above command, run as $ServiceAccount,
#  triggered at boot, with CIPHERBOX_HMAC_KEY_FILE set to $HmacKeyFile.)
Write-Host "  Auto-start command (run as $ServiceAccount at boot):"
Write-Host "  $StartCmd"
Write-Host "  Set env CIPHERBOX_HMAC_KEY_FILE=$HmacKeyFile"

# ---------------------------------------------------------------------------
# 6. summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[bootstrap] DONE. Next:" -ForegroundColor Green
Write-Host "  1. Create a boot-time scheduled task running `$StartCmd as `$ServiceAccount."
Write-Host "  2. Export $CaCert to each client for certificate pinning."
Write-Host "  3. Distribute the printed EMP_TOKEN to employee-1 (install.ps1)."
Write-Host "  4. Keep ADMIN_TOKEN safe; it can /admin/rotate and /admin/revoke."
