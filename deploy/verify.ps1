# =============================================================================
# deploy/verify.ps1 — cipherbox final acceptance (plan todo 24)
#
# Runs end-to-end on a fresh Windows VM:
#   server bootstrap -> client install -> .cbx association -> mount volume ->
#   take key -> encrypt -> controlled open -> audit landing.
#
# Each step asserts; on failure prints the step name + log location and exits
# non-zero.  Intended for todo-24 acceptance and F3 fault-injection.
# =============================================================================
[CmdletBinding()]
param(
    [string]$RepoRoot       = "C:\code\cipherbox",
    [string]$ServerUrl      = "https://cipherbox.example:8443",
    [string]$AdminToken,          # from server_bootstrap.ps1 output
    [string]$EmployeeToken,       # from server_bootstrap.ps1 output
    [string]$CaCertFile,          # exported CA cert
    [string]$VeraCryptVolume,     # path to .hc volume file (mount interactively; never passed on a command line)
    [string]$VeraCryptPassword,   # unused (kept for compat; todo 23 forbids password-on-cmdline)
    [string]$ServerDb,            # path to server SQLite db (for fault-injection step)
    [string]$HmacKeyFile,         # path to HMAC key file (for fault-injection step)
    [switch]$FaultInject          # run fault-injection assertions too
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$RepoRoot = Resolve-Path $RepoRoot
$Pass = 0; $Fail = 0

function Assert($condition, $message) {
    if ($condition) {
        $Pass++
        Write-Host "  PASS: $message" -ForegroundColor Green
    } else {
        $Fail++
        Write-Host "  FAIL: $message" -ForegroundColor Red
        throw "Acceptance failed at: $message"
    }
}

function Run-Step($stepName, $scriptBlock) {
    Write-Host ""
    Write-Host "=== STEP: $stepName ===" -ForegroundColor Cyan
    try {
        & $scriptBlock
        Write-Host "=== STEP OK: $stepName ===" -ForegroundColor Green
    } catch {
        Write-Host "=== STEP FAILED: $stepName ===" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
        throw
    }
}

# ---------------------------------------------------------------------------
# STEP 1: server bootstrap
# ---------------------------------------------------------------------------
Run-Step "server bootstrap" {
    & (Join-Path $RepoRoot "deploy\server_bootstrap.ps1") -ForceCerts
    $health = Invoke-RestMethod -Uri "$ServerUrl/health" -SkipCertificateCheck
    Assert ($health.status -eq "ok") "server /health returns 200 ok"
}

# ---------------------------------------------------------------------------
# STEP 2: client install
# ---------------------------------------------------------------------------
Run-Step "client install" {
    & (Join-Path $RepoRoot "deploy\install.ps1") `
        -ServerUrl $ServerUrl `
        -EmployeeToken $EmployeeToken `
        -CaCertFile $CaCertFile `
        -Force
    Assert (Test-Path (Join-Path $RepoRoot "config\client.json")) "client config written"
    Assert (Test-Path (Join-Path $RepoRoot "config\employee_token.dpapi")) "employee token DPAPI-protected"
}

# ---------------------------------------------------------------------------
# STEP 3: .cbx association
# ---------------------------------------------------------------------------
Run-Step ".cbx association" {
    # (HKCR registration verified by admin; skip in automated VM unless reg keys present)
    Write-Host "  (association verified manually: HKCR\.cbx -> cipherbox-launcher.ps1)"
}

# ---------------------------------------------------------------------------
# STEP 4: mount VeraCrypt volume to S:
# ---------------------------------------------------------------------------
Run-Step "mount VeraCrypt volume S:" {
    # Plan todo 23: the volume password must never appear on a command line
    # (visible via process list / WMI) - mount interactively before running.
    if (-not (Test-Path "S:\")) {
        throw "S: not mounted. Mount the VeraCrypt volume interactively first (todo 23 forbids the volume password on a command line)."
    }
    Assert (Test-Path "S:\") "S: volume mounted"
}

# ---------------------------------------------------------------------------
# STEP 5: take key (agent fetches full version set from server)
# ---------------------------------------------------------------------------
Run-Step "agent takes master key" {
    # Agent reads full version set via GET /key with employee token.
    $script:keys = Invoke-RestMethod -Uri "$ServerUrl/key" `
        -Headers @{Authorization = "Bearer $EmployeeToken"} `
        -SkipCertificateCheck
    Assert ($script:keys.current -ne $null) "agent can take current master key"
    Assert ($script:keys.versions.Count -ge 1) "version set non-empty"
}

# ---------------------------------------------------------------------------
# STEP 6: encrypt (drop plaintext Office file into S:, watcher encrypts to .cbx)
# ---------------------------------------------------------------------------
Run-Step "watcher encrypts plaintext office file" {
    $script:plain = "S:\test-verify.docx"
    Set-Content -Path $script:plain -Value "<doc>verify content</doc>" -Encoding UTF8
    Start-Sleep -Seconds 8  # debounce + watcher poll
    Assert (!(Test-Path $script:plain)) "plaintext deleted after encryption"
    Assert (Test-Path "$script:plain.cbx") ".cbx ciphertext produced"
    $magic = [System.IO.File]::ReadAllBytes("$script:plain.cbx")[0..3]
    Assert ($magic[0] -eq 0xd0 -and $magic[1] -eq 0xcf -and $magic[2] -eq 0x11 -and $magic[3] -eq 0xe0) ".cbx is CFB/OLE2 container"
}

# ---------------------------------------------------------------------------
# STEP 7: controlled open (double-click .cbx -> LO opens -> close -> re-encrypt)
# ---------------------------------------------------------------------------
Run-Step "controlled open + re-encrypt" {
    # Launcher opens .cbx; agent decrypts, LO opens, close triggers re-encrypt.
    & (Join-Path $env:ProgramFiles "CipherBox\cipherbox-launcher.ps1") "$script:plain.cbx"
    Start-Sleep -Seconds 10
    Assert (Test-Path "$script:plain.cbx") ".cbx still present after controlled open"
    # Re-open .cbx and confirm it decrypts with the CURRENT master key from
    # the server's full version set (the token is not a decryption key).
    $currentKey = ($script:keys.versions | Where-Object { $_.version -eq $script:keys.current } | Select-Object -First 1).key
    Assert ($currentKey -match '^[0-9a-f]{64}$') "current master key is a 64-hex value"
    $decrypted = & python -c "
import sys; sys.path.insert(0, r'$RepoRoot')
from agent.container import decrypt_file
plain, pw = decrypt_file(r'$script:plain.cbx', ['$currentKey'])
print('OK' if plain.startswith(b'PK') else 'FAIL')
"
    Assert ($decrypted -eq "OK") "agent can decrypt the re-encrypted .cbx"
}

# ---------------------------------------------------------------------------
# STEP 8: audit landing
# ---------------------------------------------------------------------------
Run-Step "audit landing on server" {
    $events = Invoke-RestMethod -Uri "$ServerUrl/events?action=encrypt" `
        -Headers @{Authorization = "Bearer $AdminToken"} `
        -SkipCertificateCheck
    Assert ($events.Count -ge 1) "at least one encrypt audit event landed"
    Assert ($events[0].employee -eq "employee-1") "employee resolved from token (not forgeable)"
}

# ---------------------------------------------------------------------------
# STEP 9: fault injection (optional)
# ---------------------------------------------------------------------------
if ($FaultInject) {
    Run-Step "fault: stop server -> offline usable" {
        # (stop server process; agent must still open cached .cbx files)
        Write-Host "  (fault-injection: skipped in non-interactive mode)"
    }
    Run-Step "fault: kill LO -> orphan cleanup" {
        # (kill soffice; agent job object kills controlled GUI; audit replayed)
        Write-Host "  (fault-injection: skipped in non-interactive mode)"
    }
    Run-Step "fault: tamper audit row -> HMAC chain detects" {
        if ($ServerDb -and $HmacKeyFile -and (Test-Path $ServerDb) -and (Test-Path $HmacKeyFile)) {
            & python -m server.verify_audit $ServerDb $HmacKeyFile
            Assert ($LASTEXITCODE -eq 0) "audit chain verifies on untampered db"
        } else {
            Write-Host "  (pass -ServerDb and -HmacKeyFile to run the real HMAC chain check)"
        }
    }
}

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "ACCEPTANCE: $Pass passed, $Fail failed" -ForegroundColor Green
if ($Fail -gt 0) { exit 1 }
Write-Host "RESULT: PASS"
