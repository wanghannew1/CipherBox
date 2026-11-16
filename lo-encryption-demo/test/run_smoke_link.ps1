# run_smoke_link.ps1 -- watchdogged per-phase runner for smoke_link_live.py
# (2026-11-16 priority 1: live smoke of force_encrypt + uno_link_worker on the
# new dev machine's fresh LibreOffice install).
#
# DEDICATED headless soffice (pipe cipherbox-smoke6, own temp profile under
# %TEMP%); NEVER touches cipherbox-service.  Engine registration replicates
# start_soffice.ps1 -- BOTH engine modules (cipherbox.py + cipherbox_crypto.py,
# todo-10 split) are deployed hash-guarded alongside components.rdb + unorc.
#
# Per phase: launch instance -> wait pipe-ready -> run one bundled-python phase
# process with stdout/stderr redirected STRAIGHT TO FILES (WAVE0-LESSONS) ->
# kill the instance so the next phase starts fresh (stale-state guard).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File run_smoke_link.ps1 -Phase 1
#   powershell -NoProfile -ExecutionPolicy Bypass -File run_smoke_link.ps1            # all
#   powershell -NoProfile -ExecutionPolicy Bypass -File run_smoke_link.ps1 -Cleanup

param(
    [int[]]$Phase = @(1, 2, 3, 4, 5, 6),
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"

$Soffice = "C:\Program Files\LibreOffice\program\soffice.exe"
$BundledPython = "C:\Program Files\LibreOffice\program\python.exe"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Script = Join-Path $PSScriptRoot "smoke_link_live.py"
$EngineSrc = Join-Path $PSScriptRoot "..\src\cipherbox.py"
$CryptoSrc = Join-Path $PSScriptRoot "..\src\cipherbox_crypto.py"
$Artifacts = Join-Path $RepoRoot ".omo\start-work\artifacts\smoke-link-live"

$PipeName = "cipherbox-smoke6"
$UnoUrl = "uno:pipe,name=$PipeName;urp;StarOffice.ComponentContext"
$TempRoot = [IO.Path]::GetTempPath().TrimEnd("\")
$ProfileDir = Join-Path $TempRoot "cipherbox-smoke6"
$TmpDir = Join-Path $TempRoot "cipherbox-smoke6-tmp"
$OutRoot = Join-Path $TempRoot "cipherbox-smoke6-out"
$EngineLog = Join-Path $TmpDir "cipherbox-encryption.log"
$ProfileUrl = "file:///" + ($ProfileDir -replace "\\", "/")

$PhaseCapSec = @{ 1 = 90; 2 = 150; 3 = 120; 4 = 90; 5 = 90; 6 = 180 }
$PhaseSlug = @{ 1 = "frames"; 2 = "saveas"; 3 = "ctrls"; 4 = "dialog"; 5 = "guard"; 6 = "worker" }

# -- smoke6 instance process discovery (own instance ONLY) ---------------------

function Get-SmokeSoffice {
    Get-CimInstance Win32_Process -Filter "Name='soffice.exe' OR Name='soffice.bin'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "cipherbox-smoke6" }
}

function Get-SmokePhasePython {
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "smoke_link_live.py" }
}

function Stop-SmokeInstance {
    foreach ($p in @(Get-SmokeSoffice)) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    foreach ($p in @(Get-SmokePhasePython)) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds(25)
    while ((@(Get-SmokeSoffice)).Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
    }
    $left = @(Get-SmokeSoffice)
    if ($left.Count -gt 0) {
        Write-Output "WARNING: smoke instance still alive after kill: $($left.ProcessId -join ', ')"
    }
}

# -- engine registration deploy (replicates start_soffice.ps1; BOTH modules) ----

function Deploy-EngineRegistration {
    $EngineDst = Join-Path $ProfileDir "user\Scripts\python\cipherbox.py"
    $CryptoDst = Join-Path $ProfileDir "user\Scripts\python\cipherbox_crypto.py"
    $ExtDir = Join-Path $ProfileDir "user\extensions\shared\cipherbox"
    $ComponentBackendDir = Join-Path $ProfileDir "user\extensions\shared\registry\com.sun.star.comp.deployment.component.PackageRegistryBackend"
    New-Item -ItemType Directory -Force -Path $ProfileDir, $TmpDir, $OutRoot,
        (Split-Path -Parent $EngineDst), $ExtDir, $ComponentBackendDir | Out-Null

    foreach ($pair in @(
            @{ Src = $EngineSrc; Dst = $EngineDst },
            @{ Src = $CryptoSrc; Dst = $CryptoDst }
        )) {
        if (-not ((Test-Path -LiteralPath $pair.Dst) -and
                  ((Get-FileHash -LiteralPath $pair.Src).Hash -eq (Get-FileHash -LiteralPath $pair.Dst).Hash))) {
            Copy-Item -LiteralPath $pair.Src -Destination $pair.Dst -Force
            Write-Output "engine deployed -> $($pair.Dst)"
        }
    }

    $ModuleUrl = "$ProfileUrl/user/Scripts/python/cipherbox"
    $RdbContent = @"
<?xml version="1.0"?>
<components xmlns="http://openoffice.org/2010/uno-components">
    <component loader="com.sun.star.loader.Python" uri="vnd.openoffice.pymodule:$ModuleUrl">
        <implementation name="com.cipherbox.CipherBoxDataSpace">
            <service name="com.sun.star.comp.oox.crypto.CipherBoxDataSpace"/>
        </implementation>
    </component>
</components>
"@
    $UnorcContent = @'
ORIGIN=$ORIGIN
UNO_SERVICES=?$SHARED_EXTENSIONS_USER/cipherbox/components.rdb
'@
    Set-Content -LiteralPath (Join-Path $ExtDir "components.rdb") -Value $RdbContent -Encoding Ascii
    Set-Content -LiteralPath (Join-Path $ComponentBackendDir "unorc") -Value $UnorcContent -Encoding Ascii
    Write-Output "registration written under $ProfileDir\user\extensions\shared"
}

# -- watchdogged pipe probe (bundled python, tiny output -> safe capture) --------

$ProbeFile = Join-Path ([IO.Path]::GetTempPath()) "cipherbox-smoke6-probe.py"
$ProbeCode = @"
import sys
import uno
local = uno.getComponentContext()
resolver = local.ServiceManager.createInstanceWithContext(
    "com.sun.star.bridge.UnoUrlResolver", local)
try:
    resolver.resolve("$UnoUrl")
    print("RESOLVE: OK")
except Exception as exc:
    print("RESOLVE: FAIL %s: %s" % (type(exc).__name__, exc))
    sys.exit(1)
"@
Set-Content -LiteralPath $ProbeFile -Value $ProbeCode -Encoding Ascii

function Invoke-PipeProbe {
    param([int]$CapSec = 10)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BundledPython
    $psi.Arguments = '"' + $ProbeFile + '"'
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        if (-not $p.WaitForExit($CapSec * 1000)) {
            $p.Kill()
            $p.WaitForExit(5000) | Out-Null
            Write-Output "WARNING: pipe probe killed after $CapSec s"
            return $false
        }
        $null = $p.StandardOutput.ReadToEnd()
        $null = $p.StandardError.ReadToEnd()
        return ($p.ExitCode -eq 0)
    }
    finally {
        $p.Dispose()
    }
}

function Start-SmokeInstance {
    if (Invoke-PipeProbe -CapSec 5) { return }
    Stop-SmokeInstance
    $env:TMP = $TmpDir
    $env:TEMP = $TmpDir
    $proc = Start-Process -FilePath $Soffice -WindowStyle Hidden -PassThru -ArgumentList @(
        "--headless",
        "--norestore",
        "-env:UserInstallation=$ProfileUrl",
        "--accept=pipe,name=$PipeName;urp;"
    )
    Write-Output "smoke instance launched: launcher PID $($proc.Id)"
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (Invoke-PipeProbe -CapSec 8) { Write-Output "smoke instance ready"; return }
        Start-Sleep -Seconds 2
    }
    throw "smoke pipe did not become resolvable within 60 s"
}

# -- phase execution (Start-Process file redirect, watchdog kill) ----------------

function Invoke-Phase {
    param([int]$N)
    $cap = $PhaseCapSec[$N]
    $slug = $PhaseSlug[$N]
    $outFile = Join-Path $Artifacts ("transcript-p{0}-{1}.txt" -f $N, $slug)
    $errFile = "$outFile.err"
    $argList = '"' + $Script + '" --phase ' + $N + ' --url "' + $UnoUrl + '"' +
        ' --out "' + $OutRoot + '" --engine-log "' + $EngineLog + '"' +
        ' --pipe "' + $PipeName + '"'
    Write-Host "--- phase $N ($slug), cap ${cap}s -> $outFile"
    $env:PYTHONIOENCODING = "utf-8"
    $env:PYTHONUTF8 = "1"
    $p = Start-Process -FilePath $BundledPython -ArgumentList $argList -WindowStyle Hidden `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru
    if (-not $p.WaitForExit($cap * 1000)) {
        $p.Kill()
        $p.WaitForExit(5000) | Out-Null
        Add-Content -LiteralPath $outFile -Value ("RUNNER-WATCHDOG: phase killed after {0}s (hang IS the finding)" -f $cap)
        Write-Host "phase ${N}: WATCHDOG-KILLED after ${cap}s"
        return -1
    }
    $p.WaitForExit() | Out-Null
    # PS5.1 quirk: ExitCode stays $null with -RedirectStandardOutput; the
    # transcript's own RESULT line is the authority (no misleading success).
    # The phase python's stdio handles can outlive its exit by a tick on
    # Windows -- retry the read instead of failing the phase on a lock race.
    $passed = $false
    foreach ($i in 1..5) {
        try {
            $passed = [bool](Select-String -LiteralPath $outFile -Pattern "^RESULT: PASS" -Quiet)
            break
        } catch [System.IO.IOException] {
            Start-Sleep -Milliseconds 400
        }
    }
    Write-Host ("phase ${N}: " + $(if ($passed) { "PASS" } else { "FAIL (see transcript)" }))
    return $(if ($passed) { 0 } else { 1 })
}

# -- main -----------------------------------------------------------------------

if ($Cleanup) {
    Stop-SmokeInstance
    foreach ($d in @($OutRoot, $TmpDir, $ProfileDir)) {
        if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    Write-Output "cleanup done: instance killed, out/tmp/profile dirs removed"
    exit 0
}

New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null
Deploy-EngineRegistration

$results = @{}
foreach ($n in $Phase) {
    try {
        Start-SmokeInstance
        $results[$n] = Invoke-Phase -N $n
    }
    catch {
        Write-Output "phase ${n}: RUNNER ERROR $_"
        $results[$n] = -2
    }
    finally {
        Stop-SmokeInstance
    }
}

Write-Output ""
Write-Output ("summary: " + (($results.GetEnumerator() | Sort-Object Name | ForEach-Object { "p$($_.Name)=$($_.Value)" }) -join " "))
