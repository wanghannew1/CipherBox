<#
run_spike_interceptor.ps1 -- watchdogged per-phase runner for spike_interceptor.py
(Wave 0 todo 4).  Uses a DEDICATED headless soffice (pipe cipherbox-spike4, own
temp profile under %TEMP%); NEVER touches the shared cipherbox-service instance.

Per phase: launch instance -> wait pipe-ready -> run one bundled-python phase
process with stdout/stderr redirected STRAIGHT TO FILES (WAVE0-LESSONS: .NET
Process + redirected pipes deadlock on >4KB output; Start-Process
-RedirectStandardOutput writes the file itself) -> kill the instance and wait
for exit so the next phase starts from a fresh instance (stale-state guard).

Engine registration replicates start_soffice.ps1: the profile's
user\extensions\shared\cipherbox\components.rdb maps the service to the Python
loader + module URL, and the component PackageRegistryBackend's unorc points the
service manager at that RDB.  A bare module copy does NOT register the service.

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File run_spike_interceptor.ps1 -Phase 1
  powershell -NoProfile -ExecutionPolicy Bypass -File run_spike_interceptor.ps1            # all phases
  powershell -NoProfile -ExecutionPolicy Bypass -File run_spike_interceptor.ps1 -Cleanup   # kill + wipe temp state
#>

param(
    [int[]]$Phase = @(1, 2, 3, 4, 5, 6, 7, 8, 9),
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"

$Soffice = "C:\Program Files\LibreOffice\program\soffice.exe"
$BundledPython = "C:\Program Files\LibreOffice\program\python.exe"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Script = Join-Path $PSScriptRoot "spike_interceptor.py"
$EngineSrc = Join-Path $PSScriptRoot "..\src\cipherbox.py"
$Artifacts = Join-Path $RepoRoot ".omo\start-work\artifacts\todo-04"

$PipeName = "cipherbox-spike4"
$UnoUrl = "uno:pipe,name=$PipeName;urp;StarOffice.ComponentContext"
$TempRoot = [IO.Path]::GetTempPath().TrimEnd("\")  # C:\Users\22419\AppData\Local\Temp
$ProfileDir = Join-Path $TempRoot "cipherbox-spike4"
$TmpDir = Join-Path $TempRoot "cipherbox-spike4-tmp"
$OutRoot = Join-Path $TempRoot "cipherbox-spike4-out"
$ProfileUrl = "file:///" + ($ProfileDir -replace "\\", "/")

$PhaseCapSec = @{ 1 = 60; 2 = 120; 3 = 90; 4 = 90; 5 = 90; 6 = 90; 7 = 120; 8 = 120; 9 = 90 }
$PhaseSlug = @{ 1 = "basic"; 2 = "saveas"; 3 = "secondframe"; 4 = "discovery"; 5 = "reverse";
                6 = "saveacopy"; 7 = "save-after-saveas"; 8 = "exportfamily"; 9 = "saveall" }

# -- spike4 instance process discovery (own instance ONLY) --------------------

function Get-Spike4Soffice {
    Get-CimInstance Win32_Process -Filter "Name='soffice.exe' OR Name='soffice.bin'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "cipherbox-spike4" }
}

function Stop-Spike4Instance {
    foreach ($p in @(Get-Spike4Soffice)) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    $deadline = (Get-Date).AddSeconds(25)
    while ((@(Get-Spike4Soffice)).Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
    }
    $left = @(Get-Spike4Soffice)
    if ($left.Count -gt 0) {
        Write-Output "WARNING: spike4 instance still alive after kill: $($left.ProcessId -join ', ')"
    }
}

# -- engine registration deploy (replicates start_soffice.ps1) -----------------

function Deploy-EngineRegistration {
    $EngineDst = Join-Path $ProfileDir "user\Scripts\python\cipherbox.py"
    $ExtDir = Join-Path $ProfileDir "user\extensions\shared\cipherbox"
    $ComponentBackendDir = Join-Path $ProfileDir "user\extensions\shared\registry\com.sun.star.comp.deployment.component.PackageRegistryBackend"
    New-Item -ItemType Directory -Force -Path $ProfileDir, $TmpDir, $OutRoot,
        (Split-Path -Parent $EngineDst), $ExtDir, $ComponentBackendDir | Out-Null

    if (-not ((Test-Path -LiteralPath $EngineDst) -and
              ((Get-FileHash -LiteralPath $EngineSrc).Hash -eq (Get-FileHash -LiteralPath $EngineDst).Hash))) {
        Copy-Item -LiteralPath $EngineSrc -Destination $EngineDst -Force
        Write-Output "engine deployed -> $EngineDst"
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

# -- watchdogged pipe probe (bundled python, tiny output -> safe capture) -------

$ProbeFile = Join-Path ([IO.Path]::GetTempPath()) "cipherbox-spike4-probe.py"
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

function Start-Spike4Instance {
    if (Invoke-PipeProbe -CapSec 5) { return }
    Stop-Spike4Instance
    $env:TMP = $TmpDir
    $env:TEMP = $TmpDir
    $proc = Start-Process -FilePath $Soffice -WindowStyle Hidden -PassThru -ArgumentList @(
        "--headless",
        "--norestore",
        "-env:UserInstallation=$ProfileUrl",
        "--accept=pipe,name=$PipeName;urp;"
    )
    Write-Output "spike4 launched: launcher PID $($proc.Id)"
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (Invoke-PipeProbe -CapSec 8) { Write-Output "spike4 ready"; return }
        Start-Sleep -Seconds 2
    }
    throw "spike4 pipe did not become resolvable within 60 s"
}

# -- phase execution (Start-Process file redirect, watchdog kill) ---------------

function Invoke-Phase {
    param([int]$N)
    $cap = $PhaseCapSec[$N]
    $slug = $PhaseSlug[$N]
    $outFile = Join-Path $Artifacts ("transcript-p{0}-{1}.txt" -f $N, $slug)
    $errFile = "$outFile.err"
    $argList = '"' + $Script + '" --phase ' + $N + ' --url "' + $UnoUrl + '" --out "' + $OutRoot + '"'
    Write-Host "--- phase $N ($slug), cap ${cap}s -> $outFile"
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
    $passed = [bool](Select-String -LiteralPath $outFile -Pattern "^RESULT: PASS" -Quiet)
    Write-Host ("phase ${N}: " + $(if ($passed) { "PASS" } else { "FAIL (see transcript)" }))
    return $(if ($passed) { 0 } else { 1 })
}

# -- main -----------------------------------------------------------------------

if ($Cleanup) {
    Stop-Spike4Instance
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
        Start-Spike4Instance
        $results[$n] = Invoke-Phase -N $n
    }
    catch {
        Write-Output "phase ${n}: RUNNER ERROR $_"
        $results[$n] = -2
    }
    finally {
        Stop-Spike4Instance
    }
}

Write-Output ""
Write-Output ("summary: " + (($results.GetEnumerator() | Sort-Object Name | ForEach-Object { "p$($_.Name)=$($_.Value)" }) -join " "))
