<#
start_soffice.ps1 -- persistent headless LibreOffice service over a UNO named pipe.

Starts (or reuses) a dedicated headless soffice bound to the service profile inside
the S: volume, accepting UNO connections on the named pipe `cipherbox-service`.
Unlike loopback TCP, a Windows named pipe is scoped by the OS to the creating user
(NT DACL), which is exactly the per-user isolation this service wants.

The CipherBoxDataSpace engine (src/cipherbox.py) is deployed into the service
profile's user Scripts/python together with its UNO service registration
(extensions/shared/cipherbox/components.rdb + the component backend's unorc --
a bare module copy does not register the service), and TMP/TEMP are pointed at
the in-volume service temp dir so the engine's component log lands on the volume.

Idempotent by design:
  * profile/tmp dirs are created only if missing; the engine is copied only when
    the deployed file differs from src
  * if the pipe already resolves, prints "already listening" and exits 0
  * if a soffice with our service profile exists but the pipe is not ready yet,
    waits for it (up to -ExistingWaitTimeoutSec) and never starts a second one

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File start_soffice.ps1
#>

param(
    [string]$Soffice = "C:\Program Files\LibreOffice\program\soffice.exe",
    [string]$BundledPython = "C:\Program Files\LibreOffice\program\python.exe",
    [string]$Volume = "S:\",
    [int]$LaunchReadinessTimeoutSec = 60,
    [int]$ExistingWaitTimeoutSec = 120
)

$ErrorActionPreference = "Stop"

$PipeName = "cipherbox-service"
$UnoUrl = "uno:pipe,name=$PipeName;urp;StarOffice.ComponentContext"

$vol = $Volume.TrimEnd("\")
$ProfileDir = "$vol\.cipherbox-profile\service"
$TmpDir = "$vol\.cipherbox-tmp\service"
$ProfileUrl = "file:///$vol/.cipherbox-profile/service"
$EngineSrc = Join-Path $PSScriptRoot "src\cipherbox.py"
$EngineDst = Join-Path $ProfileDir "user\Scripts\python\cipherbox.py"

# -- prerequisites ----------------------------------------------------------

if (-not (Test-Path -LiteralPath "$vol\")) {
    Write-Output "ERROR: volume $vol is not mounted; mount it before starting the service."
    exit 1
}
foreach ($p in @($Soffice, $BundledPython, $EngineSrc)) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Output "ERROR: required path not found: $p"
        exit 1
    }
}

# -- idempotent dirs + engine/registration deployment -------------------------
#
# Registration mirrors the default profile's hand-installed shared extension:
# the component PackageRegistryBackend's unorc points the service manager at
# cipherbox/components.rdb, which maps the service name to the Python loader and
# the module URL (vnd.openoffice.pymodule:<profile>/user/Scripts/python/cipherbox).
# A bare module copy does NOT register the service -- the RDB + unorc are required.

$ExtDir = Join-Path $ProfileDir "user\extensions\shared\cipherbox"
$ComponentBackendDir = Join-Path $ProfileDir "user\extensions\shared\registry\com.sun.star.comp.deployment.component.PackageRegistryBackend"
New-Item -ItemType Directory -Force -Path $ProfileDir, $TmpDir, (Split-Path -Parent $EngineDst), $ExtDir, $ComponentBackendDir | Out-Null

if ((Test-Path -LiteralPath $EngineDst) -and
    ((Get-FileHash -LiteralPath $EngineSrc).Hash -eq (Get-FileHash -LiteralPath $EngineDst).Hash)) {
    Write-Output "engine deployment unchanged: $EngineDst"
}
else {
    Copy-Item -LiteralPath $EngineSrc -Destination $EngineDst -Force
    Write-Output "engine deployed: $EngineSrc -> $EngineDst"
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

function Set-ContentIfChanged {
    param([string]$Path, [string]$Value)
    $current = $null
    if (Test-Path -LiteralPath $Path) {
        $current = ((Get-Content -LiteralPath $Path -Raw) -replace "`r`n", "`n").TrimEnd("`n")
    }
    $desired = ($Value -replace "`r`n", "`n").TrimEnd("`n")
    if ($current -eq $desired) {
        Write-Output "registration unchanged: $Path"
    }
    else {
        Set-Content -LiteralPath $Path -Value $Value -Encoding Ascii
        Write-Output "registration written: $Path"
    }
}

Set-ContentIfChanged -Path (Join-Path $ExtDir "components.rdb") -Value $RdbContent
Set-ContentIfChanged -Path (Join-Path $ComponentBackendDir "unorc") -Value $UnorcContent

# -- watchdogged pipe probe (bundled python) ---------------------------------

$ProbeFile = Join-Path ([IO.Path]::GetTempPath()) "cipherbox-$PipeName-probe.py"
$ProbeCode = @"
import sys
import uno
url = "uno:pipe,name=$PipeName;urp;StarOffice.ComponentContext"
local = uno.getComponentContext()
resolver = local.ServiceManager.createInstanceWithContext(
    "com.sun.star.bridge.UnoUrlResolver", local)
try:
    resolver.resolve(url)
    print("RESOLVE: OK " + url)
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
            Write-Output "WARNING: probe watchdog: resolve probe killed after $CapSec s (hung bridge call)"
            return $false
        }
        return ($p.ExitCode -eq 0)
    }
    finally {
        $p.Dispose()
    }
}

function Get-ServiceSoffice {
    Get-CimInstance Win32_Process -Filter "Name='soffice.exe' OR Name='soffice.bin'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "cipherbox-profile[\\/]service" }
}

# -- already listening? ------------------------------------------------------

if (Invoke-PipeProbe -CapSec 10) {
    Write-Output "already listening: $UnoUrl resolves (probe ok)"
    exit 0
}

# -- launch (or wait for an existing instance) -------------------------------

$existing = @(Get-ServiceSoffice)
if ($existing.Count -gt 0) {
    $pids = ($existing | ForEach-Object { $_.ProcessId }) -join ", "
    Write-Output "service soffice already running (PID $pids) but pipe not ready; waiting up to $ExistingWaitTimeoutSec s without starting a second instance"
    $BudgetSec = $ExistingWaitTimeoutSec
}
else {
    $env:TMP = $TmpDir
    $env:TEMP = $TmpDir
    $proc = Start-Process -FilePath $Soffice -WindowStyle Hidden -PassThru -ArgumentList @(
        "--headless",
        "--norestore",
        "-env:UserInstallation=$ProfileUrl",
        "--accept=pipe,name=$PipeName;urp;"
    )
    Write-Output "service launched: launcher PID $($proc.Id), profile $ProfileUrl, pipe $PipeName, TMP=TEMP=$TmpDir"
    $BudgetSec = $LaunchReadinessTimeoutSec
}

# -- readiness poll (hard timeout) --------------------------------------------

$deadline = (Get-Date).AddSeconds($BudgetSec)
$ready = $false
while (-not $ready -and (Get-Date) -lt $deadline) {
    $remaining = [int](($deadline - (Get-Date)).TotalSeconds)
    $cap = [Math]::Min(10, [Math]::Max(1, $remaining))
    $ready = Invoke-PipeProbe -CapSec $cap
    if (-not $ready) {
        $sleep = [Math]::Min(2, [int](($deadline - (Get-Date)).TotalSeconds))
        if ($sleep -gt 0) { Start-Sleep -Seconds $sleep }
    }
}

if ($ready) {
    Write-Output "service ready: $UnoUrl resolves"
    exit 0
}

# -- loud failure + process existence diagnostics -----------------------------

Write-Output ""
Write-Output "ERROR: service pipe '$PipeName' did not become resolvable within $BudgetSec s."
Write-Output "Process existence diagnostics:"
$ours = @(Get-ServiceSoffice)
if ($ours.Count -eq 0) {
    Write-Output "  no soffice process with the service profile ($ProfileUrl) is running -- the launch may have failed or exited"
}
foreach ($p in $ours) {
    Write-Output "  PID $($p.ProcessId) $($p.Name): $($p.CommandLine)"
}
$all = @(Get-CimInstance Win32_Process -Filter "Name='soffice.exe' OR Name='soffice.bin'" -ErrorAction SilentlyContinue)
if ($all.Count -eq 0) {
    Write-Output "  no soffice.exe/soffice.bin process exists at all"
}
else {
    $allIds = ($all | ForEach-Object { $_.ProcessId }) -join ", "
    Write-Output "  all soffice processes: $allIds"
}
$pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match $PipeName }
if ($pipes) {
    Write-Output "  pipe exists: $($pipes -join ', ') (created but bridge not accepting yet)"
}
else {
    Write-Output "  no pipe matching '$PipeName' exists"
}
exit 1
