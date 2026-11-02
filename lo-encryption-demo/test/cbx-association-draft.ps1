<#
cbx-association-draft.ps1 -- DRAFT .cbx file association (Wave 0 todo 3 spike).

HKCU-scoped only (HKCU:\Software\Classes) -- never HKLM/HKCR writes, no admin
needed, fully reversible via -Uninstall.  Windows merges HKCU\Software\Classes
into the effective HKCR view, so ShellExecute / Invoke-Item resolve the verb.

Layout written:
  HKCU:\Software\Classes\.cbx                       (default) = CipherBox.Document
  HKCU:\Software\Classes\CipherBox.Document         (default) = CipherBox Encrypted Document
  ...\CipherBox.Document\shell\open\command         (default) = "<Launcher>" "%1"

-Install   : capture pre-existing values into -BackupFile, then write the keys.
-Uninstall : remove what -Install created (restoring any pre-existing values).
-SelfTest  : end-to-end verb-resolution proof against a STUB launcher that logs
             its arguments: install -> Invoke-Item a dummy .cbx -> assert the
             stub log received the path -> uninstall -> report HKCU state.
             Cleans everything up unless -KeepEvidence is passed.

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File cbx-association-draft.ps1 -SelfTest -WorkDir <dir>
#>

[CmdletBinding(DefaultParameterSetName = "Install")]
param(
    [Parameter(ParameterSetName = "Install")]
    [switch]$Install,
    [Parameter(ParameterSetName = "Uninstall")]
    [switch]$Uninstall,
    [Parameter(ParameterSetName = "SelfTest")]
    [switch]$SelfTest,
    [Parameter(ParameterSetName = "SelfTest")]
    [switch]$KeepEvidence,

    [string]$Launcher = "C:\Program Files\CipherBox\cbx-launcher.exe",
    [string]$BackupFile = (Join-Path $env:TEMP "cbx-association-backup.json"),
    [Parameter(ParameterSetName = "SelfTest", Mandatory = $true)]
    [string]$WorkDir
)

$ErrorActionPreference = "Stop"

$ExtKey = "HKCU:\Software\Classes\.cbx"
$ProgKey = "HKCU:\Software\Classes\CipherBox.Document"
$CmdKey = "HKCU:\Software\Classes\CipherBox.Document\shell\open\command"
$ProgId = "CipherBox.Document"
$Verb = '"{0}" "%1"' -f $Launcher

function Get-KeyState {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path
        return @{ Exists = $true; Default = [string]($item.GetValue("")) }
    }
    return @{ Exists = $false; Default = $null }
}

function Save-Backup {
    $state = [ordered]@{
        ExtKey  = Get-KeyState $ExtKey
        ProgKey = Get-KeyState $ProgKey
        CmdKey  = Get-KeyState $CmdKey
    }
    $state | ConvertTo-Json | Set-Content -LiteralPath $BackupFile -Encoding Ascii
    Write-Output "backup captured -> $BackupFile"
}

function Install-Association {
    Save-Backup
    New-Item -Path $ExtKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $ExtKey -Name "(default)" -Value $ProgId
    New-Item -Path $ProgKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $ProgKey -Name "(default)" -Value "CipherBox Encrypted Document"
    New-Item -Path $CmdKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $CmdKey -Name "(default)" -Value $Verb
    Write-Output "installed (HKCU only):"
    Write-Output "  $ExtKey  (default) = $ProgId"
    Write-Output "  $ProgKey (default) = CipherBox Encrypted Document"
    Write-Output "  $CmdKey (default) = $Verb"
}

function Uninstall-Association {
    $backup = $null
    if (Test-Path -LiteralPath $BackupFile) {
        $backup = Get-Content -LiteralPath $BackupFile -Raw | ConvertFrom-Json
    }
    # Remove what we created.
    foreach ($k in @($CmdKey, $ProgKey, $ExtKey)) {
        if (Test-Path -LiteralPath $k) {
            Remove-Item -LiteralPath $k -Recurse -Force
            Write-Output "removed $k"
        }
    }
    # Restore anything that existed before (defensive: draft never expected it).
    if ($backup) {
        if ($backup.ProgKey.Exists) {
            New-Item -Path $ProgKey -Force | Out-Null
            Set-ItemProperty -LiteralPath $ProgKey -Name "(default)" -Value $backup.ProgKey.Default
            Write-Output "restored pre-existing $ProgKey"
        }
        if ($backup.ExtKey.Exists) {
            New-Item -Path $ExtKey -Force | Out-Null
            Set-ItemProperty -LiteralPath $ExtKey -Name "(default)" -Value $backup.ExtKey.Default
            Write-Output "restored pre-existing $ExtKey"
        }
    }
    Write-Output "uninstalled; HKCU state clean: ext=$(Test-Path -LiteralPath $ExtKey) prog=$(Test-Path -LiteralPath $ProgKey)"
}

function Invoke-SelfTest {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $log = Join-Path $WorkDir "stub-launcher.log"
    $stub = Join-Path $WorkDir "stub-launcher.cmd"
    $dummy = Join-Path $WorkDir "dummy.docx.cbx"
    $stubBody = "@echo off`r`necho STUB-ARGS: %* >> `"$log`"`r`n"
    Set-Content -LiteralPath $stub -Value $stubBody -Encoding Ascii
    Set-Content -LiteralPath $dummy -Value "CIPHERBOX-DUMMY" -Encoding Ascii
    Write-Output "self-test: stub=$stub dummy=$dummy log=$log"

    $script:Verb = '"{0}" "%1"' -f $stub
    Install-Association
    try {
        if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
        Write-Output "self-test: Invoke-Item $dummy"
        Invoke-Item -LiteralPath $dummy
        $deadline = (Get-Date).AddSeconds(20)
        $ok = $false
        while ((Get-Date) -lt $deadline) {
            if ((Test-Path -LiteralPath $log) -and
                ((Get-Content -LiteralPath $log -Raw) -match [regex]::Escape($dummy))) {
                $ok = $true
                break
            }
            Start-Sleep -Milliseconds 500
        }
        if ($ok) {
            Write-Output "self-test: VERB RESOLVED -- stub received:"
            Write-Output ("  " + ((Get-Content -LiteralPath $log) -join " | "))
        }
        else {
            Write-Output "self-test: FAIL -- stub log did not record the dummy path within 20 s"
            exit 1
        }
    }
    finally {
        Uninstall-Association
    }

    $extGone = -not (Test-Path -LiteralPath $ExtKey)
    $progGone = -not (Test-Path -LiteralPath $ProgKey)
    Write-Output "self-test: HKCU state after cleanup: ext key gone=$extGone, prog key gone=$progGone"
    if (-not ($extGone -and $progGone)) {
        Write-Output "self-test: FAIL -- HKCU residue remains"
        exit 1
    }
    if (-not $KeepEvidence) {
        Remove-Item -LiteralPath $stub, $dummy, $log -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $BackupFile -Force -ErrorAction SilentlyContinue
        Write-Output "self-test: scratch cleaned (stub/dummy/log/backup removed)"
    }
    else {
        Write-Output "self-test: evidence kept in $WorkDir (stub/dummy/log) and $BackupFile"
    }
    Write-Output "self-test: PASS"
}

switch ($PSCmdlet.ParameterSetName) {
    "Install" { Install-Association }
    "Uninstall" { Uninstall-Association }
    "SelfTest" { Invoke-SelfTest }
}
