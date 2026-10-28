#Requires -Version 5.1
<#
.SYNOPSIS
  Generates a self-signed CA and a TLS server certificate for the cipherbox
  HTTPS server (port 8443, HTTPS-only; no HTTP listener is ever started).

.DESCRIPTION
  Produces, under -OutDir (default server\certs):
    ca.key      CA private key            (server-side secret, never shipped)
    ca.crt      CA certificate            (distribute to clients for pinning)
    server.key  server private key        (server-side secret, never shipped)
    server.crt  server certificate        (used by uvicorn --ssl-certfile)

  The server certificate carries SANs for -ServerName and -ExtraIP so LAN
  clients can verify the handshake against the pinned CA (todo 9 exercises
  real TLS end-to-end; this script only provisions the material).

  Do NOT commit these files: server/certs/ is git-ignored.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File server\scripts\make_certs.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File server\scripts\make_certs.ps1 -ServerName cipherbox.lan -ExtraIP 192.168.1.10

.NOTES
  Server run command (from repo root, after this script):
    server\.venv\Scripts\python.exe -m uvicorn server.app:create_app --factory `
      --host 0.0.0.0 --port 8443 `
      --ssl-certfile server\certs\server.crt --ssl-keyfile server\certs\server.key
#>
[CmdletBinding()]
param(
  # Default resolved below (PSScriptRoot is not reliable in param defaults on PS5.1).
  [string]$OutDir = '',
  [string]$ServerName = 'localhost',
  [string]$ExtraIP = '127.0.0.1',
  [int]$CaDays = 3650,
  [int]$ServerDays = 825
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutDir)) {
  $scriptDir = $PSScriptRoot
  if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
  }
  if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = (Get-Location).Path
  }
  $OutDir = Join-Path $scriptDir '..\certs'
}

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
  throw "openssl not found on PATH. Install OpenSSL (e.g. via Git for Windows, Strawberry Perl, or anaconda) and re-run."
}

$OutDir = (New-Item -ItemType Directory -Force $OutDir).FullName
$caKey  = Join-Path $OutDir 'ca.key'
$caCrt  = Join-Path $OutDir 'ca.crt'
$svKey  = Join-Path $OutDir 'server.key'
$svCsr  = Join-Path $OutDir 'server.csr'
$svCrt  = Join-Path $OutDir 'server.crt'
$extFile = Join-Path $OutDir 'server-ext.cnf'
$cnfFile = Join-Path $OutDir 'openssl-min.cnf'

# Many Windows OpenSSL builds ship without a default openssl.cnf; `openssl req`
# hard-fails without one. Ship a minimal config (we pass -subj explicitly) and
# point OPENSSL_CONF at it for the duration of this script.
@"
[req]
distinguished_name = dn
prompt = no
[dn]
CN = placeholder
"@ | Set-Content -Encoding ascii $cnfFile
$env:OPENSSL_CONF = $cnfFile

function Invoke-OpenSsl([string[]]$CmdArgs) {
  & openssl @CmdArgs | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "openssl $($CmdArgs[0]) failed (exit $LASTEXITCODE)" }
}

try {
  Write-Host "[1/4] CA key + self-signed CA cert"
  Invoke-OpenSsl @('genrsa', '-out', $caKey, '4096')
  Invoke-OpenSsl @('req', '-x509', '-new', '-nodes', '-key', $caKey,
                   '-sha256', '-days', "$CaDays", '-out', $caCrt,
                   '-subj', '/CN=CipherBox Local CA')

  Write-Host "[2/4] server key + CSR (CN=$ServerName)"
  Invoke-OpenSsl @('genrsa', '-out', $svKey, '2048')
  Invoke-OpenSsl @('req', '-new', '-key', $svKey, '-out', $svCsr,
                   '-subj', "/CN=$ServerName")

  Write-Host "[3/4] sign server cert with SAN DNS:$ServerName IP:$ExtraIP"
  @"
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$ServerName,IP:$ExtraIP
"@ | Set-Content -Encoding ascii $extFile
  Invoke-OpenSsl @('x509', '-req', '-in', $svCsr,
                   '-CA', $caCrt, '-CAkey', $caKey, '-CAcreateserial',
                   '-out', $svCrt, '-days', "$ServerDays", '-sha256',
                   '-extfile', $extFile)

  Write-Host "[4/4] verify chain"
  Invoke-OpenSsl @('verify', '-CAfile', $caCrt, $svCrt)
}
finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $svCsr, $extFile, $cnfFile
}

Write-Host ""
Write-Host "Done. Material in $OutDir"
Write-Host "  ca.crt     -> distribute to clients for certificate pinning"
Write-Host "  server.crt -> uvicorn --ssl-certfile"
Write-Host "  server.key -> uvicorn --ssl-keyfile (keep secret)"
Write-Host ""
Write-Host "Run (HTTPS only, port 8443):"
Write-Host "  server\.venv\Scripts\python.exe -m uvicorn server.app:create_app --factory ``"
Write-Host "    --host 0.0.0.0 --port 8443 ``"
Write-Host "    --ssl-certfile server\certs\server.crt --ssl-keyfile server\certs\server.key"
