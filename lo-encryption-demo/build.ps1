# Builds the CipherBoxDataSpace Java UNO component and stages a deployable
# LibreOffice extension directory.
#
#   .\build.ps1
#
# Outputs:
#   build\classes\                    compiled classes
#   build\extension\cipherbox.jar     component jar
#   build\extension\components.rdb     JURT registration
#   build\extension\description.xml    extension descriptor

$ErrorActionPreference = 'Stop'

$root     = $PSScriptRoot
$srcDir   = Join-Path $root 'src'
$buildDir = Join-Path $root 'build'
$clsDir   = Join-Path $buildDir 'classes'
$extDir   = Join-Path $buildDir 'extension'

$jdkHome = 'C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot'
$loHome  = 'C:\Program Files\LibreOffice'
$apiJar  = Join-Path $loHome 'program\classes\libreoffice.jar'

foreach ($p in @($jdkHome, $loHome)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "missing prerequisite: $p" }
}
if (-not (Test-Path -LiteralPath $apiJar)) { throw "missing UNO API jar: $apiJar" }

$javac = Join-Path $jdkHome 'bin\javac.exe'
$jar   = Join-Path $jdkHome 'bin\jar.exe'
if (-not (Test-Path -LiteralPath $javac)) { throw "javac not found: $javac" }

foreach ($d in @($buildDir, $clsDir, $extDir)) {
    if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}

$javaFiles = @(Get-ChildItem -LiteralPath $srcDir -Recurse -Filter '*.java' | Select-Object -ExpandProperty FullName)
if ($javaFiles.Count -eq 0) { throw "no .java sources under $srcDir" }

# Use a javac @argfile: PowerShell 5.1 mangles native arguments whose paths contain spaces,
# and javac treats backslashes as escapes inside @argfiles, so use forward slashes.
$argFile = Join-Path $buildDir 'javac.args'
$argLines = @(
    '-encoding UTF-8'
    '-nowarn'
    ('-cp "' + ($apiJar -replace '\\', '/') + '"')
    ('-d "' + ($clsDir -replace '\\', '/') + '"')
) + ($javaFiles | ForEach-Object { '"' + ($_ -replace '\\', '/') + '"' })
Set-Content -LiteralPath $argFile -Value ($argLines -join "`n") -Encoding ASCII

Write-Host "==> compiling $($javaFiles.Count) source file(s)"
& $javac "@$argFile"
if ($LASTEXITCODE -ne 0) { throw "javac failed with exit code $LASTEXITCODE" }

Write-Host "==> packaging cipherbox.jar"
& $jar --create --file (Join-Path $extDir 'cipherbox.jar') -C $clsDir .
if ($LASTEXITCODE -ne 0) { throw "jar failed with exit code $LASTEXITCODE" }

Write-Host "==> writing components.rdb"
@'
<?xml version="1.0"?>
<components xmlns="http://openoffice.org/2010/uno-components">
    <component loader="com.sun.star.loader.Java2" uri="./cipherbox.jar">
        <implementation name="com.sun.star.comp.oox.crypto.IMPL.CipherBoxDataSpace">
            <service name="com.sun.star.comp.oox.crypto.CipherBoxDataSpace"/>
        </implementation>
    </component>
</components>
'@ | Set-Content -LiteralPath (Join-Path $extDir 'components.rdb') -Encoding UTF8

Write-Host "==> writing description.xml"
@'
<?xml version="1.0" encoding="UTF-8"?>
<description xmlns="http://openoffice.org/extensions/description/2006">
    <version value="1.0.0"/>
    <identifier value="com.cipherbox.oox.dataspace"/>
    <display-name>
        <name lang="en-US">CipherBox DataSpace</name>
    </display-name>
    <extension>
        <resourcedir/>
    </extension>
    <requires>
        <component/>
    </requires>
</description>
'@ | Set-Content -LiteralPath (Join-Path $extDir 'description.xml') -Encoding UTF8

Write-Host "==> writing META-INF/manifest.xml"
$metaDir = Join-Path $extDir 'META-INF'
New-Item -ItemType Directory -Path $metaDir -Force | Out-Null
@'
<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="http://openoffice.org/2001/manifest">
  <manifest:file-entry manifest:media-type="application/vnd.sun.star.uno-components"
                       manifest:full-path="components.rdb"/>
  <manifest:file-entry manifest:media-type="application/vnd.sun.star.package-bundle-description"
                       manifest:full-path="description/extensiondescription.txt"/>
</manifest:manifest>
'@ | Set-Content -LiteralPath (Join-Path $metaDir 'manifest.xml') -Encoding UTF8

$descDir = Join-Path $extDir 'description'
New-Item -ItemType Directory -Path $descDir -Force | Out-Null
@'
CipherBox DataSpace
Custom XPackageEncryption provider for LibreOffice (com.sun.star.comp.oox.crypto.CipherBoxDataSpace).
'@ | Set-Content -LiteralPath (Join-Path $descDir 'extensiondescription.txt') -Encoding UTF8

Write-Host "==> build OK: $extDir"
Get-ChildItem -LiteralPath $extDir | Select-Object Name, Length | Format-Table -AutoSize
