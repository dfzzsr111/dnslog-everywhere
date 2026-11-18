<#
.SYNOPSIS
    Build dnslog-everywhere.jar from source.

.DESCRIPTION
    Compiles src/main/java with a Burp/Montoya API jar on the classpath and
    packages only the extension classes into dist/dnslog-everywhere.jar.

.PARAMETER BurpJar
    Path to burpsuite_pro.jar (or a standalone montoya-api.jar).
    Defaults to $env:BURP_JAR, then common install paths, then lib\*.jar.

.PARAMETER JavaHome
    JDK 17+ home. Defaults to $env:JAVA_HOME, then javac on PATH.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -BurpJar 'D:\Burp\burpsuite_pro.jar' -JavaHome 'C:\Program Files\Java\jdk-21'
#>
param(
    [string]$BurpJar = $env:BURP_JAR,
    [string]$JavaHome = $env:JAVA_HOME
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
Push-Location $root

function Resolve-BurpJar {
    param([string]$explicit)

    if ($explicit) {
        if (-not (Test-Path $explicit)) { throw "BurpJar not found: $explicit" }
        return (Resolve-Path $explicit).Path
    }
    $candidates = @(
        'C:\Program Files\BurpSuiteProfessional\burpsuite_pro.jar',
        'C:\Program Files\BurpSuiteCommunity\burpsuite_community.jar',
        'C:\Program Files\BurpSuitePro\burpsuite_pro.jar',
        (Join-Path $env:LOCALAPPDATA 'BurpSuite\burpsuite_pro.jar')
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    $local = Get-ChildItem (Join-Path $root 'lib\*.jar') -ErrorAction SilentlyContinue
    if ($local) { return $local[0].FullName }
    return $null
}

$apiJar = Resolve-BurpJar -explicit $BurpJar
if (-not $apiJar) {
    Write-Host @'
[ERROR] Burp / Montoya API jar not found.

Provide one of:
  1) -BurpJar 'C:\path\to\burpsuite_pro.jar'
  2) set BURP_JAR=C:\path\to\burpsuite_pro.jar
  3) drop a jar into .\lib\

You do not need a full Burp install: the standalone API jar works too.
  https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/
'@ -ForegroundColor Red
    Pop-Location
    exit 1
}

$javac = if ($JavaHome) { Join-Path $JavaHome 'bin\javac.exe' } else { 'javac' }
$jarTool = if ($JavaHome) { Join-Path $JavaHome 'bin\jar.exe' } else { 'jar' }
foreach ($tool in @($javac, $jarTool)) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Not found: $tool (install JDK 17+ or pass -JavaHome)"
    }
}

Write-Host "API jar : $apiJar"
Write-Host "javac   : $javac"

Remove-Item build, stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force build, stage, dist | Out-Null

$sources = Get-ChildItem 'src\main\java\dnslogeverywhere\*.java' | ForEach-Object { $_.FullName }
if (-not $sources) { throw 'No sources found under src\main\java\dnslogeverywhere' }

& $javac -encoding UTF-8 -nowarn -cp $apiJar -d build $sources
if ($LASTEXITCODE -ne 0) { throw "javac failed (exit $LASTEXITCODE)" }

# Package only our own classes: build\ may also contain API classes pulled in
# by the compiler, and shipping those would bloat (and break) the jar.
New-Item -ItemType Directory -Force 'stage\dnslogeverywhere' | Out-Null
Copy-Item 'build\dnslogeverywhere\*.class' 'stage\dnslogeverywhere\'

$out = Join-Path $root 'dist\dnslog-everywhere.jar'
Remove-Item $out -ErrorAction SilentlyContinue
& $jarTool cf $out -C stage .
if ($LASTEXITCODE -ne 0) { throw "jar failed (exit $LASTEXITCODE)" }

Write-Host ''
Get-Item $out | Select-Object FullName, Length, LastWriteTime | Format-List
Pop-Location
