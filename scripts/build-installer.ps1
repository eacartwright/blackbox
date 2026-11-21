# Builds the release binaries and BlackBox-Setup-<version>.exe in dist\.
# Needs Rust (MSVC), the Visual Studio C++ Build Tools and Inno Setup 6
# (winget install JRSoftware.InnoSetup).
#   .\scripts\build-installer.ps1            # build, test, package
#   .\scripts\build-installer.ps1 -SkipTests
param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $version) { throw 'Could not read the version from Cargo.toml' }

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup' }

Write-Host "Building BlackBox $version"
cargo build --release
if ($LASTEXITCODE) { throw 'cargo build failed' }
if (-not $SkipTests) {
    cargo test --workspace
    if ($LASTEXITCODE) { throw 'tests failed' }
}

& $iscc /Qp "/DAppVersion=$version" installer\blackbox.iss
if ($LASTEXITCODE) { throw 'Inno Setup failed' }
Get-Item "dist\BlackBox-Setup-$version.exe" | Select-Object FullName, @{n='MB';e={[math]::Round($_.Length / 1MB, 1)}}
