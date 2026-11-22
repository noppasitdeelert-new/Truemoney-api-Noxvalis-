<#
.SYNOPSIS
    Build dist\ngm-panel.exe (PyInstaller) and optionally the Inno Setup installer.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\build.ps1
    powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -Installer
#>
param(
    [switch]$Installer,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "== ngm-panel build ==" -ForegroundColor Cyan
python --version

if (-not $SkipTests) {
    Write-Host "`n-- running offline tests --" -ForegroundColor Cyan
    python -m unittest discover -s tests
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
    python -m ngm_panel catalog --check
    if ($LASTEXITCODE -ne 0) { throw "catalog check failed" }
}

Write-Host "`n-- installing PyInstaller --" -ForegroundColor Cyan
python -m pip install --upgrade pyinstaller

Write-Host "`n-- building single-file exe --" -ForegroundColor Cyan
python -m PyInstaller packaging\ngm-panel.spec --noconfirm --clean

if (-not (Test-Path "dist\ngm-panel.exe")) { throw "build failed: dist\ngm-panel.exe not found" }

Write-Host "`n-- smoke test --" -ForegroundColor Cyan
& ".\dist\ngm-panel.exe" --version
& ".\dist\ngm-panel.exe" catalog --check

if ($Installer) {
    $iscc = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if (-not $iscc) {
        $candidate = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
        if (Test-Path $candidate) { $iscc = Get-Item $candidate } else {
            throw "Inno Setup 6 not found. Install it (winget install JRSoftware.InnoSetup) or run without -Installer."
        }
    }
    Write-Host "`n-- building installer --" -ForegroundColor Cyan
    & $iscc.Source "packaging\installer\ngm-panel.iss"
    Get-ChildItem "dist\ngm-panel-*-setup.exe" | ForEach-Object { Write-Host "installer: $($_.FullName)" }
}

Write-Host "`nDone. Try:  .\dist\ngm-panel.exe run" -ForegroundColor Green
