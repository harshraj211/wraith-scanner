param(
    [switch]$SkipFrontend,
    [switch]$SkipPyInstaller
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Frontend = Join-Path $Root "scanner-terminal"
$Spec = Join-Path $Root "desktop\pyinstaller\wraith_desktop.spec"

Write-Host "[wraith] Desktop build root: $Root"

if (-not $SkipFrontend) {
    Write-Host "[wraith] Building React frontend"
    Push-Location $Frontend
    try {
        npm install
        npm run build
    }
    finally {
        Pop-Location
    }
}

if (-not $SkipPyInstaller) {
    Write-Host "[wraith] Building desktop bundle with PyInstaller"
    Push-Location $Root
    try {
        python -m pip install -r requirements.txt
        python -m pip install -r desktop\requirements-desktop.txt
        python -m PyInstaller $Spec --noconfirm
    }
    finally {
        Pop-Location
    }
}

Write-Host "[wraith] Desktop build complete. Output: dist\WraithDesktop"
