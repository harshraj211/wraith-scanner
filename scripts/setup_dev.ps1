$ErrorActionPreference = 'Stop'

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $Root

if (-not (Test-Path '.env') -and (Test-Path '.env.example')) {
    Copy-Item '.env.example' '.env'
    Write-Host '[wraith] Created .env from .env.example'
}

if (-not (Test-Path 'venv')) {
    python -m venv venv
}

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

Invoke-Checked { .\venv\Scripts\python.exe -m pip install --upgrade pip }
Invoke-Checked { .\venv\Scripts\python.exe -m pip install -r requirements.txt }
Invoke-Checked { .\venv\Scripts\python.exe -m pip install -r requirements-dev.txt }
Invoke-Checked { .\venv\Scripts\python.exe -m playwright install chromium }

Push-Location 'scanner-terminal'
Invoke-Checked { npm install }
Pop-Location

Write-Host '[wraith] Development environment ready.'
