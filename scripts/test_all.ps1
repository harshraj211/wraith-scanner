$ErrorActionPreference = 'Stop'

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $Root

function Invoke-Checked {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE"
    }
}

$Python = '.\venv\Scripts\python.exe'
if (-not (Test-Path $Python)) {
    $Python = 'python'
}

Invoke-Checked { & $Python -m compileall -q main.py api_server.py scanner desktop }
Invoke-Checked { & $Python -m pytest -q }

Push-Location 'scanner-terminal'
Invoke-Checked { npm run build }
Pop-Location

Write-Host '[wraith] Backend tests and frontend build passed.'
