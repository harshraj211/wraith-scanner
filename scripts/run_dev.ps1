$ErrorActionPreference = 'Stop'

$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $Root

$Python = '.\venv\Scripts\python.exe'
if (-not (Test-Path $Python)) {
    $Python = 'python'
}

Write-Host '[wraith] Starting API at http://127.0.0.1:5001'
$Api = Start-Process -FilePath $Python -ArgumentList 'api_server.py' -WorkingDirectory $Root -PassThru

try {
    Push-Location 'scanner-terminal'
    Write-Host '[wraith] Starting frontend at http://127.0.0.1:3000'
    npm start
}
finally {
    Pop-Location
    if ($Api -and -not $Api.HasExited) {
        Stop-Process -Id $Api.Id -Force
    }
}
