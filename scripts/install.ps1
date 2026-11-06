# Install tvbox-botnet-scanner into .venv in this folder (Windows PowerShell 5.1+).
# Usage: powershell -ExecutionPolicy Bypass -File scripts\install.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$py = $null
foreach ($cand in @("py -3", "python", "python3")) {
    $exe, $arg = $cand.Split(" ", 2)
    if (Get-Command $exe -ErrorAction SilentlyContinue) {
        $ver = & $exe $arg -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($ver -and [version]$ver -ge [version]"3.10") { $py = $cand; break }
    }
}
if (-not $py) {
    Write-Host "Python 3.10+ not found. Install it: winget install --id Python.Python.3.12 -e" -ForegroundColor Red
    exit 1
}
Write-Host "Using $py"

$exe, $arg = $py.Split(" ", 2)
& $exe $arg -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
& .\.venv\Scripts\python.exe -m pip install ".[ui]" --quiet
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "adb not found. Install Android platform-tools, then open a new terminal:" -ForegroundColor Yellow
    Write-Host "  winget install --id Google.PlatformTools -e"
}

Write-Host ""
& .\.venv\Scripts\tvbox-scan.exe doctor
Write-Host ""
Write-Host "Run:  .\.venv\Scripts\tvbox-scan.exe ui" -ForegroundColor Green
