param(
  [switch]$SkipFrontend
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
Write-Host "[setup] root: $root"

function Assert-Cmd($name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "Required command not found: $name" }
}

Assert-Cmd python
if (-not (Test-Path ".venv")) {
  Write-Host "[setup] creating virtual environment .venv"
  python -m venv .venv
}
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Virtual environment python not found at $py" }
Write-Host "[setup] installing backend dependencies"
& $py -m pip install --upgrade pip
& $py -m pip install -e .

if (-not $SkipFrontend -and (Test-Path "dashboard/package.json")) {
  Assert-Cmd npm
  Write-Host "[setup] installing dashboard dependencies"
  Push-Location dashboard
  try { npm install } finally { Pop-Location }
}

Write-Host "[setup] complete"
Write-Host "[setup] backend: $py -m bugbounty.cli --help"
Write-Host "[setup] tests:   $py -m pytest -q tests"
if (-not $SkipFrontend) { Write-Host "[setup] frontend: cd dashboard; npm run dev" }
