param(
  [string]$Pattern = "tests"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
Write-Host "[test] running: $py -m pytest -q $Pattern"
& $py -m pytest -q $Pattern
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "[test] passed"
