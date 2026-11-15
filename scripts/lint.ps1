$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
$failed = $false

Write-Host "[lint] python compileall"
& $py -m compileall bugbounty tests
if ($LASTEXITCODE -ne 0) { $failed = $true }

if (Get-Command ruff -ErrorAction SilentlyContinue) {
  Write-Host "[lint] ruff check"
  ruff check .
  if ($LASTEXITCODE -ne 0) { $failed = $true }
} else {
  Write-Host "[lint] ruff not installed; skipping"
}

if (Test-Path "dashboard/package.json" -and (Get-Command npm -ErrorAction SilentlyContinue)) {
  Push-Location dashboard
  try {
    Write-Host "[lint] frontend typecheck/build (tsc via npm run build --dry-run not available; running tsc -b if present)"
    if (Test-Path "node_modules/.bin/tsc.cmd") { & node_modules/.bin/tsc.cmd -b; if ($LASTEXITCODE -ne 0) { $failed = $true } }
    else { Write-Host "[lint] dashboard deps not installed; skipping frontend typecheck" }
  } finally { Pop-Location }
}

if ($failed) { exit 1 }
Write-Host "[lint] completed"
