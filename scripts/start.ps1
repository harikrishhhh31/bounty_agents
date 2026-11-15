param(
  [int]$BackendPort = 8765,
  [int]$FrontendPort = 5173,
  [switch]$BackendOnly,
  [switch]$FrontendOnly,
  [int]$HealthTimeoutSeconds = 30
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

$pidFile = Join-Path $root ".run-pids"
if (-not (Test-Path $pidFile)) { New-Item -ItemType Directory -Path $pidFile | Out-Null }

if (-not $FrontendOnly) {
  Write-Host "[start] backend dashboard API on http://127.0.0.1:$BackendPort"
  $backendProc = Start-Process -FilePath $py -ArgumentList @("-m","bugbounty.cli","dashboard","--host","127.0.0.1","--port","$BackendPort") -WorkingDirectory $root -PassThru
  $backendProc.Id | Out-File (Join-Path $pidFile "backend.pid") -Encoding ascii
  # Health check: poll until the API responds.
  $deadline = (Get-Date).AddSeconds($HealthTimeoutSeconds)
  $ready = $false
  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$BackendPort/overview" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
      if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) { $ready = $true; break }
    } catch { Start-Sleep -Milliseconds 500 }
  }
  if ($ready) { Write-Host "[start] backend healthy" } else { Write-Warning "[start] backend did not become healthy within ${HealthTimeoutSeconds}s" }
}
if (-not $BackendOnly -and (Test-Path "dashboard/package.json")) {
  if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Write-Warning "[start] npm not found; frontend not started" }
  else {
    Write-Host "[start] frontend dev server on http://127.0.0.1:$FrontendPort"
    $frontendProc = Start-Process -FilePath "npm.cmd" -ArgumentList @("run","dev","--","--host","127.0.0.1","--port","$FrontendPort") -WorkingDirectory (Join-Path $root "dashboard") -PassThru
    $frontendProc.Id | Out-File (Join-Path $pidFile "frontend.pid") -Encoding ascii
  }
}
Write-Host "[start] done. Use scripts/stop.ps1 to stop."