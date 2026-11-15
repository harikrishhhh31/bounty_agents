param(
  [int[]]$Ports = @(8765,5173)
)
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $root ".run-pids"

# Kill recorded PIDs first.
if (Test-Path $pidFile) {
  foreach ($pidPath in (Get-ChildItem $pidFile -Filter *.pid -ErrorAction SilentlyContinue)) {
    $pidValue = (Get-Content $pidPath.FullName -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($pidValue) {
      try {
        Stop-Process -Id ([int]$pidValue) -Force -ErrorAction SilentlyContinue
        Write-Host "[stop] stopped recorded PID $pidValue ($($pidPath.BaseName))"
      } catch {}
    }
    Remove-Item $pidPath.FullName -Force -ErrorAction SilentlyContinue
  }
}

# Kill by port.
foreach ($port in $Ports) {
  try {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
      if ($c.OwningProcess) {
        Write-Host "[stop] stopping PID $($c.OwningProcess) on port $port"
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
      }
    }
  } catch {
    Write-Warning "[stop] could not inspect/stop port $port: $($_.Exception.Message)"
  }
}
Write-Host "[stop] done"