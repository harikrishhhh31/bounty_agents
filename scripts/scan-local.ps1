param(
  [string]$Config = "examples/engagement.yaml",
  [string]$Target = "",
  [string]$Workspace = "demo-assessment"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
if ($Target -ne "") {
  Write-Host "[scan-local] running assessment against target $Target"
  & $py -m bugbounty.cli assess --target $Target --workspace $Workspace
} else {
  if (-not (Test-Path $Config)) { throw "Config not found: $Config. Provide -Target or a valid -Config." }
  Write-Host "[scan-local] running assessment from config $Config"
  & $py -m bugbounty.cli assess --config $Config
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "[scan-local] complete"
