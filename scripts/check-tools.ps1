$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }

Write-Host "[tools] checking optional external tools"
$external = @("nuclei","zap","burp","schemathesis","restler","ffuf","kr","kiterunner")
foreach ($tool in $external) {
  $cmd = Get-Command $tool -ErrorAction SilentlyContinue
  if ($cmd) {
    $ver = ""
    try { $ver = (& $tool --version 2>&1 | Select-Object -First 1) } catch {}
    Write-Host ("[tools] OK   {0} -> {1} {2}" -f $tool, $cmd.Source, $ver)
  } else {
    Write-Host ("[tools] MISS {0} (optional)" -f $tool)
  }
}

if (Test-Path ".venv\Scripts\python.exe") {
  Write-Host "[tools] querying adapter registry"
  & $py -c "from bugbounty.tool_adapters import available_adapters; import json; print(json.dumps(available_adapters(), indent=2))"
}
Write-Host "[tools] core engine does not require external tools"