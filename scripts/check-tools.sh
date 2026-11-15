#!/usr/bin/env bash
set -euo pipefail

echo "[tools] checking optional external tools"
TOOLS=(nuclei zap burp schemathesis restler ffuf kr kiterunner)

for tool in "${TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    src="$(command -v "$tool")"
    ver=""
    ver="$("$tool" --version 2>&1 | head -n 1 || true)"
    if [[ -z "$ver" ]]; then
      ver="$("$tool" -version 2>&1 | head -n 1 || true)"
    fi
    ver="$(printf '%s' "$ver" | tr -d '\r')"
    echo "[tools] OK   $tool -> $src $ver"
  else
    echo "[tools] MISS $tool (optional)"
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
PY=""
if [[ -x ".venv/bin/python" ]]; then PY="$ROOT/.venv/bin/python"
elif [[ -x ".venv/Scripts/python.exe" ]]; then PY="$ROOT/.venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then PY="python3"
elif command -v python >/dev/null 2>&1; then PY="python"
fi
if [[ -n "$PY" ]]; then
  echo "[tools] querying adapter registry"
  "$PY" -c "import json; from bugbounty.tool_adapters import available_adapters; print(json.dumps(available_adapters(), indent=2))" || true
fi
echo "[tools] core engine does not require external tools"