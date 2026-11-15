#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/test.sh [pattern]

Runs pytest (default: tests). Uses .venv python if available.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

PATTERN="${1:-tests}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

PY=""
if [[ -x ".venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
elif [[ -x ".venv/Scripts/python.exe" ]]; then
  PY="$ROOT/.venv/Scripts/python.exe"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
elif command -v python >/dev/null 2>&1; then
  PY="python"
else
  echo "[test] ERROR: no python interpreter found" >&2
  exit 1
fi

echo "[test] running: $PY -m pytest -q $PATTERN"
"$PY" -m pytest -q "$PATTERN"
echo "[test] passed"
