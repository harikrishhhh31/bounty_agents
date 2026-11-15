#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/setup.sh [--skip-frontend]

Creates .venv if missing, installs backend (pip install -e .), and installs
dashboard dependencies unless --skip-frontend is set.
EOF
}

SKIP_FRONTEND=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-frontend) SKIP_FRONTEND=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[setup] ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"
echo "[setup] root: $ROOT"

require_cmd() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "[setup] ERROR: required command not found: $name" >&2
    exit 1
  fi
}

# Prefer python3, fall back to python for bootstrapping the venv
BOOTSTRAP_PY=""
if command -v python3 >/dev/null 2>&1; then
  BOOTSTRAP_PY="python3"
elif command -v python >/dev/null 2>&1; then
  BOOTSTRAP_PY="python"
else
  echo "[setup] ERROR: python3 or python is required" >&2
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  echo "[setup] creating virtual environment .venv"
  "$BOOTSTRAP_PY" -m venv .venv
fi

PY=""
if [[ -x ".venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
elif [[ -x ".venv/Scripts/python.exe" ]]; then
  PY="$ROOT/.venv/Scripts/python.exe"
else
  echo "[setup] ERROR: virtual environment python not found in .venv/bin or .venv/Scripts" >&2
  exit 1
fi

echo "[setup] installing backend dependencies"
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -e .

if [[ "$SKIP_FRONTEND" == false && -f "dashboard/package.json" ]]; then
  require_cmd npm
  echo "[setup] installing dashboard dependencies"
  (cd dashboard && npm install)
fi

echo "[setup] complete"
echo "[setup] backend: $PY -m bugbounty.cli --help"
echo "[setup] tests:   $PY -m pytest -q tests"
if [[ "$SKIP_FRONTEND" == false ]]; then
  echo "[setup] frontend: cd dashboard && npm run dev"
fi
