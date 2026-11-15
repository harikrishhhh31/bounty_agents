#!/usr/bin/env bash
set -euo pipefail

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
  echo "[lint] ERROR: no python interpreter found" >&2
  exit 1
fi

failed=0

echo "[lint] python compileall"
if ! "$PY" -m compileall bugbounty tests; then
  failed=1
fi

if command -v ruff >/dev/null 2>&1; then
  echo "[lint] ruff check"
  if ! ruff check .; then
    failed=1
  fi
else
  echo "[lint] ruff not installed; skipping"
fi

if [[ -f "dashboard/package.json" ]] && command -v npm >/dev/null 2>&1; then
  if [[ -x "dashboard/node_modules/.bin/tsc" ]]; then
    echo "[lint] frontend typecheck (tsc -b)"
    if ! (cd dashboard && node_modules/.bin/tsc -b); then
      failed=1
    fi
  else
    echo "[lint] dashboard deps not installed; skipping frontend typecheck"
  fi
else
  if [[ ! -f "dashboard/package.json" ]]; then
    echo "[lint] dashboard/package.json not found; skipping frontend typecheck"
  else
    echo "[lint] npm not found; skipping frontend typecheck"
  fi
fi

if [[ $failed -ne 0 ]]; then
  exit 1
fi
echo "[lint] completed"
