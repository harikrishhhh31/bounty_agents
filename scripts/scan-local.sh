#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/scan-local.sh [--config PATH] [--target URL] [--workspace NAME]

Runs a local assessment via the CLI.
  --config     Config file (default: examples/engagement.yaml)
  --target     Target URL/host (if set, runs: assess --target ... --workspace ...)
  --workspace  Workspace name when using --target (default: demo-assessment)
If --target is not provided, runs: assess --config <config>.
EOF
}

CONFIG="examples/engagement.yaml"
TARGET=""
WORKSPACE="demo-assessment"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --workspace) WORKSPACE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[scan-local] ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

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
  echo "[scan-local] ERROR: no python interpreter found" >&2
  exit 1
fi

if [[ -n "$TARGET" ]]; then
  echo "[scan-local] running assessment against target $TARGET"
  "$PY" -m bugbounty.cli assess --target "$TARGET" --workspace "$WORKSPACE"
else
  if [[ ! -f "$CONFIG" ]]; then
    echo "[scan-local] ERROR: config not found: $CONFIG. Provide --target or a valid --config." >&2
    exit 1
  fi
  echo "[scan-local] running assessment from config $CONFIG"
  "$PY" -m bugbounty.cli assess --config "$CONFIG"
fi

echo "[scan-local] complete"
