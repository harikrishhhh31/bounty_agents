#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/start.sh [--backend-port PORT] [--frontend-port PORT] [--backend-only|--frontend-only]

Starts backend dashboard API and/or frontend dev server in the background.
Records PIDs under .run/ for scripts/stop.sh.
EOF
}

BACKEND_PORT=8765
FRONTEND_PORT=5173
BACKEND_ONLY=false
FRONTEND_ONLY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend-port) BACKEND_PORT="${2:-}"; shift 2 ;;
    --frontend-port) FRONTEND_PORT="${2:-}"; shift 2 ;;
    --backend-only) BACKEND_ONLY=true; shift ;;
    --frontend-only) FRONTEND_ONLY=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[start] ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$BACKEND_ONLY" == true && "$FRONTEND_ONLY" == true ]]; then
  echo "[start] ERROR: --backend-only and --frontend-only cannot be used together" >&2
  exit 2
fi

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
  echo "[start] ERROR: no python interpreter found" >&2
  exit 1
fi

mkdir -p .run

if [[ "$FRONTEND_ONLY" == false ]]; then
  echo "[start] backend dashboard API on http://127.0.0.1:${BACKEND_PORT}"
  nohup "$PY" -m bugbounty.cli dashboard --host 127.0.0.1 --port "$BACKEND_PORT" > .run/backend.log 2>&1 &
  echo $! > .run/backend.pid
  echo "[start] backend pid $(cat .run/backend.pid) (log: .run/backend.log)"
fi

if [[ "$FRONTEND_ONLY" == false ]]; then
  # Health check
  for i in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${BACKEND_PORT}/overview" >/dev/null 2>&1; then
      echo "[start] backend healthy"
      break
    fi
    sleep 1
    if [[ $i -eq 30 ]]; then echo "[start] WARN: backend did not become healthy" >&2; fi
  done
fi

if [[ "$BACKEND_ONLY" == false ]]; then
  if [[ -f "dashboard/package.json" ]]; then
    if command -v npm >/dev/null 2>&1; then
      echo "[start] frontend dev server on http://127.0.0.1:${FRONTEND_PORT}"
      (cd dashboard && nohup npm run dev -- --host 127.0.0.1 --port "$FRONTEND_PORT" > "$ROOT/.run/frontend.log" 2>&1 & echo $! > "$ROOT/.run/frontend.pid")
      echo "[start] frontend pid $(cat .run/frontend.pid) (log: .run/frontend.log)"
    else
      echo "[start] WARN: npm not found; frontend not started" >&2
    fi
  else
    echo "[start] WARN: dashboard/package.json not found; frontend not started" >&2
  fi
fi

echo "[start] processes launched. Use scripts/stop.sh to stop known ports/pids."
