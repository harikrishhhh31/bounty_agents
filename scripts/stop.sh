#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/stop.sh [--ports 8765,5173]

Stops processes recorded in .run/*.pid and any listeners on the given ports.
Defaults to ports 8765,5173. Best-effort and non-destructive beyond those targets.
EOF
}

PORTS_CSV="8765,5173"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ports) PORTS_CSV="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[stop] ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

is_pid_alive() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

stop_pid() {
  local pid="$1"
  local label="$2"
  if [[ -z "$pid" ]]; then return 0; fi
  if is_pid_alive "$pid"; then
    echo "[stop] stopping $label PID $pid"
    kill "$pid" >/dev/null 2>&1 || true
    sleep 0.2
    if is_pid_alive "$pid"; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  fi
}

# Stop recorded PIDs first (if any)
for name in backend frontend; do
  pidfile=".run/${name}.pid"
  if [[ -f "$pidfile" ]]; then
    pid="$(tr -d '[:space:]' < "$pidfile" || true)"
    stop_pid "$pid" "$name"
    rm -f "$pidfile"
  fi
done

IFS=',' read -r -a PORTS <<< "$PORTS_CSV"
for port in "${PORTS[@]}"; do
  port="$(echo "$port" | xargs)"
  [[ -z "$port" ]] && continue
  pids=""
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  elif command -v ss >/dev/null 2>&1; then
    # extract pid=NNN from ss output
    pids="$(ss -ltnp "sport = :$port" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | sort -u || true)"
  elif command -v netstat >/dev/null 2>&1; then
    # Windows netstat format: last column is PID
    pids="$(netstat -ano 2>/dev/null | awk -v p=":$port" '$1 ~ /^TCP/ && $2 ~ p"$" && $4=="LISTENING" {print $5}' | sort -u || true)"
  fi
  if [[ -n "$pids" ]]; then
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      stop_pid "$pid" "port $port"
    done <<< "$pids"
  fi
done

echo "[stop] done"
