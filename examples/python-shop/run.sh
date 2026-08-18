#!/usr/bin/env bash
# Bring up the Python shop: OpticTrace in collector mode + three FastAPI
# services instrumented with the SDK.
#
#   ./run.sh              start everything, drive traffic, leave it running
#   ./run.sh --no-drive   start only
set -euo pipefail
cd "$(dirname "$0")"

ROOT="$(cd ../.. && pwd)"
export PATH="$HOME/.local/go/bin:$PATH"
VENV=".venv"
PY="$VENV/bin/python"

# --- dependencies -----------------------------------------------------------
if [[ ! -x "$PY" ]]; then
  echo "==> Creating virtualenv"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --disable-pip-version-check fastapi uvicorn httpx pyyaml
fi
[[ -x "$ROOT/bin/optictrace" ]] || (cd "$ROOT" && go build -o bin/ ./cmd/...)

mkdir -p .run
rm -f shop.db shop.db-wal shop.db-shm
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

# --- the agent, collector mode ---------------------------------------------
# No service.listen and no upstream: nothing is proxied. Each service governs
# itself in-process and POSTs the governed record here.
"$ROOT/bin/optictrace" run -config optic.yaml > .run/agent.log 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  curl -sS -o /dev/null --max-time 1 http://127.0.0.1:9095/healthz 2>/dev/null && break
  sleep 0.2
done

# --- the services -----------------------------------------------------------
start() {   # start <name> <port>
  PYTHONPATH="services" "$VENV/bin/uvicorn" "$1:app" \
    --host 127.0.0.1 --port "$2" --log-level warning > ".run/$1.log" 2>&1 &
  PIDS+=($!)
}
start catalog    8102
start payments   8103
start storefront 8101

for port in 8101 8102 8103; do
  for _ in $(seq 1 60); do
    curl -sS -o /dev/null --max-time 1 "http://127.0.0.1:$port/api/v1/health" 2>/dev/null && break
    sleep 0.2
  done
done

echo
echo "  storefront   http://127.0.0.1:8101   (public API)"
echo "  catalog      http://127.0.0.1:8102"
echo "  payments     http://127.0.0.1:8103"
echo "  dashboard    http://127.0.0.1:9095"
echo

if [[ "${1:-}" != "--no-drive" ]]; then
  "$PY" drive.py
  echo
  echo "  Verify:   $PY verify.py"
  echo "  Dashboard: http://127.0.0.1:9095"
fi

echo "Press Ctrl+C to stop."
wait
