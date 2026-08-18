#!/usr/bin/env bash
# Start the pipeline: three services, each behind its own OpticTrace sidecar,
# all writing to one store. Ctrl-C stops everything.
set -uo pipefail
cd "$(dirname "$0")"

OT=${OT:-optictrace}
command -v "$OT" >/dev/null 2>&1 || OT=$(cd ../.. && go build -o /tmp/optictrace-demo ./cmd/optictrace && echo /tmp/optictrace-demo)

mkdir -p .run
rm -f pipeline.db pipeline.db-wal pipeline.db-shm
pids=()
cleanup() { echo; echo "stopping…"; for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT INT TERM

for svc in leadsvc scoringsvc bureausvc; do
  (cd ../.. && go build -o "examples/lead-pipeline/.run/$svc" "./examples/lead-pipeline/$svc") || exit 1
done

# Applications first, then their sidecars.
SCORING_URL=http://127.0.0.1:8002 ./.run/leadsvc    > .run/leadsvc.log 2>&1 &   pids+=($!)
BUREAU_URL=http://127.0.0.1:8003  ./.run/scoringsvc > .run/scoringsvc.log 2>&1 & pids+=($!)
./.run/bureausvc > .run/bureausvc.log 2>&1 & pids+=($!)

for c in bureau scoring leads; do
  "$OT" run -config "optic/$c.yaml" > ".run/$c.log" 2>&1 & pids+=($!)
done

echo "waiting for the pipeline…"
for port in 7001 7002 7003 8001 8002 8003; do
  for _ in $(seq 1 600); do
    (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null && { exec 3<&-; break; }
  done
done

cat <<EOF

  pipeline up

    POST http://127.0.0.1:8001/api/v1/leads     the entry point (through OpticTrace)

    http://127.0.0.1:9001   leads    dashboard · /metrics · /api/*
    http://127.0.0.1:9002   scoring
    http://127.0.0.1:9003   bureau

  send traffic:   ./drive.sh
  check it:       ./verify.py

EOF
wait
