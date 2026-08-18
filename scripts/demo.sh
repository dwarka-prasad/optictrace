#!/usr/bin/env bash
# Local end-to-end demo: mock upstream + OpticTrace agent + seeded traffic,
# left running so you can click around the dashboard.
#
#   ./scripts/demo.sh
#
# Traffic generation lives in scripts/seed.sh and is NOT duplicated here — two
# copies drift, and the copy nobody regenerates is the one that stops covering
# the features that were added since.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/go/bin:$PATH"

CONFIG="${CONFIG:-optic.yaml}"

go build -o bin/ ./cmd/...

./bin/mocktarget -addr :9000 -applogs "http://localhost:9095" &
MOCK_PID=$!
./bin/optictrace run -config "$CONFIG" &
AGENT_PID=$!
trap 'kill $MOCK_PID $AGENT_PID 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  curl -sS -o /dev/null --max-time 1 localhost:9095/healthz 2>/dev/null && break
  sleep 0.1
done

echo
echo "==> Seeding traffic (multi-tenant payments, restricted auth, metered AI,"
echo "    sampled reads, an ungoverned route, errors, slow calls, one trace)…"
./scripts/seed.sh

cat <<'TXT'

  Dashboard:   http://localhost:9095
  Prometheus:  http://localhost:9095/metrics
  Logs API:    http://localhost:9095/api/logs?path=/api/v1/payments
  One tenant:  http://localhost:9095/api/logs?label.tenant=globex
  Marketplace: http://localhost:9095/api/logs?label.channel=marketplace

Press Ctrl+C to stop.
TXT
wait
