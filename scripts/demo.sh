#!/usr/bin/env bash
# Local end-to-end demo: mock upstream + OpticTrace agent + sample traffic.
# Usage: ./scripts/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o bin/ ./cmd/...

./bin/mocktarget -addr :9000 &
MOCK_PID=$!
./bin/optictrace run -config optic.yaml &
AGENT_PID=$!
trap 'kill $MOCK_PID $AGENT_PID 2>/dev/null' EXIT

for _ in $(seq 1 30); do
  curl -s -o /dev/null localhost:9095/healthz && break
  sleep 0.1
done

echo
echo "==> Generating traffic (payments w/ secrets, restricted auth, plain GETs)…"
for i in $(seq 1 15); do
  curl -s -o /dev/null -X POST localhost:8080/api/v1/payments/charge \
    -H 'Content-Type: application/json' \
    -H 'Authorization: Bearer topsecret123' \
    -H 'X-Tenant-ID: acme-corp' -H 'X-Region: ap-south-1' \
    -d '{"amount": 4200, "credit_card": {"number": "4111111111111111", "cvv": "123"}}'
  curl -s -o /dev/null -X POST localhost:8080/api/v1/auth/login \
    -H 'Content-Type: application/json' -d '{"username": "ada", "password": "hunter2"}'
  curl -s -o /dev/null "localhost:8080/api/v1/users/$i"
done

echo
echo "  Dashboard:   http://localhost:9095"
echo "  Prometheus:  http://localhost:9095/metrics"
echo "  Logs API:    http://localhost:9095/api/logs?path=/api/v1/payments"
echo
echo "Press Ctrl+C to stop."
wait
