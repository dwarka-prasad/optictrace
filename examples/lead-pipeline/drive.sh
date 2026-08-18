#!/usr/bin/env bash
# Send realistic multi-partner lead traffic through the pipeline.
set -uo pipefail
cd "$(dirname "$0")"
N=${1:-24}
partners=(flipkart samsung flipkart amazon samsung xiaomi flipkart direct)
products=(personal-loan credit-card personal-loan)
echo "sending $N leads…"
for i in $(seq 1 "$N"); do
  p=${partners[$(( (i-1) % ${#partners[@]} ))]}
  prod=${products[$(( (i-1) % ${#products[@]} ))]}
  curl -s -o /dev/null \
    -H 'Content-Type: application/json' \
    -H 'X-Tenant-ID: acme-finance' \
    -H 'Authorization: Bearer super-secret-token' \
    -d "{\"lead\":{\"source\":\"$p\",\"product\":\"$prod\",\"pan\":\"ABCPD1234E\",\"phone\":\"98765$(printf '%05d' $i)\",\"email\":\"lead$i@example.com\"}}" \
    http://127.0.0.1:8001/api/v1/leads
done
echo "done"
