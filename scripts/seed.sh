#!/usr/bin/env bash
# Drive a realistic spread of traffic through a running OpticTrace agent, so
# the dashboard, `optictrace review` and the billing report all have something
# true to work with.
#
#   ./scripts/seed.sh                 # start a stack if needed, seed, stop it
#   ./scripts/seed.sh                 # (stack already up: seed and leave it up)
#   PROXY=localhost:8080 ./scripts/seed.sh
#   CONFIG=deploy/compose/optic.yaml ROUNDS=4 ./scripts/seed.sh
#
# The point is coverage, not volume: every governance mechanism in the config
# needs traffic that actually triggers it. Fast 2xx calls from one tenant
# exercise almost nothing, which is how a broken rule ships.
set -euo pipefail
cd "$(dirname "$0")/.."

PROXY="${PROXY:-localhost:8080}"
ADMIN="${ADMIN:-localhost:9095}"
CONFIG="${CONFIG:-optic.yaml}"
ROUNDS="${ROUNDS:-6}"
# AUTOSTART=0 means "an agent must already be there" — the compose seeder runs
# in a container with no Go toolchain, so it needs a clear failure rather than
# a build attempt.
AUTOSTART="${AUTOSTART:-1}"
WAIT_SECS="${WAIT_SECS:-20}"

post() { curl -sS -o /dev/null -X POST "$PROXY$1" -H 'Content-Type: application/json' "${@:2}"; }
get()  { curl -sS -o /dev/null "$PROXY$1" "${@:2}"; }

# --- wait for an agent, then bring one up if allowed ------------------------
wait_for_admin() {
  local deadline=$(( $(date +%s) + $1 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    curl -sS -o /dev/null --max-time 1 "$ADMIN/healthz" 2>/dev/null && return 0
    sleep 0.25
  done
  return 1
}

STARTED=""
if ! wait_for_admin "$WAIT_SECS"; then
  if [[ "$AUTOSTART" != "1" ]]; then
    echo "✗ no agent answering on $ADMIN after ${WAIT_SECS}s" >&2
    exit 1
  fi
  echo "==> No agent on $ADMIN — starting one (config: $CONFIG)"
  export PATH="$HOME/.local/go/bin:$PATH"
  go build -o bin/ ./cmd/...
  ./bin/mocktarget -addr :9000 -applogs "http://localhost:9095" >/dev/null 2>&1 &
  MOCK_PID=$!
  ./bin/optictrace run -config "$CONFIG" >/dev/null 2>&1 &
  AGENT_PID=$!
  STARTED=yes
  trap 'kill $MOCK_PID $AGENT_PID 2>/dev/null || true' EXIT
  wait_for_admin "$WAIT_SECS" || { echo "✗ agent failed to come up" >&2; exit 1; }
fi

# --- the tenant matrix ------------------------------------------------------
# Three tenants in three geographies, on three plans, reached through two
# channels. This is the shape that makes tagging worth having: the same route,
# the same method, the same payload schema — separable only by label.
TENANTS=(acme-corp globex initech)
REGIONS=(ap-south-1 eu-west-1 us-east-2)
PLANS=(gold silver platinum)
PARTNERS=(flipkart amazon walk-in direct)

echo "==> Seeding $ROUNDS round(s) of traffic through $PROXY"
for r in $(seq 1 "$ROUNDS"); do
  for i in "${!TENANTS[@]}"; do
    tenant="${TENANTS[$i]}"; region="${REGIONS[$i]}"; plan="${PLANS[$i]}"
    partner="${PARTNERS[$(( (r + i) % ${#PARTNERS[@]} ))]}"
    idem="$(printf '%s-%s-%s' "$tenant" "$r" "$i")"

    # Payments: secrets to redact, a partner in the payload to tag on.
    post "/api/v1/payments/charge?api_key=live_sk_should_be_masked&page=$r" \
      -H "Authorization: Bearer topsecret123" \
      -H "X-Tenant-ID: $tenant" -H "X-Region: $region" -H "X-Plan: $plan" \
      -H "X-Idempotency-Key: $idem" \
      -d "{\"source\":\"$partner\",\"amount\":$(( 1000 + r * 37 )),
           \"credit_card\":{\"number\":\"4111111111111111\",\"cvv\":\"123\"},
           \"customer\":{\"name\":\"Ada Lovelace\",\"email\":\"ada@example.com\"}}"

    # Credentials: nothing but metadata may be recorded here.
    post "/api/v1/auth/login" -H "X-Tenant-ID: $tenant" \
      -d '{"username":"ada","password":"hunter2"}'

    # Metering: the prompt stays private, the tokens are still counted.
    post "/api/v1/ai/complete" -H "X-Tenant-ID: $tenant" -H "X-Region: $region" \
      -d "{\"model\":\"claude-3\",\"prompt\":\"summarise invoice $r for $tenant\"}"

    # Hot read path: sampled, so volume is what makes the sampling visible.
    for u in 1 2 3; do
      get "/api/v1/users/$(( r * 10 + u ))" -H "X-Tenant-ID: $tenant"
    done

    # Ungoverned on purpose — this is what `optictrace scan` should flag.
    post "/api/v1/orders" -H "X-Tenant-ID: $tenant" \
      -d "{\"sku\":\"SKU-$r\",\"qty\":$r,\"card\":{\"number\":\"4111111111111111\"}}"
  done

  # --- the unhappy paths ----------------------------------------------------
  # keep_errors and keep_slower_than only mean something if some traffic is
  # actually failing or slow, so make some.
  post "/api/v1/payments/charge?outcome=declined" \
    -H "X-Tenant-ID: acme-corp" -H "X-Region: ap-south-1" \
    -d '{"source":"flipkart","amount":99999,"credit_card":{"number":"4111111111111111","cvv":"999"}}'
  post "/api/v1/payments/charge?status=502" \
    -H "X-Tenant-ID: globex" -H "X-Region: eu-west-1" \
    -d '{"source":"amazon","amount":500}'
  get "/api/v1/users/404?status=404" -H "X-Tenant-ID: initech"
  get "/api/v1/users/$(( r * 100 ))?delay=400ms" -H "X-Tenant-ID: acme-corp"

  # --- internet noise -------------------------------------------------------
  # Anything reachable gets probed. These 404 at the upstream, but they still
  # appear as governed-by-nothing routes, which is the other half of what
  # `optictrace scan` reports on — and a real config has to decide whether it
  # wants scanner traffic in its telemetry at all.
  get "/wp-login.php"
  get "/.env"
  get "/api/v1/../../etc/passwd"

  # --- one correlated group ------------------------------------------------
  # A client doing several calls under a single trace: same trace id, a fresh
  # parent span per call. Without this every record is its own trace and the
  # inspector's trace view has nothing to show.
  trace="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  for hop in 1 2 3; do
    span="$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    post "/api/v1/payments/charge" \
      -H "traceparent: 00-$trace-$span-01" \
      -H "X-Tenant-ID: acme-corp" -H "X-Region: ap-south-1" -H "X-Plan: platinum" \
      -d "{\"source\":\"flipkart\",\"amount\":$(( hop * 100 )),\"leg\":$hop}"
  done
done

# Give the async store queue a moment to drain before anyone reads it.
sleep 1

total="$(curl -sS "$ADMIN/api/logs?window=24h&limit=1" | tr ',' '\n' | grep -m1 -o '"total":[0-9]*' | cut -d: -f2 || true)"
echo "==> Seeded. Records in the last 24h: ${total:-unknown}"
echo "    Dashboard: http://$ADMIN"
if [[ -n "$STARTED" ]]; then
  echo "==> Stopping the stack this script started (the store keeps the data)."
fi
