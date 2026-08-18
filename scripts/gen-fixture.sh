#!/usr/bin/env bash
# Regenerate examples/traffic-sample.jsonl — the traffic the governance PR bot
# reviews every pull request against.
#
#   ./scripts/gen-fixture.sh
#
# The fixture is generated from a real run rather than hand-written, because a
# hand-written one drifts: it keeps whatever fields existed the day someone
# typed it, so the bot silently stops exercising everything added since. It is
# produced against deploy/compose/optic.yaml — the same config the workflow
# passes as -config — so the rules and the traffic cannot disagree.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/go/bin:$PATH"

OUT="examples/traffic-sample.jsonl"
WORK="$(mktemp -d)"
trap 'kill ${MOCK_PID:-} ${AGENT_PID:-} 2>/dev/null || true; rm -rf "$WORK"' EXIT

go build -o bin/ ./cmd/...

# The compose config addresses container paths and container DNS. Rewrite only
# those, so every rule under review stays byte-identical to what ships.
sed -e 's|http://demo-upstream:9000|http://localhost:9000|' \
    -e 's|/data/optictrace.db|'"$WORK"'/fixture.db|' \
    -e 's|/data/audit.jsonl|'"$WORK"'/audit.jsonl|' \
    -e 's|"0.0.0.0:9095"|"127.0.0.1:9095"|' \
    deploy/compose/optic.yaml > "$WORK/optic.yaml"
./bin/optictrace validate -config "$WORK/optic.yaml" >/dev/null

./bin/mocktarget -addr :9000 -applogs "http://localhost:9095" >/dev/null 2>&1 &
MOCK_PID=$!
./bin/optictrace run -config "$WORK/optic.yaml" >/dev/null 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 50); do
  curl -sS -o /dev/null --max-time 1 localhost:9095/healthz 2>/dev/null && break
  sleep 0.1
done

ROUNDS="${ROUNDS:-4}" ./scripts/seed.sh >/dev/null

# The file exporter emits governed records — post-restriction, post-redaction —
# as JSONL, which is exactly the shape `optictrace review -from-file` reads.
sleep 3
kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

if [[ ! -s "$WORK/audit.jsonl" ]]; then
  echo "✗ exporter produced nothing — is the audit-log exporter still in deploy/compose/optic.yaml?" >&2
  exit 1
fi

# Sort by time so the fixture reads chronologically, and drop the volume down
# to something reviewable by hand.
python3 - "$WORK/audit.jsonl" "$OUT" <<'PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
recs = [json.loads(l) for l in open(src) if l.strip()]
recs.sort(key=lambda r: r.get("time", ""))
# Keep every distinct (route, status, sorted label keys) combination, then top
# up to a cap — so trimming can never silently drop the only record that
# exercises a rule.
seen, kept = set(), []
for r in recs:
    key = (r.get("route"), r.get("status"), tuple(sorted((r.get("labels") or {}))))
    if key not in seen:
        seen.add(key)
        kept.append(r)
CAP = 60
for r in recs:
    if len(kept) >= CAP:
        break
    if r not in kept:
        kept.append(r)
kept.sort(key=lambda r: r.get("time", ""))
with open(dst, "w") as f:
    for r in kept:
        f.write(json.dumps(r, sort_keys=True) + "\n")
print(f"wrote {len(kept)} record(s) to {dst} ({len(seen)} distinct route/status/label shapes)")
PY

./bin/optictrace review -config deploy/compose/optic.yaml -from-file "$OUT" -window 720h -out "$WORK/review.md" >/dev/null
echo "✓ fixture regenerated and accepted by \`optictrace review\`"
