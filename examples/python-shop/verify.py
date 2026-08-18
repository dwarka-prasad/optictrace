"""Assert that the shop's governance actually holds.

Run against a live stack (./run.sh). Every check states what would be wrong if
it failed — a test whose failure you cannot interpret is a test nobody fixes.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request

BASE = "http://127.0.0.1:9095"
ok, bad = 0, []


def check(name, cond, detail=""):
    global ok
    if cond:
        ok += 1
        print(f"  \033[32m✓\033[0m {name}")
    else:
        bad.append(name)
        print(f"  \033[31m✗\033[0m {name}" + (f"\n      {detail}" if detail else ""))


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=20) as r:
        return json.loads(r.read())


def all_records():
    out, off = [], 0
    while True:
        d = get(f"/api/logs?window=2h&limit=200&offset={off}")
        out += d["records"]
        off += len(d["records"])
        if not d["records"] or off >= d["total"]:
            return out


recs = all_records()
logs = get("/api/applogs?window=2h&limit=5000")["lines"]
blob = json.dumps(recs) + json.dumps(logs)

print(f"\n{len(recs)} record(s), {len(logs)} log line(s)\n")

# --- the SDK actually delivered ---------------------------------------------
# This is the check that would have caught the RFC3339 bug: the middleware
# swallowed every ship failure, so "no records" looked like "no traffic".
check("records reached the agent from the SDK", len(recs) > 0)
check("all three services report", {r["service"] for r in recs} >= {"storefront", "catalog", "payments"},
      f"saw {sorted({r['service'] for r in recs})}")
check("records are SDK-sourced, not proxied", all(r.get("source") == "fastapi" for r in recs))

# --- nothing sensitive survives ---------------------------------------------
for secret, what in [
    ("4111111111111111", "card number"),
    ("topsecret123", "bearer token"),
    ("hunter2", "login password"),
    ("ada@example.com", "customer email"),
]:
    check(f"{what} never stored", secret not in blob)

cvvs = set()
for r in recs:
    for f in ("request_body", "response_body"):
        cvvs |= set(re.findall(r'"cvv"\s*:\s*"([^"]*)"', r.get(f) or ""))
check("every stored cvv is masked", cvvs <= {"[REDACTED]"}, f"found {cvvs}")

logins = [r for r in recs if r["path"] == "/api/v1/login"]
check("login requests were recorded at all", len(logins) > 0)
check("login bodies and headers never captured",
      all(not r.get("request_body") and not r.get("request_headers") for r in logins))
check("login is still attributed to a tenant (capture != attribution)",
      any((r.get("labels") or {}).get("tenant") for r in logins))

# --- correlation is a fact, not a guess -------------------------------------
traces = {}
for r in recs:
    if r.get("trace_id"):
        traces.setdefault(r["trace_id"], []).append(r)
multi = {t: hops for t, hops in traces.items() if len(hops) > 1}
check("orders produce multi-service traces", len(multi) > 0, f"{len(traces)} traces, none multi-hop")

if multi:
    hops = max(multi.values(), key=len)
    services = {h["service"] for h in hops}
    check("one order spans storefront, catalog and payments",
          services >= {"storefront", "catalog", "payments"}, f"saw {sorted(services)}")
    roots = [h for h in hops if not h.get("parent_span_id")]
    check("the trace has exactly one root", len(roots) == 1, f"{len(roots)} roots")
    if roots:
        root = roots[0]
        check("storefront is the root of the order trace", root["service"] == "storefront",
              f"root was {root['service']}")
        children = [h for h in hops if h.get("parent_span_id") == root["span_id"]]
        check("downstream calls are children of the order, not siblings",
              len(children) >= 2, f"{len(children)} children of the root span")

# --- application logs are attached to the right request ---------------------
check("application logs were collected", len(logs) > 0)
spans = {r["span_id"] for r in recs}
orphans = [l for l in logs if l["span_id"] not in spans]
check("every stored log line belongs to a recorded span", not orphans,
      f"{len(orphans)} line(s) reference an unknown span")

with_logs = {l["span_id"] for l in logs}
order_spans = {r["span_id"] for r in recs if r["path"] == "/api/v1/orders"}
check("order requests carry their own log lines", order_spans & with_logs != set())

masked = [l for l in logs if "[REDACTED]" in l["message"]]
check("a careless debug line was masked, not dropped", len(masked) > 0,
      "payments logs the card number on purpose; it must be stored redacted")
check("error-level lines survive", any(l["level"] == "error" for l in logs))

# --- rules that only matter when things go wrong ----------------------------
check("404s from the sampled catalog route were kept (keep_errors)",
      any(r["status"] == 404 and r["service"] == "catalog" for r in recs))
check("payment declines were recorded", any(r["status"] == 402 for r in recs))

# --- billing ----------------------------------------------------------------
usage = get("/api/usage?window=2h")
consumers = {c["consumer"] for c in usage["consumers"]}
check("usage is attributed per tenant", consumers >= {"acme-corp", "globex", "initech"},
      f"saw {sorted(consumers)}")
check("order value was metered", any((c.get("meters") or {}).get("order_value") for c in usage["consumers"]))

print(f"\n{ok} passed, {len(bad)} failed")
sys.exit(1 if bad else 0)
