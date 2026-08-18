#!/usr/bin/env python3
"""Assert that the demo pipeline behaved.

This is the test, not a demo: every check fails loudly if a governance
guarantee regressed, rather than printing output for a human to squint at.

    ./run.sh          # in one terminal
    ./drive.sh 28     # send traffic
    ./verify.py       # assert
"""
import json
import sys
import urllib.request

LEADS, SCORING, BUREAU = (
    "http://127.0.0.1:9001",
    "http://127.0.0.1:9002",
    "http://127.0.0.1:9003",
)

GREEN, RED, DIM, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[0m"
failures = []

# Unique per run, so the probe record is unambiguous.
PROBE_MARKER = f"probe-{__import__('os').getpid()}@example.com"
PROBE_PHONE = "9876500000"


def get(base, path):
    with urllib.request.urlopen(base + path) as r:
        return json.load(r)


def raw(base, path):
    with urllib.request.urlopen(base + path) as r:
        return r.read().decode()


def probe(marker):
    """Send one lead carrying a unique marker and return its stored record.

    The PII checks assert on traffic THIS run sent, not on whatever is already
    in the store. Otherwise a leak recorded under an earlier configuration
    fails the suite forever, and the suite stops being re-runnable — which
    matters, because the first thing anyone does after a failure is fix the
    config and run it again.
    """
    payload = json.dumps({"lead": {
        "source": "flipkart", "product": "personal-loan",
        "pan": "ABCPD1234E", "phone": PROBE_PHONE, "email": marker,
    }}).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8001/api/v1/leads", data=payload,
        headers={"Content-Type": "application/json",
                 "X-Tenant-ID": "acme-finance",
                 "Authorization": "Bearer super-secret-token"})
    with urllib.request.urlopen(req) as r:
        trace = r.headers.get("X-Trace-Id", "")
        r.read()
    # The store write is asynchronous; poll rather than sleep a fixed amount.
    for _ in range(600):
        for rec in get(LEADS, "/api/logs?limit=20")["records"]:
            if rec.get("request_body") and marker in str(rec.get("request_body")) + str(rec.get("response_body")):
                return rec, trace
            if rec.get("trace_id") and trace and rec["trace_id"] == trace and rec["service"] == "leads":
                return rec, trace
    return None, trace


def check(name):
    """Decorator: the function returns None to pass, or a failure message."""
    def wrap(fn):
        try:
            problem = fn()
        except Exception as e:                      # a broken check is a failure
            problem = f"{type(e).__name__}: {e}"
        if problem:
            failures.append(name)
            print(f"  {RED}✗{OFF} {name}\n      {problem}")
        else:
            print(f"  {GREEN}✓{OFF} {name}")
        return fn
    return wrap


def section(title):
    print(f"\n{DIM}── {title} {'─' * max(0, 58 - len(title))}{OFF}")


# --- governance -------------------------------------------------------------
section("governance")

PROBE, PROBE_TRACE = None, ""


@check("a probe lead reaches the store")
def _():
    global PROBE, PROBE_TRACE
    PROBE, PROBE_TRACE = probe(PROBE_MARKER)
    if PROBE is None:
        return "the probe lead never appeared in the store"


def probe_bodies():
    if PROBE is None:
        raise AssertionError("no probe record — see the check above")
    return (PROBE.get("request_body") or "") + (PROBE.get("response_body") or "")


@check("PII is redacted in the stored REQUEST body")
def _():
    body = PROBE.get("request_body") or ""
    if not body:
        return "the probe's request body was not captured"
    leaked = [p for p in (PROBE_PHONE, PROBE_MARKER, "ABCPD") if p in body]
    if leaked:
        return f"raw PII survived {leaked}: {body[:140]}"


# The lead service echoes the applicant back, so a request-only rule would
# leak on the way out. This is the check that catches that.
@check("PII is redacted in the stored RESPONSE body too")
def _():
    body = PROBE.get("response_body") or ""
    if not body:
        return "the probe's response body was not captured"
    leaked = [p for p in (PROBE_PHONE, PROBE_MARKER) if p in body]
    if leaked:
        return f"the response leaked {leaked}: {body[:160]}"


@check("the redaction placeholder is actually present")
def _():
    if "[REDACTED]" not in probe_bodies():
        return "nothing was masked; the rule may not be matching"


@check("the Authorization header is masked")
def _():
    hdr = (PROBE.get("request_headers") or {}).get("Authorization", "")
    if not hdr:
        return "the Authorization header was not captured"
    if "super-secret-token" in hdr:
        return "the bearer token was stored verbatim"


# --- partner segregation ----------------------------------------------------
section("partner segregation")


@check("the same endpoint splits by partner, taken from the BODY")
def _():
    got = {c["consumer"]: c["requests"] for c in get(LEADS, "/api/usage?label=partner")["consumers"]}
    missing = [p for p in ("flipkart", "samsung", "amazon", "xiaomi") if p not in got]
    if missing:
        return f"partners missing from attribution: {missing} (got {got})"


@check("body criteria classified marketplace vs oem")
def _():
    got = {c["consumer"]: c["requests"] for c in get(LEADS, "/api/usage?label=channel")["consumers"]}
    if not (got.get("marketplace", 0) and got.get("oem", 0)):
        return f"channel classification wrong: {got}"


@check("filtering by tag returns only that partner")
def _():
    recs = get(LEADS, "/api/logs?label.partner=samsung&limit=100")["records"]
    if not recs:
        return "no samsung records returned"
    wrong = [r["labels"].get("partner") for r in recs if r["labels"].get("partner") != "samsung"]
    if wrong:
        return f"{len(wrong)} record(s) from another partner leaked in: {set(wrong)}"


@check("two tags compose as an AND")
def _():
    one = get(LEADS, "/api/logs?label.partner=flipkart")["total"]
    two = get(LEADS, "/api/logs?label.partner=flipkart&label.product=credit-card")["total"]
    if not (0 < two <= one):
        return f"AND is wrong: partner={one}, partner+product={two}"


# --- trace correlation ------------------------------------------------------
section("trace correlation")


def traces():
    out = {}
    for r in get(LEADS, "/api/logs?limit=200")["records"]:
        out.setdefault(r.get("trace_id", ""), []).append(r)
    return out


@check("every hop of one request shares a trace id")
def _():
    multi = {t: {r["service"] for r in rs} for t, rs in traces().items()}
    if not any(len(s) > 1 for s in multi.values()):
        seen = [(t[:8], sorted(s)) for t, s in list(multi.items())[:4]]
        return f"no trace spans more than one service; saw {seen}"


@check("the tree is nested, not flat")
def _():
    tree = next((rs for rs in traces().values()
                 if len({r["service"] for r in rs}) == 3), None)
    if not tree:
        return "no single trace covered all three services"
    spans = {r["span_id"]: r for r in tree}
    roots = [r for r in tree if not r.get("parent_span_id")]
    orphans = [r for r in tree if r.get("parent_span_id") and r["parent_span_id"] not in spans]
    if len(roots) != 1:
        return f"expected exactly 1 root span, found {len(roots)}"
    if orphans:
        return f"{len(orphans)} span(s) point at a parent outside the trace"


@check("?trace= returns exactly that request and nothing else")
def _():
    t = traces()
    tid = max(t, key=lambda k: len(t[k]))
    want = len(t[tid])
    got = get(LEADS, f"/api/logs?trace={tid}")
    if got["total"] != want:
        return f"trace {tid[:8]} has {want} hops in the full list, ?trace= returned {got['total']}"
    strays = [r["trace_id"] for r in got["records"] if r["trace_id"] != tid]
    if strays:
        return f"the filter returned records from other traces: {set(s[:8] for s in strays)}"


@check("the trace id is returned to the caller")
def _():
    payload = json.dumps({"lead": {"source": "flipkart", "product": "personal-loan",
                                   "pan": "ABCPD1234E", "phone": "9876500000",
                                   "email": "probe@example.com"}}).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8001/api/v1/leads", data=payload,
        headers={"Content-Type": "application/json", "X-Tenant-ID": "acme-finance"})
    with urllib.request.urlopen(req) as r:
        tid = r.headers.get("X-Trace-Id", "")
    if len(tid) != 32:
        return f"X-Trace-Id = {tid!r}, want 32 hex chars"


# --- metering, sampling, errors --------------------------------------------
section("metering, sampling, errors")


@check("tokens were metered out of the scoring response")
def _():
    recs = get(SCORING, "/api/logs?limit=100")["records"]
    if not any((r.get("meters") or {}).get("tokens") for r in recs):
        return "no scoring record carries a tokens meter"


@check("sampling dropped internal bodies but keep_errors rescued the failures")
def _():
    recs = get(SCORING, "/api/logs?limit=200")["records"]
    if not recs:
        return "no scoring records"
    errs = [r for r in recs if r["status"] >= 500]
    kept = [r for r in errs if r.get("response_body")]
    dropped = [r for r in recs if r["status"] < 500 and not r.get("response_body")]
    if not errs:
        return "no 5xx was produced — send more traffic"
    if not kept:
        return f"keep_errors rescued none of the {len(errs)} failures"
    if not dropped:
        return "sample: 0.25 kept every body — sampling is not applying"


@check("the error rate reaches the aggregates")
def _():
    d = get(SCORING, "/api/stats")
    if not (d["errors"] > 0 and d["error_rate"] > 0):
        return f"errors={d['errors']} error_rate={d['error_rate']}"


# --- the leak this pipeline exists to expose -------------------------------
section("the leak the pipeline is meant to expose")


# The bureau sidecar deliberately has NO rule covering the card or Aadhaar in
# the third-party response. Finding it is the whole point of the tool.
@check("scan finds the ungoverned card and Aadhaar in the bureau response")
def _():
    kinds = {f["kind"] for f in get(BUREAU, "/api/scan?window=1h")["findings"]}
    missing = [k for k in ("credit-card", "aadhaar") if k not in kinds]
    if missing:
        return f"scan missed {missing}; it found {sorted(kinds)}"


@check("scan never prints a raw sensitive value")
def _():
    body = raw(BUREAU, "/api/scan?window=1h")
    for secret in ("4111111111111111", "999941057058"):
        if secret in body:
            return f"scan output contains the raw value {secret[:6]}…"


# --- prometheus ------------------------------------------------------------
section("prometheus")


@check("custom tags became Prometheus dimensions")
def _():
    lines = [l for l in raw(LEADS, "/metrics").splitlines()
             if l.startswith("optictrace_requests_total")]
    if not lines:
        return "no optictrace_requests_total series"
    missing = [d for d in ("partner=", "product=", "channel=")
               if not any(d in l for l in lines)]
    if missing:
        return f"missing dimensions: {missing}"


@check("each service reports separately")
def _():
    names = {s["service"] for s in get(LEADS, "/api/services")["services"]}
    missing = {"leads", "scoring", "bureau"} - names
    if missing:
        return f"services missing from the fleet view: {missing} (saw {names})"


# --- result ----------------------------------------------------------------
print()
if failures:
    print(f"{RED}{len(failures)} check(s) failed{OFF}")
    for f in failures:
        print(f"  · {f}")
    print()
    sys.exit(1)
print(f"{GREEN}all checks passed{OFF}\n")
