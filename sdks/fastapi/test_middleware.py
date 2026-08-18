"""Dependency-free test: drives OpticTraceMiddleware as a raw ASGI app.

Run: python3 test_middleware.py
Set OPTIC_AGENT_URL to also ship records to a live agent.
"""

import asyncio
import json
import os
import tempfile

from optictrace_fastapi import OpticTraceMiddleware
from optictrace_fastapi.engine import Engine, redact_path, match_segments, split_path, REDACTED

import yaml

CONFIG = """
version: 1
service:
  name: fastapi-test
rules:
  - name: meter-ai
    match:
      path: "/ai/**"
    restrict: [response_body]
    meter:
      tokens: "$.usage.total_tokens"

  - name: no-capture-on-auth
    match: { path: "/auth/**" }
    restrict: [request_body, response_body, headers]
  - name: redact-payments
    match: { path: "/payments/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.card.number"]
    labels:
      tenant: "header:X-Tenant-ID"
"""

# --- engine parity checks ----------------------------------------------------
assert match_segments(split_path("/api/v1/**"), split_path("/api/v1/a/b"))
assert not match_segments(split_path("/api/*"), split_path("/api/a/b"))
assert redact_path(
    {"echo": {"card": {"number": "4111"}}, "card": {"number": "2"}}, ["**", "card", "number"]
) == {"echo": {"card": {"number": REDACTED}}, "card": {"number": REDACTED}}
policy = Engine(yaml.safe_load(CONFIG)).evaluate("POST", "/auth/login")
assert not policy.capture_request_body and not policy.capture_headers
print("✓ engine unit checks passed")


# --- ASGI integration ---------------------------------------------------------
async def echo_app(scope, receive, send):
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break
    out = {"ok": True, "echo": json.loads(body or b"{}")}
    if scope["path"].startswith("/ai/"):
        out["usage"] = {"prompt_tokens": 86, "completion_tokens": 42, "total_tokens": 128}
    payload = json.dumps(out).encode()
    await send({
        "type": "http.response.start",
        "status": 201,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({"type": "http.response.body", "body": payload})


async def call(mw, method, path, headers, body):
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "client": ("127.0.0.1", 1234),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(msg):
        sent.append(msg)

    await mw(scope, receive, send)
    return sent


async def main():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(CONFIG)
        cfg_path = f.name

    emitted = []
    mw = OpticTraceMiddleware(
        echo_app,
        config_path=cfg_path,
        agent_url=os.environ.get("OPTIC_AGENT_URL"),
        console_log=True,
    )
    # Intercept print output by wrapping _build_record instead: simpler — hook print.
    orig_build = mw._build_record

    def spy(*args, **kwargs):
        rec = orig_build(*args, **kwargs)
        emitted.append(rec)
        return rec

    mw._build_record = spy

    sent = await call(
        mw, "POST", "/payments/charge",
        {"content-type": "application/json", "authorization": "Bearer tok", "x-tenant-id": "acme"},
        json.dumps({"card": {"number": "4111111111111111"}, "amount": 5}).encode(),
    )
    resp_body = json.loads(sent[-1]["body"])
    assert resp_body["echo"]["card"]["number"] == "4111111111111111", "traffic must not be mutated"

    await call(mw, "POST", "/auth/login",
               {"content-type": "application/json"}, json.dumps({"password": "hunter2"}).encode())

    await asyncio.sleep(0.3)  # let executor ship records

    pay = next(r for r in emitted if r["path"] == "/payments/charge")
    auth = next(r for r in emitted if r["path"] == "/auth/login")

    pay_str = json.dumps(pay)
    assert "4111111111111111" not in pay_str, "card number leaked"
    assert REDACTED in pay_str
    assert pay["request_headers"]["authorization"] == REDACTED
    assert pay["labels"]["tenant"] == "acme"
    assert pay["matched_rules"] == ["redact-payments"]

    auth_str = json.dumps(auth)
    assert "hunter2" not in auth_str, "restricted body leaked"
    assert "request_headers" not in auth, "restricted headers leaked"
    assert auth["status"] == 201

    # --- the regression that made this SDK ship nothing at all ------------
    # `%z` renders "+0530"; the agent parses RFC3339 strictly and answered 400
    # for every record. Because _ship swallowed all exceptions, the SDK looked
    # healthy while delivering zero. Assert the wire format, not just the
    # fields — a field that never arrives is not a field.
    from datetime import datetime

    for rec in (pay, auth):
        ts = rec["time"]
        assert ts.endswith("Z"), f"timestamp {ts!r} is not UTC RFC3339"
        # Python's parser is the closest stand-in for Go's RFC3339 here; the
        # combination of "+0530" and this call is what fails.
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    # --- trace context ----------------------------------------------------
    # Correlation is the whole reason app logs can be attributed at all.
    assert len(pay["trace_id"]) == 32, pay["trace_id"]
    assert len(pay["span_id"]) == 16, pay["span_id"]
    assert pay["trace_id"] != auth["trace_id"], "separate requests share a trace id"

    await call(
        mw,
        "POST",
        "/payments/charge",
        {"content-type": "application/json",
         "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
        b"{}",
    )
    inherited = emitted[-1]
    assert inherited["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736", "inbound trace not adopted"
    assert inherited["parent_span_id"] == "00f067aa0ba902b7", "caller's span is not the parent"
    assert inherited["span_id"] != "00f067aa0ba902b7", "this hop reused the caller's span"

    # --- metering is independent of capture -------------------------------
    # The Python SDK ignored `meter:` entirely, so anyone billing from a
    # FastAPI service was attributing zero. Worse, this rule also restricts the
    # response body — if metering read the STORED body instead of the raw
    # bytes, the number would silently be missing exactly where it is
    # deliberately private.
    await call(mw, "POST", "/ai/complete",
               {"content-type": "application/json"}, b'{"prompt":"hi"}')
    ai = emitted[-1]
    assert ai.get("meters", {}).get("tokens") == 128, f"meters not extracted: {ai.get('meters')}"
    assert "response_body" not in ai, "restricted response body was stored"

    print("✓ ASGI middleware integration checks passed")
    if os.environ.get("OPTIC_AGENT_URL"):
        print(f"✓ records shipped to agent at {os.environ['OPTIC_AGENT_URL']}")
    os.unlink(cfg_path)


asyncio.run(main())
