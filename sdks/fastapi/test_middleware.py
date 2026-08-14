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
    payload = json.dumps({"ok": True, "echo": json.loads(body or b"{}")}).encode()
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

    print("✓ ASGI middleware integration checks passed")
    if os.environ.get("OPTIC_AGENT_URL"):
        print(f"✓ records shipped to agent at {os.environ['OPTIC_AGENT_URL']}")
    os.unlink(cfg_path)


asyncio.run(main())
