"""OpticTrace middleware for FastAPI (and any ASGI framework).

    from fastapi import FastAPI
    from optictrace_fastapi import OpticTraceMiddleware

    app = FastAPI()
    app.add_middleware(
        OpticTraceMiddleware,
        config_path="optic.yaml",
        agent_url="http://localhost:9095",
    )

Pure ASGI — no hard dependency on FastAPI or Starlette. Governance
(restriction + redaction) runs in-process; the governed record ships to the
OpticTrace agent's /api/ingest in a background task (fire-and-forget).
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import time
import urllib.error
import urllib.request
from typing import Optional

import yaml

from .engine import Engine, Policy, REDACTED, first_string  # noqa: F401 (public API)
from .logs import OpticTraceLogHandler
from .trace import HEADER as TRACEPARENT, TraceContext, current as current_span, from_header, outbound_headers

__all__ = [
    "OpticTraceMiddleware",
    "Engine",
    "Policy",
    "REDACTED",
    "OpticTraceLogHandler",
    "TraceContext",
    "TRACEPARENT",
    "current_span",
    "from_header",
    "outbound_headers",
]


class OpticTraceMiddleware:
    def __init__(
        self,
        app,
        config_path: str = "optic.yaml",
        agent_url: Optional[str] = None,
        service_name: Optional[str] = None,
        console_log: bool = False,
    ):
        self.app = app
        with open(config_path, encoding="utf-8") as f:
            self.engine = Engine(yaml.safe_load(f))
        self.service = service_name or self.engine.service_name
        self.ingest_url = agent_url.rstrip("/") + "/api/ingest" if agent_url else None
        self.console_log = console_log
        # Delivery counters. The previous version swallowed every failure with
        # a bare `except: pass`, so a malformed timestamp made it drop 100% of
        # records while looking perfectly healthy. Silence is the bug.
        self.shipped = 0
        self.ship_failed = 0
        self.last_ship_error: Optional[str] = None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        method = scope["method"]
        path = scope["path"]
        policy = self.engine.evaluate(method, path)
        sampled = policy.sample_rate >= 1.0 or random.random() < policy.sample_rate

        req_headers = {
            k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])
        }

        # Adopt the caller's trace, or start one. Setting the ContextVar here
        # is what lets a log line or an outbound call name this exact span
        # without the application threading anything through by hand.
        ctx = from_header(req_headers.get(TRACEPARENT, ""))
        token = current_span.set(ctx)

        state = {
            "status": 200,
            "resp_headers": {},
            "req_body": bytearray(),
            "resp_body": bytearray(),
            "req_bytes": 0,
            "resp_bytes": 0,
            "req_trunc": False,
            "resp_trunc": False,
        }

        capture_req = sampled and policy.capture_request_body
        capture_resp = sampled and policy.capture_response_body
        # Meters read the response bytes even when the body is not STORED:
        # metering is independent of capture, which is what lets a rule keep a
        # prompt private while still counting the tokens in it. Without this,
        # `restrict: [response_body]` would silently zero the billing.
        need_resp_bytes = capture_resp or bool(policy.meters)

        async def tee_receive():
            message = await receive()
            if capture_req and message["type"] == "http.request":
                body = message.get("body", b"")
                state["req_bytes"] += len(body)
                room = policy.capture_limit - len(state["req_body"])
                if room > 0:
                    state["req_body"] += body[:room]
                if len(body) > room:
                    state["req_trunc"] = True
            return message

        async def tee_send(message):
            if message["type"] == "http.response.start":
                state["status"] = message["status"]
                state["resp_headers"] = {
                    k.decode("latin-1"): v.decode("latin-1")
                    for k, v in message.get("headers", [])
                }
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                state["resp_bytes"] += len(body)
                if need_resp_bytes:
                    room = policy.capture_limit - len(state["resp_body"])
                    if room > 0:
                        state["resp_body"] += body[:room]
                    if len(body) > room and capture_resp:
                        state["resp_trunc"] = True
            await send(message)

        try:
            await self.app(scope, tee_receive, tee_send)
        finally:
            current_span.reset(token)
            duration_ms = (time.perf_counter() - start) * 1000
            record = self._build_record(
                scope, method, path, policy, req_headers, state, duration_ms, ctx
            )
            if self.console_log or not self.ingest_url:
                print(json.dumps({"msg": "http_exchange", **record}), flush=True)
            if self.ingest_url:
                # Fire-and-forget in a worker thread — urllib is blocking.
                asyncio.get_running_loop().run_in_executor(None, self._ship, record)

    def _build_record(self, scope, method, path, policy, req_headers, state, duration_ms, ctx=None):
        client = scope.get("client") or ("", 0)
        record = {
            # RFC3339. `%z` renders "+0530", which the agent's strict RFC3339
            # parser rejects — every record shipped that way was answered with
            # a 400 and silently dropped by the old error handling.
            "time": _rfc3339(time.time()),
            "service": self.service,
            "method": method,
            "path": path,
            "route": policy.route_pattern or path,
            "status": state["status"],
            "duration_ms": duration_ms,
            "remote": f"{client[0]}:{client[1]}" if client[0] else "",
            "source": "fastapi",
            "req_bytes": state["req_bytes"] or int(req_headers.get("content-length") or 0),
            "resp_bytes": state["resp_bytes"],
        }
        if ctx is not None:
            record["trace_id"] = ctx.trace_id
            record["span_id"] = ctx.span_id
            if ctx.parent_span_id:
                record["parent_span_id"] = ctx.parent_span_id
        if policy.matched_rules:
            record["matched_rules"] = policy.matched_rules
        if policy.capture_headers:
            record["request_headers"] = policy.sanitize_headers(req_headers)
            record["response_headers"] = policy.sanitize_headers(state["resp_headers"])
        if state["req_body"]:
            record["request_body"] = policy.redact_body(
                bytes(state["req_body"]), req_headers.get("content-type", "")
            )
            if state["req_trunc"]:
                record["req_truncated"] = True
        governed_response = None
        if state["resp_body"]:
            meters = policy.extract_meters(bytes(state["resp_body"]))
            if meters:
                record["meters"] = meters
            # Buffered for metering is not the same as allowed to be stored.
            if policy.capture_response_body:
                governed_response = policy.redact_body(
                    bytes(state["resp_body"]), state["resp_headers"].get("content-type", "")
                )
                record["response_body"] = governed_response
                if state["resp_trunc"]:
                    record["resp_truncated"] = True
        if policy.labels:
            query = {}
            qs = scope.get("query_string", b"").decode("latin-1")
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    query.setdefault(k, v)
            # Labels read the GOVERNED bodies, so a label can never copy a
            # value the policy just masked into a Prometheus dimension.
            def _parse(text):
                try:
                    return json.loads(text) if text else None
                except (ValueError, TypeError):
                    return None

            req_doc = _parse(record.get("request_body"))
            if req_doc is None and state["req_body"]:
                governed = policy.redact_body(
                    bytes(state["req_body"]), req_headers.get("content-type", "")
                )
                req_doc = _parse(governed) if not governed.startswith("<") else None
            res_doc = _parse(governed_response)

            labels = {}
            for name, src in policy.labels.items():
                labels[name] = _label_value(str(src), req_headers, query, path, req_doc, res_doc)
            record["labels"] = labels
        return record

    def _ship(self, record: dict):
        """Deliver one record. Never raises into the application — but never
        silently succeeds either: failures are counted and the last one is
        kept, so "is my telemetry actually arriving" has an answer."""
        try:
            req = urllib.request.Request(
                self.ingest_url,
                data=json.dumps(record).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
            self.shipped += 1
        except urllib.error.HTTPError as e:
            self.ship_failed += 1
            self.last_ship_error = f"HTTP {e.code}: {e.read()[:200].decode('utf-8', 'replace')}"
        except Exception as e:  # noqa: BLE001 — telemetry must never break the app
            self.ship_failed += 1
            self.last_ship_error = repr(e)


def _rfc3339(epoch: float) -> str:
    """RFC3339 in UTC with a 'Z' suffix — the one format the agent accepts."""
    import datetime

    return (
        datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _label_value(src: str, headers: dict, query: dict, path: str,
                 request_body=None, response_body=None) -> str:
    """Resolve one label source, mirroring the Go engine.

    Sources are `kind:key`, optionally followed by `|<regex>` whose single
    capture group narrows the value — that is how `header:X-Region|^([a-z]{2})-`
    turns ap-south-1 into ap, and the two engines have to agree on it or the
    same optic.yaml produces different series depending on which one ran.

    `json:` and `json_response:` read the ALREADY-REDACTED bodies, so a label
    can never carry a value the policy just masked.
    """
    spec, sep, pattern = src.partition("|")
    kind, _, key = spec.partition(":")
    value = ""
    if kind == "header":
        value = headers.get(key.lower(), "")
    elif kind == "query":
        value = query.get(key, "")
    elif kind == "static":
        value = key
    elif kind == "json":
        return _narrow(first_string(request_body, key), sep, pattern)
    elif kind == "json_response":
        return _narrow(first_string(response_body, key), sep, pattern)
    elif kind == "path":
        # path:<n> is 1-based, matching the Go engine.
        segs = [s for s in path.split("/") if s]
        try:
            idx = int(key)
        except ValueError:
            return ""
        if 1 <= idx <= len(segs):
            value = segs[idx - 1]
    return _narrow(value, sep, pattern)


def _narrow(value: str, sep: str, pattern: str) -> str:
    """Apply a `|<regex>` suffix: one capture group narrows the value, no group
    means "matched, keep the whole thing"."""
    if not sep or not value:
        return value
    m = re.search(pattern, value)
    if not m:
        return ""
    return m.group(1) if m.groups() else value
