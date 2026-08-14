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
import time
import urllib.request
from typing import Optional

import yaml

from .engine import Engine, Policy, REDACTED  # noqa: F401 (public API)

__all__ = ["OpticTraceMiddleware", "Engine", "Policy", "REDACTED"]


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
                if capture_resp:
                    room = policy.capture_limit - len(state["resp_body"])
                    if room > 0:
                        state["resp_body"] += body[:room]
                    if len(body) > room:
                        state["resp_trunc"] = True
            await send(message)

        try:
            await self.app(scope, tee_receive, tee_send)
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            record = self._build_record(
                scope, method, path, policy, req_headers, state, duration_ms
            )
            if self.console_log or not self.ingest_url:
                print(json.dumps({"msg": "http_exchange", **record}), flush=True)
            if self.ingest_url:
                # Fire-and-forget in a worker thread — urllib is blocking.
                asyncio.get_running_loop().run_in_executor(None, self._ship, record)

    def _build_record(self, scope, method, path, policy, req_headers, state, duration_ms):
        client = scope.get("client") or ("", 0)
        record = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
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
        if state["resp_body"]:
            record["response_body"] = policy.redact_body(
                bytes(state["resp_body"]), state["resp_headers"].get("content-type", "")
            )
            if state["resp_trunc"]:
                record["resp_truncated"] = True
        if policy.labels:
            query = {}
            qs = scope.get("query_string", b"").decode("latin-1")
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    query.setdefault(k, v)
            labels = {}
            for name, src in policy.labels.items():
                kind, _, key = str(src).partition(":")
                if kind == "header":
                    labels[name] = req_headers.get(key.lower(), "")
                elif kind == "query":
                    labels[name] = query.get(key, "")
            record["labels"] = labels
        return record

    def _ship(self, record: dict):
        try:
            req = urllib.request.Request(
                self.ingest_url,
                data=json.dumps(record).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:  # noqa: BLE001 — telemetry must never break the app
            pass
