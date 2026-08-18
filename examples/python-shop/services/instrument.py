"""One place where every service in this example gets instrumented.

Three things happen here, and they are deliberately separate concerns:

  1. governance   — the SDK middleware evaluates optic.yaml IN-PROCESS, so a
                    card number is masked inside the service that saw it and
                    never crosses a process boundary in the clear;
  2. correlation  — the middleware adopts (or starts) a W3C trace and puts the
                    span in a ContextVar;
  3. logs         — a logging handler reads that ContextVar, so ordinary
                    `log.info(...)` calls land under the request that made
                    them without any call site knowing about OpticTrace.

Nothing about how the application code is written has to change for (3), which
is the whole point: instrumentation you have to remember at every call site is
instrumentation that will be missing where it matters.
"""

from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "sdks", "fastapi"))

from optictrace_fastapi import (  # noqa: E402
    OpticTraceLogHandler,
    OpticTraceMiddleware,
    outbound_headers,
)

AGENT = os.environ.get("OPTIC_AGENT", "http://127.0.0.1:9095")
CONFIG = os.environ.get("OPTIC_CONFIG", os.path.join(os.path.dirname(__file__), "..", "optic.yaml"))


def instrument(app, service_name: str) -> logging.Logger:
    """Wire governance, correlation and log shipping onto an ASGI app."""
    app.add_middleware(
        OpticTraceMiddleware,
        config_path=CONFIG,
        agent_url=AGENT,
        service_name=service_name,
    )

    log = logging.getLogger(service_name)
    log.setLevel(logging.DEBUG)
    # Local stdout so `run.sh` output is readable, plus the OpticTrace handler.
    # Both, not either: an operator watching the terminal and an operator
    # reading the dashboard should see the same thing.
    stream = logging.StreamHandler()
    stream.setFormatter(logging.Formatter(f"[{service_name}] %(levelname)-5s %(message)s"))
    log.addHandler(stream)
    log.addHandler(OpticTraceLogHandler(AGENT, service=service_name))
    log.propagate = False
    return log


__all__ = ["instrument", "outbound_headers", "AGENT"]
