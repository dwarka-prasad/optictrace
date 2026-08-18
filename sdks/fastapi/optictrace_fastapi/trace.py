"""W3C trace context for the OpticTrace ASGI middleware.

The point of this module is that correlation must be a fact, not a guess. A
span id generated here is written onto the record AND made available to the
application, so a log line or an outbound call can name the exact request it
belongs to instead of being matched by timestamp — which, under concurrent
traffic, files one tenant's data inside another tenant's request.
"""

from __future__ import annotations

import contextvars
import os
import re
from dataclasses import dataclass
from typing import Optional

HEADER = "traceparent"

# 00-<32 hex trace>-<16 hex span>-<2 hex flags>. Version ff is forbidden by the
# spec; anything malformed starts a fresh trace rather than failing a request —
# losing correlation is a nuisance, failing a request over a bad header is a
# fault.
_TRACEPARENT = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    span_id: str
    parent_span_id: str = ""
    sampled: bool = True

    def header(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{'01' if self.sampled else '00'}"


# The span currently being served. Set by the middleware, read by the log
# handler and by outbound_headers(). A ContextVar is what makes this correct
# under asyncio: every concurrent request gets its own value rather than
# racing over one global.
current: contextvars.ContextVar[Optional[TraceContext]] = contextvars.ContextVar(
    "optictrace_span", default=None
)


def _hex(n: int) -> str:
    return os.urandom(n).hex()


def from_header(raw: str) -> TraceContext:
    """Adopt an inbound traceparent, or start a new trace if there isn't a
    usable one. The caller's span becomes this span's parent, which is what
    makes the result a tree rather than a flat list."""
    m = _TRACEPARENT.match((raw or "").strip())
    if not m:
        return TraceContext(trace_id=_hex(16), span_id=_hex(8))
    version, trace_id, parent, flags = m.groups()
    # All-zero ids are invalid per the spec and mean the caller is broken.
    if version == "ff" or trace_id == "0" * 32 or parent == "0" * 16:
        return TraceContext(trace_id=_hex(16), span_id=_hex(8))
    return TraceContext(
        trace_id=trace_id,
        span_id=_hex(8),
        parent_span_id=parent,
        sampled=bool(int(flags, 16) & 1),
    )


def outbound_headers(extra: Optional[dict] = None) -> dict:
    """Headers to attach to a call this service makes downstream, so the next
    hop nests under this one.

    Carries THIS hop's span, not the caller's. Forwarding the inbound header
    unchanged would make every downstream call a sibling of this request rather
    than a child, and the tree flattens into a list.
    """
    headers = dict(extra or {})
    ctx = current.get()
    if ctx is not None:
        headers[HEADER] = ctx.header()
    return headers
