"""Inner spans: the operations that run while a request is being served.

The middleware records the HTTP exchange. This records what happened inside it
— a query, a cache lookup, an outbound call — which is the difference between
"this request took 300ms" and "this request took 300ms, 280 of them in one
query".

Attributes are governed by the agent before storage, so a statement that quotes
its parameters is redacted before anything is written. Pass the statement
TEMPLATE where you can: the safest secret is the one that was never sent.
"""

from __future__ import annotations

import contextvars
import secrets
import time
from datetime import datetime, timezone
from types import TracebackType
from typing import Optional, Type

from .logs import OpticTraceLogHandler
from .trace import current as current_span

# The innermost open span, so operations nest: a query inside a transaction
# parents to the transaction rather than jumping to the request.
#
# A ContextVar rather than a plain global, for the same reason the request span
# is one: asyncio interleaves requests in one thread, and a global would parent
# one request's query to another request's transaction.
_open_span: contextvars.ContextVar[str] = contextvars.ContextVar("optictrace_open_span", default="")


def _hex(n: int) -> str:
    return secrets.token_hex(n)


class SpanRecorder:
    """Ships inner spans to the agent.

    ``agent_url`` empty makes every span inert, so instrumentation can stay in
    place in an environment with no agent rather than being guarded by an ``if``
    at each call site.
    """

    def __init__(self, agent_url: str, service: str = "", **kwargs):
        # The shipper is the app-log handler's, pointed at a different path:
        # batching, a bounded queue and delivery counters are the same problem,
        # and a second copy would drift from this one.
        self._shipper = (
            OpticTraceLogHandler(agent_url, service, path="/api/spans/ingest", **kwargs)
            if agent_url
            else None
        )
        self.service = service

    def start(self, name: str, kind: str = "") -> "InnerSpan":
        """Opens a span.

        ``kind`` classifies the operation for the waterfall and the breakdown:
        db, cache, http, queue, rpc, internal. Outside a request the span has no
        parent and the agent drops it by default — work belonging to no request
        cannot be attributed to one.
        """
        return InnerSpan(self, name, kind)

    @property
    def sent(self) -> int:
        return self._shipper.sent if self._shipper else 0

    @property
    def failed(self) -> int:
        return self._shipper.failed if self._shipper else 0

    @property
    def dropped(self) -> int:
        return self._shipper.dropped if self._shipper else 0

    def close(self) -> None:
        if self._shipper:
            self._shipper.close()


class InnerSpan:
    """One operation in flight. Used as a context manager.

    ::

        with spans.start("db.query", "db") as sp:
            sp.set("db.statement", SQL)
            rows = cur.execute(SQL, (order_id,)).fetchall()
            sp.set_int("db.rows", len(rows))

    An exception leaving the block is recorded and re-raised: the span exists to
    say what happened, not to change it.
    """

    def __init__(self, owner: SpanRecorder, name: str, kind: str):
        self._owner = owner
        self.name = name
        self.kind = kind or ""
        self._start_perf = time.perf_counter()
        self._started_at = datetime.now(timezone.utc)
        self.attrs: dict[str, str] = {}
        self._error: Optional[str] = None
        self._ended = False

        ctx = current_span.get(None)
        self.trace_id = ctx.trace_id if ctx else ""
        self.span_id = _hex(8)
        self.parent_span_id = _open_span.get() or (ctx.span_id if ctx else "")
        self._token = _open_span.set(self.span_id)

    def set(self, key: str, value) -> "InnerSpan":
        """Attaches an attribute.

        Conventional keys — db.statement, db.rows, cache.key, cache.hit,
        http.method, http.url, http.status — are what the dashboard reads.
        """
        if key is not None and value is not None:
            self.attrs[key] = str(value)
        return self

    def set_int(self, key: str, value: int) -> "InnerSpan":
        return self.set(key, int(value))

    def fail(self, exc: Optional[BaseException]) -> "InnerSpan":
        """Marks the operation as failed. ``None`` is a no-op.

        A failed operation survives the agent's ``min_duration`` filter: "it
        returned in 200µs" and "it returned in 200µs with an error" are not the
        same event, and the second is the one someone is looking for.
        """
        if exc is not None:
            self._error = f"{type(exc).__name__}: {exc}"
        return self

    def end(self) -> None:
        """Ends the span and queues it.

        Idempotent: a ``with`` block plus an explicit ``end()`` is a natural
        thing to write and must not double count.
        """
        if self._ended:
            return
        self._ended = True
        try:
            _open_span.reset(self._token)
        except ValueError:
            # Reset from a different context than the set — an operation moved
            # across tasks. Nothing to unwind, and raising here would turn a
            # telemetry detail into an application failure.
            pass
        if self._owner._shipper is None:
            return

        span = {
            # RFC3339 UTC — the agent parses strictly, and this SDK once had
            # every record rejected for sending "+0530".
            "start": self._started_at.isoformat().replace("+00:00", "Z"),
            "service": self._owner.service,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "name": self.name,
            "kind": self.kind,
            "duration_ms": (time.perf_counter() - self._start_perf) * 1000.0,
            "source": "fastapi",
        }
        if self.parent_span_id:
            span["parent_span_id"] = self.parent_span_id
        if self._error:
            span["error"] = self._error
        if self.attrs:
            span["attrs"] = self.attrs
        self._owner._shipper.ship(span)

    def __enter__(self) -> "InnerSpan":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> bool:
        self.fail(exc)
        self.end()
        return False  # never swallow — the span reports, it does not intervene
