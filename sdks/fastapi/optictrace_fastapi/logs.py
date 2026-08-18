"""Ship application log lines to OpticTrace, correlated to the span serving them.

Install it on the root logger and your existing ``logger.info(...)`` calls are
filed under the exact request that produced them. Nothing about how the
application logs has to change — the span comes from a ContextVar the
middleware sets, not from anything the call site passes.

Lines emitted with no request in flight (startup, background jobs) carry no
span. The agent decides what happens to them; by default they are dropped and
counted, because attaching them to whichever request happened to be running
would cross-attribute tenants.
"""

from __future__ import annotations

import atexit
import json
import logging
import queue
import threading
import urllib.error
import urllib.request
from typing import Optional

from .trace import current

# Field names on a LogRecord that are logging's own bookkeeping rather than
# something the application attached. Everything else becomes a structured
# field, which is how `logger.info("x", extra={"order": 1})` survives.
_STD = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info",
    "thread", "threadName", "taskName",
}


class OpticTraceLogHandler(logging.Handler):
    """A logging handler that batches lines to the agent on a worker thread.

    Emitting is non-blocking by design: an application must never be slower, or
    fail, because its telemetry sink is unhappy. The queue is bounded, so a
    logging storm costs a bounded amount of memory and then drops — visibly,
    via ``dropped``, rather than by growing until the process dies.
    """

    def __init__(
        self,
        agent_url: str,
        service: str = "",
        max_queue: int = 10_000,
        flush_interval: float = 0.5,
        batch_size: int = 200,
        timeout: float = 5.0,
    ):
        super().__init__()
        self.url = agent_url.rstrip("/") + "/api/applogs/ingest"
        self.service = service
        self.timeout = timeout
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._q: queue.Queue = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        # Counters, not silence. The FastAPI SDK once swallowed every ship
        # failure with a bare `except: pass`, so it looked healthy while
        # delivering nothing at all; that is the failure mode to avoid here.
        self.dropped = 0
        self.failed = 0
        self.sent = 0
        self.last_error: Optional[str] = None
        self._worker = threading.Thread(target=self._run, name="optictrace-logs", daemon=True)
        self._worker.start()
        atexit.register(self.close)

    def emit(self, record: logging.LogRecord) -> None:
        ctx = current.get()
        line = {
            # RFC3339 with a 'Z' — the agent parses RFC3339 strictly, and the
            # obvious `%z` spelling produces "+0530", which it rejects.
            "time": _rfc3339(record.created),
            "service": self.service,
            "trace_id": ctx.trace_id if ctx else "",
            "span_id": ctx.span_id if ctx else "",
            "level": record.levelname.lower(),
            "message": record.getMessage(),
            "source": "fastapi",
        }
        fields = {k: str(v) for k, v in record.__dict__.items() if k not in _STD and not k.startswith("_")}
        if record.exc_info:
            fields["exception"] = self.format(record) if self.formatter else str(record.exc_info[1])
        if fields:
            line["fields"] = fields
        try:
            self._q.put_nowait(line)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        batch: list = []
        while not self._stop.is_set():
            try:
                batch.append(self._q.get(timeout=self.flush_interval))
                while len(batch) < self.batch_size:
                    batch.append(self._q.get_nowait())
            except queue.Empty:
                pass
            if batch:
                self._post(batch)
                batch = []
        # Drain whatever is left so a clean shutdown does not lose the last
        # lines — which are usually the ones explaining the shutdown.
        rest: list = []
        try:
            while True:
                rest.append(self._q.get_nowait())
        except queue.Empty:
            pass
        if rest:
            self._post(rest)

    def _post(self, batch: list) -> None:
        body = json.dumps(batch).encode()
        req = urllib.request.Request(
            self.url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
            self.sent += len(batch)
        except urllib.error.HTTPError as e:
            self.failed += len(batch)
            self.last_error = f"HTTP {e.code}: {e.read()[:200].decode('utf-8', 'replace')}"
        except Exception as e:  # noqa: BLE001 — telemetry must never raise into the app
            self.failed += len(batch)
            self.last_error = repr(e)

    def close(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        self._worker.join(timeout=self.timeout)
        super().close()


def _rfc3339(epoch: float) -> str:
    import datetime

    return (
        datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
