"""OpticTrace rule engine — Python port, semantics-identical to the Go engine.

Governance runs IN-PROCESS: sensitive payloads are restricted/redacted before
any byte leaves the application; only the governed record is shipped to the
OpticTrace agent.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from typing import Any, Optional

REDACTED = "[REDACTED]"


def split_path(p: str) -> list[str]:
    t = (p or "").strip("/")
    return t.split("/") if t else []


def match_segments(pattern: list[str], segs: list[str]) -> bool:
    """Segment-wise glob: `*` = one segment, `**` = zero or more segments."""
    if not pattern:
        return not segs
    if pattern[0] == "**":
        if len(pattern) == 1:
            return True
        return any(match_segments(pattern[1:], segs[i:]) for i in range(len(segs) + 1))
    if not segs:
        return False
    if not fnmatch.fnmatchcase(segs[0], pattern[0]):
        return False
    return match_segments(pattern[1:], segs[1:])


def redact_path(node: Any, path: list[str]) -> Any:
    """Mask the value addressed by one dotted path.

    `*` = any key at one level; `**` = any depth; lists traverse implicitly.
    """
    if not path or node is None:
        return node
    if isinstance(node, list):
        return [redact_path(item, path) for item in node]
    if not isinstance(node, dict):
        return node
    seg, rest = path[0], path[1:]
    if seg == "**":
        if rest:
            redact_path(node, rest)  # may match at this level...
        for key in list(node.keys()):
            node[key] = redact_path(node[key], path)  # ...and any deeper level
        return node
    if seg == "*":
        for key in list(node.keys()):
            node[key] = REDACTED if not rest else redact_path(node[key], rest)
        return node
    if seg in node:
        node[seg] = REDACTED if not rest else redact_path(node[seg], rest)
    return node


def _parse_duration(value) -> Optional[float]:
    """Go-style durations ("250ms", "1s", "2m") in milliseconds.

    optic.yaml is written for the Go agent, so the spellings it accepts are the
    ones this has to understand — a config that works there and is silently
    ignored here is the kind of divergence nobody goes looking for.
    """
    if value is None:
        return None
    text = str(value).strip()
    try:
        if text.endswith("ms"):
            return float(text[:-2])
        if text.endswith("s"):
            return float(text[:-1]) * 1000
        if text.endswith("m"):
            return float(text[:-1]) * 60_000
        return float(text)
    except ValueError as exc:
        raise ValueError(f"optic.yaml: cannot parse duration {value!r}") from exc


def _parse_meters(spec: dict, rule_name: str) -> dict:
    """`meter: {name: "$.usage.total_tokens"}` -> {name: [["usage","total_tokens"]]}.

    A list of paths sums them, matching the Go engine.
    """
    out: dict[str, list[list[str]]] = {}
    for name, paths in spec.items():
        if isinstance(paths, str):
            paths = [paths]
        parsed = []
        for path in paths:
            if not str(path).startswith("$."):
                raise ValueError(f"optic.yaml rule {rule_name}: meter {name} path {path!r} must start with '$.'")
            parsed.append(str(path)[2:].split("."))
        out[name] = parsed
    return out


def first_string(doc: Any, spec: str) -> str:
    """First value at a dotted path, read from the ALREADY-REDACTED body.

    Supports `*` and `**` like the redaction grammar, so a label and a
    redaction can name the same shape of field.
    """
    if doc is None or not str(spec).startswith("$."):
        return ""

    def walk(node: Any, path: list):
        if node is None:
            return None
        if not path:
            return None if isinstance(node, (dict, list)) else node
        if isinstance(node, list):
            for child in node:
                hit = walk(child, path)
                if hit is not None:
                    return hit
            return None
        if not isinstance(node, dict):
            return None
        seg, rest = path[0], path[1:]
        if seg == "**":
            if rest:
                here = walk(node, rest)
                if here is not None:
                    return here
            for child in node.values():
                hit = walk(child, path)
                if hit is not None:
                    return hit
            return None
        if seg == "*":
            for child in node.values():
                hit = walk(child, rest)
                if hit is not None:
                    return hit
            return None
        return walk(node[seg], rest) if seg in node else None

    found = walk(doc, str(spec)[2:].split("."))
    if found is None:
        return ""
    if isinstance(found, bool):
        return "true" if found else "false"
    return str(found)


def sum_numeric(node: Any, path: list, acc: list) -> None:
    """Walk a dotted path summing numbers, supporting `*` and `**`.

    Mirrors internal/engine.sumNumeric — the two engines must agree, or the
    same optic.yaml bills differently depending on which one ran.
    """
    if not path:
        if isinstance(node, bool):
            return  # bool is an int in Python; a flag is not a quantity
        if isinstance(node, (int, float)):
            acc[0] += float(node)
            acc[1] = True
        return
    if isinstance(node, dict):
        seg, rest = path[0], path[1:]
        if seg == "**":
            if rest:
                sum_numeric(node, rest, acc)
            for child in node.values():
                sum_numeric(child, path, acc)
            return
        if seg == "*":
            for child in node.values():
                sum_numeric(child, rest, acc)
            return
        if seg in node:
            sum_numeric(node[seg], rest, acc)
    elif isinstance(node, list):
        for child in node:
            sum_numeric(child, path, acc)


@dataclass
class Policy:
    capture_request_body: bool = True
    capture_response_body: bool = True
    capture_headers: bool = True
    capture_limit: int = 65536
    redact_headers: set[str] = field(default_factory=set)  # lowercase names
    redact_paths: list[list[str]] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)  # name -> "header:X" / "query:x"
    matched_rules: list[str] = field(default_factory=list)
    route_pattern: str = ""
    sample_rate: float = 1.0
    # Tail-based keeps. `sample` is a draw made up front; these rescue a
    # request AFTER the outcome is known, because a coin flip that discards
    # your 500s is worse than no sampling at all.
    keep_errors: bool = False
    keep_slower_than_ms: Optional[float] = None
    meters: dict = field(default_factory=dict)  # name -> [path segments]

    def keep_body(self, drew: bool, status: int, elapsed_ms: float) -> bool:
        """Whether the BODY may be stored for this exchange.

        Mirrors engine.Policy.KeepBody. Two details matter for parity: the
        record is ALWAYS emitted — metrics and metadata are never sampled — and
        keep_errors means 5xx, not 4xx. A 404 is usually the client's problem,
        and rescuing it would defeat the sampling it works alongside.
        """
        if drew:
            return True
        if self.keep_errors and status >= 500:
            return True
        return self.keep_slower_than_ms is not None and elapsed_ms >= self.keep_slower_than_ms

    def tail_sampled(self) -> bool:
        """Whether any tail rule applies, so bytes must be buffered up front."""
        return self.keep_errors or self.keep_slower_than_ms is not None

    def extract_meters(self, raw: bytes) -> dict:
        """Pull numeric usage out of a response body.

        Deliberately reads the RAW bytes, not the stored body: metering is
        independent of capture, so a route that records no response body can
        still be billed. That independence is the whole reason a rule can say
        "keep the prompt private, still count the tokens".
        """
        if not self.meters or not raw:
            return {}
        try:
            doc = json.loads(raw)
        except Exception:  # noqa: BLE001 — a non-JSON body simply has no meters
            return {}
        out = {}
        for name, paths in self.meters.items():
            acc = [0.0, False]
            for path in paths:
                sum_numeric(doc, path, acc)
            if acc[1]:
                out[name] = acc[0]
        return out

    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        return {
            k: (REDACTED if k.lower() in self.redact_headers else v)
            for k, v in headers.items()
        }

    def redact_body(self, raw: bytes, content_type: str) -> str:
        if not raw:
            return ""
        if "json" in (content_type or ""):
            try:
                doc = json.loads(raw)
                for p in self.redact_paths:
                    doc = redact_path(doc, p)
                return json.dumps(doc, separators=(",", ":"))
            except (ValueError, TypeError):
                pass
        return f"<{content_type or 'unknown'} body, {len(raw)} bytes captured>"


@dataclass
class _Rule:
    name: str
    raw_pattern: str
    path_segs: list[str]
    methods: Optional[set[str]]
    restrict: set[str]
    redact_headers: list[str]
    redact_paths: list[list[str]]
    labels: dict[str, str]
    sample: Optional[float]
    keep_errors: bool
    keep_slower_than_ms: Optional[float]
    meters: dict[str, list[list[str]]]


class Engine:
    def __init__(self, cfg: dict):
        if not cfg or cfg.get("version") != 1:
            raise ValueError(f"optic.yaml: unsupported version {cfg.get('version') if cfg else None}")
        self.service_name = (cfg.get("service") or {}).get("name", "")
        # The only thread from a customer's screenshot back to the record.
        # Without it a support conversation starts at "roughly what time?",
        # which under concurrency identifies the wrong request.
        self.trace_response_header = (
            ((cfg.get("service") or {}).get("trace") or {}).get("response_header", "")
        )
        defaults = cfg.get("defaults") or {}
        cap = defaults.get("capture") or {}
        self._defaults = {
            "request_body": cap.get("request_body", True) is not False,
            "response_body": cap.get("response_body", True) is not False,
            "headers": cap.get("headers", True) is not False,
        }
        self._capture_limit = defaults.get("capture_limit_bytes") or 65536
        self._rules: list[_Rule] = []
        for i, r in enumerate(cfg.get("rules") or []):
            match = r.get("match") or {}
            path = match.get("path", "")
            if not path.startswith("/"):
                raise ValueError(f"optic.yaml rule {r.get('name', i)}: match.path must start with '/'")
            redact = r.get("redact") or {}
            paths = []
            for jf in redact.get("json_fields") or []:
                if not jf.startswith("$."):
                    raise ValueError(f"optic.yaml: json field {jf} must start with '$.'")
                paths.append(jf[2:].split("."))
            self._rules.append(
                _Rule(
                    name=r.get("name") or f"#{i}",
                    raw_pattern=path,
                    path_segs=split_path(path),
                    methods={m.upper() for m in match["methods"]} if match.get("methods") else None,
                    restrict=set(r.get("restrict") or []),
                    redact_headers=[h.lower() for h in redact.get("headers") or []],
                    redact_paths=paths,
                    labels=r.get("labels") or {},
                    sample=r.get("sample"),
                    keep_errors=r.get("keep_errors") is True,
                    keep_slower_than_ms=_parse_duration(r.get("keep_slower_than")),
                    meters=_parse_meters(r.get("meter") or {}, r.get("name") or f"#{i}"),
                )
            )

    def evaluate(self, method: str, url_path: str) -> Policy:
        policy = Policy(
            capture_request_body=self._defaults["request_body"],
            capture_response_body=self._defaults["response_body"],
            capture_headers=self._defaults["headers"],
            capture_limit=self._capture_limit,
        )
        segs = split_path(url_path)
        for r in self._rules:
            if r.methods is not None and method not in r.methods:
                continue
            if not match_segments(r.path_segs, segs):
                continue
            policy.matched_rules.append(r.name)
            policy.route_pattern = r.raw_pattern
            if r.sample is not None:
                policy.sample_rate = r.sample
            if r.keep_errors:
                policy.keep_errors = True
            if r.keep_slower_than_ms is not None:
                policy.keep_slower_than_ms = (
                    r.keep_slower_than_ms
                    if policy.keep_slower_than_ms is None
                    else min(policy.keep_slower_than_ms, r.keep_slower_than_ms)
                )
            if "request_body" in r.restrict:
                policy.capture_request_body = False
            if "response_body" in r.restrict:
                policy.capture_response_body = False
            if "headers" in r.restrict:
                policy.capture_headers = False
            policy.redact_headers.update(r.redact_headers)
            policy.redact_paths.extend(r.redact_paths)
            policy.labels.update(r.labels)
            policy.meters.update(r.meters)
        return policy
