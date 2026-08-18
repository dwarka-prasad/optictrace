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
    meters: dict = field(default_factory=dict)  # name -> [path segments]

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
    meters: dict[str, list[list[str]]]


class Engine:
    def __init__(self, cfg: dict):
        if not cfg or cfg.get("version") != 1:
            raise ValueError(f"optic.yaml: unsupported version {cfg.get('version') if cfg else None}")
        self.service_name = (cfg.get("service") or {}).get("name", "")
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
