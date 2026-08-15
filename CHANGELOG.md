# Changelog

All notable changes to OpticTrace are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions `0.4.0`–`0.6.0` were development milestones that were never tagged;
`0.7.0` is the first public release and contains all of that work.

## [Unreleased]

_Nothing yet._

## [0.7.0] — 2026-08-16

First public release. OpticTrace is a config-driven API telemetry and
governance gateway: one `optic.yaml` controls what your API traffic reveals —
which routes are monitored, which payloads are stored, what gets masked, and
which request attributes become Prometheus dimensions.

The governing invariant throughout: **live traffic is never modified**.
Restriction and redaction apply only to the telemetry OpticTrace records.

### Governance engine

- Declarative `optic.yaml` with strict validation — unknown keys are rejected at load, so a typo can't silently disable a rule.
- Path globbing (`*` = one segment, `**` = zero or more) with optional method filters.
- **Restriction**: disable capture of request bodies, response bodies, headers or query strings per rule.
- **Redaction**: mask headers, query parameters, and JSON fields by path — including `$.*` (any key) and `$.**` (any nesting depth, which matters when an upstream echoes a payload back inside a wrapper).
- **Custom labels** extracted from headers or query params, becoming real Prometheus dimensions.
- **Metering**: pull numeric usage (e.g. LLM token counts) out of responses by JSON path. Works on fully restricted routes — the payload is read for the number and never stored.
- **Sampling**: uniform `sample`, plus tail-based `keep_errors` and `keep_slower_than` that rescue the requests a coin flip would have discarded.
- **Hot reload** via `SIGHUP` or `POST /api/reload`; invalid configs are rejected and the previous rules stay live.
- Rules merge top-to-bottom rather than first-match-wins: restrictions narrow capture, redactions and labels accumulate.

### Observability and storage

- Prometheus exporter with ten metric families on a private registry, so embedding never collides with an application's own.
- **Bounded cardinality by design**: the `route` label is always a rule glob or normalized pattern (`/users/42` → `/users/:id`), and a **cardinality guard** caps distinct values per custom label, since label values arrive from arbitrary request headers.
- **SQLite** payload store (pure Go, no CGO) with an async writer that drops under backpressure rather than blocking the request path.
- **Postgres** store for multi-node deployments, pushing percentiles, usage grouping and label matching into the database via JSONB. Both drivers are held to a shared conformance suite.
- Retention by row count *and* by age, plus `optictrace purge` for erasure requests.

### Tooling powered by captured traffic

- `optictrace spec` — infer an OpenAPI 3 document from what clients actually send.
- `optictrace check` — breaking-change linter answering *"is any live client using the field I'm about to remove?"* with usage counts and last-seen times; exits non-zero in CI.
- `optictrace sdk` — generate typed TypeScript, Python or Go clients, all dependency-free.
- `optictrace mock` — stateful mock server where `POST /cart` then `GET /cart` really returns the added item; optional Claude-generated responses.
- `optictrace scan` — leak detector that finds sensitive values your rules *didn't* cover, using structural detectors (Luhn and mod-97 checksums, issuer prefixes, PEM framing). Findings carry masked samples only and print the rule that would have caught them.
- `optictrace suggest` — proposes rules for sensitive-looking field *names*, complementing `scan`'s value inspection.
- `optictrace test` — assert governance behaviour against the real engine with no server and no network.
- `optictrace replay` — re-issue captured traffic and diff status codes, skipping what governance made unreplayable rather than faking it.

### Integration and operations

- Reverse-proxy sidecar and embeddable Go middleware sharing one interception path.
- SDKs for **Express**, **FastAPI** and **Gin**; the JavaScript and Python SDKs carry semantically identical ports of the rule engine, so redaction happens in-process and raw payloads never cross a process boundary.
- Export plugins: `file` (JSONL), `webhook`, `otlp` (OpenTelemetry spans), and `command` — the custom plugin hook that streams one JSON record per line to any executable's stdin.
- Optional control-plane authentication (bearer token, constant-time comparison, `token_env`) and TLS.
- Seven-page Next.js dashboard served by the binary itself: Overview, Routes, Inspector, Usage, Governance, Config, System.
- Docker image, Compose stack with Prometheus and Grafana, and a Helm chart.
- Provisioned Grafana dashboard and Prometheus alert rules covering both traffic and the agent's own health.

### Performance

Measured with `make bench` (12th Gen Intel i5-1235U, Go 1.25):

| Policy | Added latency |
|---|---:|
| Restricted route (capture off) | +0.22 µs |
| Full capture + depth-recursive redaction | +5.4 µs |
| Prometheus observation with a custom label | +0.13 µs |

### Fixed

- Data race in the `command` exporter: process liveness was determined by reading `cmd.ProcessState` while `cmd.Wait()` wrote it from the reaper goroutine. Liveness is now published through a channel closed on exit, and `Close` no longer holds the mutex while waiting for a drain. Caught by `go test -race`, which CI runs on every push.

### Known limitations

- ClickHouse is not implemented; `sqlite`, `postgres` and `none` are the available store drivers.
- The AI mock path (`optictrace mock -ai`) is implemented but has not been exercised against the live Anthropic API.
- Hijacked connections (WebSockets) pass through uninspected by nature; gRPC and GraphQL are not specifically supported.
- Control-plane authentication is available but **off by default**.
- Homebrew publishing is configured but disabled until a `homebrew-tap` repository exists.

[Unreleased]: https://github.com/dwarka-prasad/optictrace/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/dwarka-prasad/optictrace/releases/tag/v0.7.0
