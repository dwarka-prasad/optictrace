# Changelog

All notable changes to OpticTrace are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions `0.4.0`–`0.6.0` were development milestones that were never tagged;
`0.7.0` is the first public release and contains all of that work.

## [Unreleased]

### Added

- **`ext/` — a public extension surface.** Everything else lives under `internal/`, which other Go modules cannot import; `ext` is the deliberate exception, holding the record types and the `Store`/`Exporter` interfaces. Register a driver with `ext.RegisterStore` or `ext.RegisterExporter` and it becomes valid in `optic.yaml` purely by being linked in — the core needs no changes. Driver-specific keys live under a `settings:` map, since the decoder rejects unknown top-level keys on purpose. The record types are *aliased* from `internal/store`, not duplicated, so there is exactly one `Record` in the program.
- **`ext/exttest` — the conformance suite, exported.** The acceptance criteria the built-in drivers run are now public, so an out-of-tree store can be held to the identical contract. [`examples/memstore`](examples/memstore) is a worked reference: a complete driver in its own module, outside the `optictrace/` path prefix so it genuinely cannot reach `internal/`, passing the full suite using only `ext`. CI builds it, so a gap in the extension surface fails the build.

- **Cleartext HTTP/2 (h2c)** behind `service.http2: true`. Off by default: it changes protocol negotiation for every client. This is what an HTTP/2 client needs to connect at all — it is *not* gRPC support, and the docs now say so plainly rather than describing gRPC as merely "not specifically supported". ([#11](https://github.com/dwarka-prasad/optictrace/issues/11))
- **Streams are measured separately from requests.** `optictrace_stream_duration_seconds` (1s–4.5h buckets), `optictrace_streams_total` and `optictrace_streams_open` cover SSE, chunked responses and upgraded connections. Their durations no longer enter `optictrace_request_duration_seconds` or the dashboard's route percentiles, where a single 10-minute SSE connection used to define a route's p95 for the whole window. Records carry a `stream` flag; existing databases are migrated in place. ([#12](https://github.com/dwarka-prasad/optictrace/issues/12))

### Added

- **ClickHouse `LogStore` driver** (`telemetry.store.driver: clickhouse`). Every dashboard query is a time-bucketed aggregation over an append-only table, which is what a column store is for. It passes the shared conformance suite unmodified alongside SQLite and Postgres, so the three drivers cannot answer the same question differently. Two things genuinely differ and are handled explicitly rather than hidden: ClickHouse has no autoincrement, so IDs are generated client-side with a millisecond prefix to preserve newest-first ordering; and `DELETE` is an asynchronous mutation, so every delete path runs with `mutations_sync = 2` — an erasure request that returned before the data was gone would be worse than useless. The driver is pure Go, so `CGO_ENABLED=0` and the static release binaries are unaffected. ([#2](https://github.com/dwarka-prasad/optictrace/issues/2))
- **GraphQL operations are first-class.** Set `service.graphql_paths`, and the operation name is extracted from the request body, appended to the route (`/graphql:CreatePayment`), and matchable with `match.graphql_operation`. Previously every operation collapsed into one `/graphql` route: latency percentiles averaged a 2ms `viewer` query with a 4s report, a rule could not redact a field on one mutation without applying to every query, and inferred specs produced a single endpoint whose schema was the union of everything. Operation names are client-supplied, so they are validated as plain identifiers and length-capped before becoming a label; batched requests report `batch` rather than being attributed to whichever operation came first. ([#10](https://github.com/dwarka-prasad/optictrace/issues/10))
- **Org-specific `scan` detectors** via `scan.detectors` in `optic.yaml`, merged with the built-ins. Patterns compile at load time so a bad one fails `optictrace validate` rather than at scan time, patterns that match the empty string are rejected, and a `verify:` registry exposes the built-in checksums (`luhn`, `iban`, `us_ssn`, and a new `verhoeff` for Aadhaar and similar national IDs) so a custom detector can be as precise as a built-in. Findings still go through `Mask()`, so a custom detector cannot become the hole in that. ([#3](https://github.com/dwarka-prasad/optictrace/issues/3))

### Testing

- **`internal/config`, `internal/admin` and `sdks/gin` had no tests at all.** They now cover the auth path (constant-time compare, query-token fallback, health bypass, preflight), the CORS allowlist, export pagination across multiple pages in both JSONL and CSV, the billing cost arithmetic component by component, every config validation rule, and the Gin adapter's `Flusher`/`Hijacker`/`Pusher` surface — the same class of wrapper bug as #5. Config coverage went 0% → 77%, admin 0% → 41%. CI now runs the SDK's tests rather than only building it. ([#13](https://github.com/dwarka-prasad/optictrace/issues/13))

### Performance

- **Rule-match counts are one query instead of N.** `/api/rules/stats` ran one `matched_rules LIKE '%"name"%'` per rule — and a LIKE pattern with a leading wildcard can never use an index, so that was N full table scans per dashboard load. SQLite now expands the JSON array with `json_each` and groups in one indexed pass; measured 117ms → 52ms at 50k rows with 10 rules, and it now scales with rule count rather than multiplying by it. Postgres gained the GIN index on `matched_rules` that its containment query never had. ([#9](https://github.com/dwarka-prasad/optictrace/issues/9))
- **Route percentiles no longer sort every matching row.** A new `(route, method, duration_ms)` index means the per-route `ORDER BY duration_ms LIMIT 1 OFFSET n` subqueries walk an ordered index; `EXPLAIN QUERY PLAN` confirms the temp B-tree for the sort is gone.
- **Analysis passes stream instead of materialising.** `/api/scan` and `/api/spec` loaded up to 20,000 complete records — bodies included, so gigabytes at the default capture limit — before analysing any of them, on endpoints that were unauthenticated by default. Both analysers now fold record-by-record through a new `LogStore.RecentFunc`, holding one record at a time. The cap is configurable via `telemetry.store.analysis_max_rows`, and the CLI says so when it truncates rather than letting a partial analysis read as a complete one. ([#7](https://github.com/dwarka-prasad/optictrace/issues/7))

### Security

- **The admin API is no longer exposed by default.** Three defaults combined into more than the sum of their parts: `admin_listen` bound all interfaces, auth was off, and `Access-Control-Allow-Origin: *` was set *outside* the auth wrapper — so any web page a developer visited could read the entire capture store with one `fetch()`. Now `admin_listen` defaults to `127.0.0.1:9095`, CORS is an explicit allowlist (`telemetry.cors_origins`) that sends no headers at all when empty, and a wildcard origin is rejected at load time unless auth is enabled. The Compose stack publishes its ports on `127.0.0.1` instead of `0.0.0.0`, and the Helm chart enables auth by default with a generated token that survives upgrades. ([#6](https://github.com/dwarka-prasad/optictrace/issues/6))

  **Breaking:** if you relied on reaching the dashboard from another host, set `admin_listen: "0.0.0.0:9095"` explicitly — and set `telemetry.auth` while you're there.

### Fixed

- **OTLP spans ignored inbound trace context.** Every exported span generated a fresh trace ID, so it landed in the tracing backend as an unrelated single-span trace and could never be correlated with the application's own tracing. W3C `traceparent` is now adopted when present — trace ID reused, inbound span ID becomes the parent, sampled flag and `tracestate` propagated — falling back to a fresh root for anything absent or malformed. Note this needs captured request headers, so a route that restricts `headers` still exports orphan spans. ([#14](https://github.com/dwarka-prasad/optictrace/issues/14))

- **A reload could not add a Prometheus dimension.** Adding a `labels:` key and reloading made the label appear in the dashboard but never in `/metrics` — the collector's label set is fixed at construction, so a Grafana panel built on the new label stayed empty with no error anywhere. Reload now rebuilds the affected vectors. Because `client_golang` deliberately remembers a metric name's schema for a Registry's lifetime (`Unregister` leaves `dimHashesByName` intact), the two config-dependent vectors live in their own registry that is swapped wholesale; every other counter is unaffected. Request counts and latency buckets restart on a relabel, which is inherent. ([#8](https://github.com/dwarka-prasad/optictrace/issues/8))

- **Reload silently discarded most of the config.** Changes to `telemetry.store`, `telemetry.exporters`, `telemetry.auth`, `admin_listen`, `metrics.buckets` and the rest were parsed, validated, then dropped — and the reload reported success regardless. They are now named in a warning that says a restart is needed.

- **WebSocket upgrades returned 502 instead of passing through.** `recordingWriter` embeds `http.ResponseWriter` as an interface, so it promoted neither `Hijack` nor `Unwrap`; `httputil.ReverseProxy` could not take the connection and handed the request to the error handler. The docs described this as passing through uninspected — it was failing outright. It now implements both, so upgrades work and `http.ResponseController` methods reach the underlying writer. ([#5](https://github.com/dwarka-prasad/optictrace/issues/5))

- **A missing `service.listen` silently bound port 80.** It reached `net/http` as `Addr: ""`, so the proxy either served where nobody expected it or failed with `bind: permission denied` on a port that appears nowhere in the config. `optictrace run` now refuses to start with a message naming the field; `validate` warns rather than errors, since embedded middleware legitimately has no listen address. Listen addresses are also checked for a parseable host:port. ([#15](https://github.com/dwarka-prasad/optictrace/issues/15))

- **`purge` could delete another tenant's data** (SQLite). The label match used `LIKE` without an `ESCAPE` clause, so `%` and `_` in a value stayed live wildcards: purging `acme_1` also destroyed `acmeX1`, and `a%` destroyed every tenant beginning with `a` — while still reporting success. The Postgres driver compares exactly and was never affected, so the two drivers disagreed on the same input. Values are now matched literally, and `TestConformancePurgeIsLiteral` runs the case against **both** drivers so they cannot diverge again. ([#4](https://github.com/dwarka-prasad/optictrace/issues/4))

### Added

- **Homebrew tap** — `brew install dwarka-prasad/tap/optictrace`, covering macOS and Linux on Intel and ARM. Published as a *formula* rather than a cask: casks are macOS-only, and a cask of an unsigned binary trips Gatekeeper quarantine. `scripts/update-tap.sh` regenerates it from each release's published `checksums.txt`, so the formula's hashes cannot drift from the artifacts users download.
- A **product page** (`docs/`, served by GitHub Pages) and a demo GIF in the README, both built from real output and live screenshots of a running stack rather than mockups.
- **`optictrace review` and a GitHub Action** — comments on every pull request with what the change does to API governance. Its core is a *policy diff*: the same captured traffic is evaluated under the base branch's rules and the PR's, so a change that stops redacting a field is reported with the number of real requests it affects. Also reports a coverage score, pre-existing leaks, and (with a spec) changes that break observed clients.
- By default a PR fails only for regressions it introduced; pre-existing findings are context, not a blocker. `fail-on: critical|high` escalates once the backlog is clear.
- Traffic can come from a running agent (`-from`, the CI case — records arrive already governed, so the job never handles raw payloads) or a JSONL export (`-from-file`).
- Coverage excludes 404s: a path the upstream doesn't serve isn't part of the API surface, and counting scanner noise against the score would make it untrustworthy.

### Fixed

- `optictrace suggest` no longer reports ordinary parameters as payment-card data. `pan`, `cvv` and `cvc` were substring matches, so `expand`, `company` and `panel` were all flagged high-confidence; they are now matched exactly. Found by running the Compose stack end to end.

### Changed

- The Compose demo config now exercises every governance mechanism — metering with billing, query redaction, tail-based sampling, the cardinality guard and a file exporter — so `docker compose up` produces a dashboard with real data instead of an empty shell. `/api/v1/orders` is deliberately left ungoverned so `scan` and `suggest` have something to find.

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
- Hijacked connections (WebSockets) pass through; once upgraded the bytes are not inspected. gRPC needs `service.http2` and is still not parseable without descriptors.
- Control-plane authentication is available but **off by default**.
- Homebrew publishing is configured but disabled until a `homebrew-tap` repository exists.

[Unreleased]: https://github.com/dwarka-prasad/optictrace/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/dwarka-prasad/optictrace/releases/tag/v0.7.0
