# Changelog

All notable changes to OpticTrace are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions `0.4.0`–`0.6.0` were development milestones that were never tagged;
`0.7.0` is the first public release and contains all of that work.

## [Unreleased]

### Added

- **Postgres and ClickHouse store application logs.** Previously SQLite only, so the feature was unavailable on exactly the multi-node deployments most likely to want it. Both implement the full `ext.AppLogStore` and both erase log lines together with the records a `purge` removes — ClickHouse deletes the lines first, because it has no transaction across the two mutations and a retry is safe while an orphaned line nothing can match again is not.

- **`ext/exttest` asserts the app-log contract**, including the erasure rule that `ext/applog.go` documents. That rule cannot be inferred from the interface signatures: a driver can implement `Store` and `AppLogStore` perfectly and still leave a purged tenant's log lines behind, and a log is the likelier place for the personal data to be sitting. The sub-tests skip for a driver without app-log support, so the interface stays genuinely optional. Verified by breaking each driver's purge in turn and watching the suite fail.

- **`optictrace scan` reads application log lines**, not only payloads. It was looking where the data is easiest to protect rather than where it escapes — a record whose body is `{"amount":42}` scanned clean while a card number sat in a log line attached to it. Findings group by service and level, and the suggested fix is a pattern or field name under `app_logs.redact` rather than a `json_fields` path, which could not work on free text. Both `optictrace scan` and `GET /api/scan` now report how many log lines were read alongside the record count.

## [0.10.0] — 2026-08-19

### Added

- **A Java SDK** (`sdks/java`) for anything on Jakarta Servlet 5+ — Spring Boot 3, Quarkus, Jetty, Tomcat. A servlet filter that evaluates the same `optic.yaml` in-process, plus `OpticTraceLogHandler` for application logs and `TraceContext.outboundHeaders()` for downstream calls. The response is teed as it is written, so a streaming response still streams and the client receives exactly the bytes the application produced.

  Its suite is a plain `main()` with no test framework — 57 checks — and asserts against a **live agent** when `OPTIC_AGENT_URL` is set. That check exists because offline tests cannot catch a record the agent rejects, which is precisely how the FastAPI SDK shipped nothing for weeks.

- **Application logs from Go and Express.** `optictrace.NewLogHandler` is an `slog.Handler`, and `optictrace.LogShipper` its Express counterpart; both correlate a line to the span being served with nothing at the call site knowing about OpticTrace. Go also gained `SpanFromContext` and `OutboundHeaders`, and the interceptor now publishes the span on the request context — an embedded handler previously had no way to name the request it was serving.

### Fixed

- **Every SDK is now at parity on the rule engine**, which the README claimed but was not true. Express gained trace correlation, meters, query-parameter redaction, tail-based `keep_errors`/`keep_slower_than`, and the `static:` / `path:` / `json:` / `json_response:` label sources with `|<regex>` capture; FastAPI gained `json:` and `json_response:`. The same `optic.yaml` producing different Prometheus series depending on which runtime served the request is worse than a missing label.

- **Express did not buffer response bytes when the body was restricted**, so `restrict: [response_body]` silently zeroed the meters — the same bug the Python SDK had. Metering is independent of capture, which is what lets a rule keep a prompt private while still counting the tokens in it.

- **A derived Go log handler shipped nothing.** `logger.With(...)` cloned the handler by value, giving each derived logger its own queue with no goroutine draining it — so most logging silently vanished. `go vet` caught the copied mutex; the queue is now shared. Test added.

## [0.9.0] — 2026-08-19

### Added

- **Application logs, correlated to the span that produced them.** `POST /api/applogs/ingest` accepts the lines your service wrote while serving a request; `GET /api/applogs?span=…` (or `?trace=`, `?level=`, `?q=`) reads them back, and the inspector shows them under the request itself. Correlation is by span id — never by timestamp, which under concurrent traffic files one tenant's line inside another tenant's request.

  Log lines are the **highest-risk surface** in the product: a payload is structured and can be redacted by path, but a log line is free text written by whoever was debugging that day. So `telemetry.app_logs` governs them on the way in rather than storing raw and cleaning up later — a level floor, a per-span line cap, a message byte cap, regex and field redaction, and its own retention horizon. An app that logs its own `Authorization` header is stored as `[REDACTED]`.

  `purge` deletes a tenant's log lines together with their records in one transaction: erasure that removes the requests but leaves the lines those requests wrote is not erasure, and a log is the likelier place for the personal data to be sitting.

  Lines carrying no span (startup, cron, background workers) are dropped by default and **counted** in `optictrace_app_logs_dropped_total{reason="orphan"}` — data discarded silently is data nobody knows they are missing. `drop_orphans: false` keeps them.

  Storage support is optional: `ext.AppLogStore` is a separate interface from `ext.Store`, discovered by type assertion, so a third-party driver without it is still a complete driver. Implemented for SQLite; Postgres and ClickHouse report the feature as unavailable rather than failing.

- **Collector mode.** With no `service.listen` and no `service.upstream`, `optictrace run` starts the admin API without a proxy — the deployment where framework SDKs govern in-process and POST to `/api/ingest`. Previously this required inventing a dummy upstream nobody talks to. A half-configured proxy (one address without the other) is still refused, because that is an omission rather than a mode.

- **A Python example that exercises all of it** (`examples/python-shop`): three FastAPI services making real HTTP calls to each other, governed in-process by the SDK, reporting into one agent, with a 25-assertion verification suite and an optional Prometheus + Grafana stack.

- **`make setup`, `make seed`, `make fixture`, `make test-all`** and `scripts/seed.sh`, which drives traffic covering every mechanism in `optic.yaml` — several tenants across regions and plans, an ungoverned route, errors, slow calls and a correlated trace. `docker compose up` now seeds itself, so the tour lands on a dashboard with something on it instead of an empty shell.

- **The dashboard caught up with the tags and traces work.** The inspector gained a **Tags** column whose chips filter on click (`label.<name>=<value>`, all of them ANDed, removable from the filter bar), a **stream** badge so a 600,000ms row reads as a connection lifetime rather than a catastrophe ([#24](https://github.com/dwarka-prasad/optictrace/issues/24)), and a **request trace** section in the detail panel that fetches every hop of the trace and renders it as a tree with per-hop latency bars — clicking a hop jumps to it. A tag a rule declared but the request never populated shows as `name=∅` rather than being hidden, since a silently absent tag is the usual symptom of a mistyped source. Exports now carry the tag filters, so downloading what the table shows no longer means downloading everything.
- **Usage can group by any tag**, not only the billing consumer label — partner, channel, product, whatever is in play. The picker is populated from tags present in recent traffic rather than from the config, because a tag that is declared but never populated is a dead option that sends someone to an empty breakdown.

- **Trace correlation across services.** Every record now carries `trace_id`, `span_id` and `parent_span_id`, taken from an inbound W3C `traceparent` or generated when the caller sends none. `/api/logs?trace=<id>` returns every hop of one request, so several services reporting into one store become a request tree rather than a flat list. Indexed in all three drivers, covered by the shared conformance suite.

  The forwarded request carries **this hop's** span so downstream calls nest under it — passing the caller's header through unchanged would make every downstream hop a sibling and flatten the tree. This is the one place OpticTrace writes to traffic and it is deliberately narrow: the forwarded copy only, never the response, never what the client sent. `service.trace.propagate_upstream: false` disables it; `service.trace.response_header` optionally returns the id to the caller and is off by default.

  The OTLP exporter now emits the record's stored ids rather than re-parsing headers, so a span and the record it came from cannot disagree about which trace they belong to. The `traceparent` parser moved to `internal/tracectx`, shared by the proxy, the exporter and the ingest path.

- **Multi-tenant tagging.** `match.headers` and `match.query` take regular expressions, so a rule can apply only to requests meeting a condition; and label sources gained `static:<value>` (the way to tag a class of traffic), `path:<n>` for a tenant carried in the URL, and an optional `|<regex>` capture-group suffix on any source (`header:X-Region|^([a-z]{2})-` turns `eu-west-1` into `eu`). Together these let one endpoint serving many tenants be segregated, metered and billed by tenant, plan tier, region or anything else in the request.

  There is deliberately **no separate `tags:` block**: rules already merge top to bottom with later ones winning, so a broad default plus a narrow override expresses conditional tagging using machinery that already governs redaction, sampling and metering.

  When the discriminator lives in the **payload** — two partners calling one lead endpoint with the same tenant and product, differing only in `$.lead.source` — `json:` and `json_response:` label sources and `match.body` criteria reach it, using the same path grammar as redaction including `**` recursive descent. Body values are extracted **after** redaction, so a label can never copy a masked field into a Prometheus dimension; validation refuses that overlap outright rather than leaving a label reading `[REDACTED]`. Only routes carrying a body rule buffer a body, and the set is recomputed on reload.

  Records can also be **filtered by tag**: `/api/logs?label.tenant=acme&label.tier=premium` (and the same on `/api/export`). Multiple labels are an AND, and values are matched literally by all three drivers — a tenant named `acme_1` must never select `acmeX1`, the same mistake that once let `purge` destroy a neighbour's data and just as wrong when it widens what someone is shown. Covered by the shared conformance suite, including the labels-only case where a driver that orders its WHERE clause wrongly returns everything.

  Criteria are decided from request context, so a rule using them does not match when that context is unavailable — the same fail-safe stance `graphql_operation` takes, because treating "cannot decide" as "matches" would silently apply a narrowly-scoped rule to everything. `review`, `suggest` and `optictrace test` all reconstruct that context, so a tagging rule is visible to the PR bot and testable before it ships.

### Changed

- **The dashboard overview leads with governance rather than latency.** A rule that matches nothing is called out by name — the config looks right, the dashboard looks green, and nothing is being enforced — alongside new panels for traffic by tenant, application logs by level, succeeded-vs-failed traffic and a per-service fleet strip. Panels refresh together on one window so they cannot disagree with each other.

- **`examples/traffic-sample.jsonl` is generated, not hand-written** (`make fixture`), from a real run against the same config the PR bot reviews with. A hand-written fixture keeps whatever fields existed the day someone typed it, so the bot quietly stops exercising everything added since; the old one had no trace ids, no streams and two label keys.

### Fixed

- **The FastAPI SDK had never delivered a single record.** It formatted timestamps with `%z` (`+0530`), which the agent's strict RFC3339 parser rejects with a 400 — and `_ship` swallowed every exception, so the SDK looked healthy while shipping nothing at all. Timestamps are now RFC3339 UTC, delivery failures are counted and the last error kept, and the test suite asserts the wire format rather than only the fields.

- **`optictrace test` never passed the request body**, so no rule using `match.body` or a `json:` label could be tested at all. An untestable governance rule is one nobody can trust. The runner now mirrors the proxy's two passes — redact, then let criteria and labels read the governed body.

- **A fleet of SDK services collapsed into one Prometheus series.** `service` was a const label fixed at agent startup, so several services reporting into one agent were all attributed to the collector; the store kept them apart while every dashboard showed one service. It is now a per-observation label. PromQL cannot distinguish a const label from a variable one, so existing queries and dashboards are unaffected.

- **The Python SDK ignored `meter:` entirely**, so anyone billing from a FastAPI service attributed zero. Meters now match the Go engine, including `*`/`**` paths, and read the raw response bytes so metering stays independent of capture.

- **The FastAPI SDK carried no trace context**, so SDK-instrumented services could not be correlated. It now adopts an inbound `traceparent` or starts a trace, exposes the span through a `ContextVar`, and ships `outbound_headers()` for the calls a service makes downstream. Label sources gained `static:`, `path:<n>` and the `|<regex>` capture suffix, matching the Go engine.

- **The dashboard silently vanished when the agent ran from another directory.** `-ui` defaults to a path relative to the working directory; the agent now also looks beside its own executable, and the fallback page says which path it searched instead of only "not found".

- **The flagship `optic.yaml` recorded a credential in the query string** (`?api_key=…` was not in `redact.query_params`) and **stored unmasked customer emails** returned by the user-read path. Both are closed, with rule tests covering them.

## [0.8.2] — 2026-08-16

### Security

- **The audit trail no longer records the bearer token.** The admin API accepts `?token=` so a browser can load the dashboard, so a request's raw query string can contain the credential — and `ext.Accessed.Filter` was recording it verbatim. An audit trail is written to be *read*, by auditors and SIEMs and whoever investigates an incident, so a live credential in it is handed to a wider set of people than held the token in the first place. Credential-shaped query parameters (`token`, `access_token`, `api_key`, `apikey`, `password`, `secret`) are masked before the filter is recorded; everything else survives intact, since the filter is the useful part. Found by running a licensed build end to end and reading the resulting trail.

## [0.8.1] — 2026-08-16

### Added

- **`cli` package** — the command line, importable. A binary that adds features can now *be* optictrace rather than reimplement it: register extensions with `ext`, then call `cli.Run(os.Args[1:], version)`. Every subcommand, flag and exit code is the same code, which is the only way to guarantee they behave the same. `cmd/optictrace` is now a six-line wrapper.

## [0.8.0] — 2026-08-16

Every issue on the tracker at the start of this cycle, plus the extension
surface that lets OpticTrace be built on from outside.

Two themes. **Closing the gap between what the docs claimed and what the code
did** — WebSocket upgrades returned 502 rather than passing through, gRPC could
not connect at all, a reload silently discarded most of the config, and `purge`
could delete a neighbouring tenant's data. And **`ext/`**, a public, versioned
extension surface: everything else lives under `internal/`, so until now there
was nowhere for an out-of-tree store, exporter or authentication method to
stand.

> **Breaking:** the admin API now binds `127.0.0.1` by default instead of all
> interfaces, and sends no CORS headers unless an origin is explicitly allowed.
> If you reached the dashboard from another host, set
> `admin_listen: "0.0.0.0:9095"` — and set `telemetry.auth` while you are there.
> See *Security* below for why.

### Added

- **`ext/` — a public extension surface.** Everything else lives under `internal/`, which other Go modules cannot import; `ext` is the deliberate exception, holding the record types and the `Store`/`Exporter` interfaces. Register a driver with `ext.RegisterStore` or `ext.RegisterExporter` and it becomes valid in `optic.yaml` purely by being linked in — the core needs no changes. Driver-specific keys live under a `settings:` map, since the decoder rejects unknown top-level keys on purpose. The record types are *aliased* from `internal/store`, not duplicated, so there is exactly one `Record` in the program.

- **Admin extension hooks: authentication, authorization and audit.** `ext.RegisterAuthenticator` (with an optional `Challenger` for interactive login redirects), `ext.RegisterAuthorizer`, `ext.RegisterAuditor` and `ext.RegisterAdminRoutes`. Every admin route now declares a **capability** describing what it exposes, so policy is written against capabilities rather than URLs — an extension never tracks OpticTrace's routing, and a route cannot be added without classifying it. `read:payload` and `export` are deliberately separate. The chain fails closed (a panicking authenticator 401s, a panicking authorizer 403s), composes by intersection, and never returns a denial reason to the caller. Audit events carry what was reached — count, record ids, filter, tenant — not just the URL. With nothing registered and no token, behaviour is unchanged. [`examples/adminauth`](examples/adminauth) is a worked SSO+RBAC+audit implementation in its own module.

- **`ext/exttest` — the conformance suite, exported.** The acceptance criteria the built-in drivers run are now public, so an out-of-tree store can be held to the identical contract. [`examples/memstore`](examples/memstore) is a worked reference: a complete driver in its own module, outside the `optictrace/` path prefix so it genuinely cannot reach `internal/`, passing the full suite using only `ext`. CI builds it, so a gap in the extension surface fails the build.

- **Cleartext HTTP/2 (h2c)** behind `service.http2: true`. Off by default: it changes protocol negotiation for every client. This is what an HTTP/2 client needs to connect at all — it is *not* gRPC support, and the docs now say so plainly rather than describing gRPC as merely "not specifically supported". ([#11](https://github.com/dwarka-prasad/optictrace/issues/11))

- **Streams are measured separately from requests.** `optictrace_stream_duration_seconds` (1s–4.5h buckets), `optictrace_streams_total` and `optictrace_streams_open` cover SSE, chunked responses and upgraded connections. Their durations no longer enter `optictrace_request_duration_seconds` or the dashboard's route percentiles, where a single 10-minute SSE connection used to define a route's p95 for the whole window. Records carry a `stream` flag; existing databases are migrated in place. ([#12](https://github.com/dwarka-prasad/optictrace/issues/12))

- **ClickHouse `LogStore` driver** (`telemetry.store.driver: clickhouse`). Every dashboard query is a time-bucketed aggregation over an append-only table, which is what a column store is for. It passes the shared conformance suite unmodified alongside SQLite and Postgres, so the three drivers cannot answer the same question differently. Two things genuinely differ and are handled explicitly rather than hidden: ClickHouse has no autoincrement, so IDs are generated client-side with a millisecond prefix to preserve newest-first ordering; and `DELETE` is an asynchronous mutation, so every delete path runs with `mutations_sync = 2` — an erasure request that returned before the data was gone would be worse than useless. The driver is pure Go, so `CGO_ENABLED=0` and the static release binaries are unaffected. ([#2](https://github.com/dwarka-prasad/optictrace/issues/2))

- **GraphQL operations are first-class.** Set `service.graphql_paths`, and the operation name is extracted from the request body, appended to the route (`/graphql:CreatePayment`), and matchable with `match.graphql_operation`. Previously every operation collapsed into one `/graphql` route: latency percentiles averaged a 2ms `viewer` query with a 4s report, a rule could not redact a field on one mutation without applying to every query, and inferred specs produced a single endpoint whose schema was the union of everything. Operation names are client-supplied, so they are validated as plain identifiers and length-capped before becoming a label; batched requests report `batch` rather than being attributed to whichever operation came first. ([#10](https://github.com/dwarka-prasad/optictrace/issues/10))

- **Org-specific `scan` detectors** via `scan.detectors` in `optic.yaml`, merged with the built-ins. Patterns compile at load time so a bad one fails `optictrace validate` rather than at scan time, patterns that match the empty string are rejected, and a `verify:` registry exposes the built-in checksums (`luhn`, `iban`, `us_ssn`, and a new `verhoeff` for Aadhaar and similar national IDs) so a custom detector can be as precise as a built-in. Findings still go through `Mask()`, so a custom detector cannot become the hole in that. ([#3](https://github.com/dwarka-prasad/optictrace/issues/3))

- **Homebrew tap** — `brew install dwarka-prasad/tap/optictrace`, covering macOS and Linux on Intel and ARM. Published as a *formula* rather than a cask: casks are macOS-only, and a cask of an unsigned binary trips Gatekeeper quarantine. `scripts/update-tap.sh` regenerates it from each release's published `checksums.txt`, so the formula's hashes cannot drift from the artifacts users download.

- A **product page** (`docs/`, served by GitHub Pages) and a demo GIF in the README, both built from real output and live screenshots of a running stack rather than mockups.

- **`optictrace review` and a GitHub Action** — comments on every pull request with what the change does to API governance. Its core is a *policy diff*: the same captured traffic is evaluated under the base branch's rules and the PR's, so a change that stops redacting a field is reported with the number of real requests it affects. Also reports a coverage score, pre-existing leaks, and (with a spec) changes that break observed clients.

- By default a PR fails only for regressions it introduced; pre-existing findings are context, not a blocker. `fail-on: critical|high` escalates once the backlog is clear.

- Traffic can come from a running agent (`-from`, the CI case — records arrive already governed, so the job never handles raw payloads) or a JSONL export (`-from-file`).

- Coverage excludes 404s: a path the upstream doesn't serve isn't part of the API surface, and counting scanner noise against the score would make it untrustworthy.

### Changed

- The Compose demo config now exercises every governance mechanism — metering with billing, query redaction, tail-based sampling, the cardinality guard and a file exporter — so `docker compose up` produces a dashboard with real data instead of an empty shell. `/api/v1/orders` is deliberately left ungoverned so `scan` and `suggest` have something to find.

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

- `optictrace suggest` no longer reports ordinary parameters as payment-card data. `pan`, `cvv` and `cvc` were substring matches, so `expand`, `company` and `panel` were all flagged high-confidence; they are now matched exactly. Found by running the Compose stack end to end.

### Performance

- **Rule-match counts are one query instead of N.** `/api/rules/stats` ran one `matched_rules LIKE '%"name"%'` per rule — and a LIKE pattern with a leading wildcard can never use an index, so that was N full table scans per dashboard load. SQLite now expands the JSON array with `json_each` and groups in one indexed pass; measured 117ms → 52ms at 50k rows with 10 rules, and it now scales with rule count rather than multiplying by it. Postgres gained the GIN index on `matched_rules` that its containment query never had. ([#9](https://github.com/dwarka-prasad/optictrace/issues/9))

- **Route percentiles no longer sort every matching row.** A new `(route, method, duration_ms)` index means the per-route `ORDER BY duration_ms LIMIT 1 OFFSET n` subqueries walk an ordered index; `EXPLAIN QUERY PLAN` confirms the temp B-tree for the sort is gone.

- **Analysis passes stream instead of materialising.** `/api/scan` and `/api/spec` loaded up to 20,000 complete records — bodies included, so gigabytes at the default capture limit — before analysing any of them, on endpoints that were unauthenticated by default. Both analysers now fold record-by-record through a new `LogStore.RecentFunc`, holding one record at a time. The cap is configurable via `telemetry.store.analysis_max_rows`, and the CLI says so when it truncates rather than letting a partial analysis read as a complete one. ([#7](https://github.com/dwarka-prasad/optictrace/issues/7))

### Testing

- **`internal/config`, `internal/admin` and `sdks/gin` had no tests at all.** They now cover the auth path (constant-time compare, query-token fallback, health bypass, preflight), the CORS allowlist, export pagination across multiple pages in both JSONL and CSV, the billing cost arithmetic component by component, every config validation rule, and the Gin adapter's `Flusher`/`Hijacker`/`Pusher` surface — the same class of wrapper bug as #5. Config coverage went 0% → 77%, admin 0% → 41%. CI now runs the SDK's tests rather than only building it. ([#13](https://github.com/dwarka-prasad/optictrace/issues/13))

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

[Unreleased]: https://github.com/dwarka-prasad/optictrace/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/dwarka-prasad/optictrace/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dwarka-prasad/optictrace/compare/v0.8.2...v0.9.0
[0.8.2]: https://github.com/dwarka-prasad/optictrace/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/dwarka-prasad/optictrace/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/dwarka-prasad/optictrace/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dwarka-prasad/optictrace/releases/tag/v0.7.0
