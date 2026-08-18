<div align="center">

# 👁️ OpticTrace

**Declarative API telemetry & governance — like OpenAPI, but for observability.**

One `optic.yaml` controls what your API traffic reveals: which routes are monitored,
which payloads are captured, what gets redacted, and which request attributes become
Prometheus dimensions.

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-v0.8.0--dev-orange)](#roadmap)

**[optictrace product page →](https://dwarka-prasad.github.io/optictrace/)**

<br>

<img src="docs/assets/demo.gif" alt="A payment request passes through OpticTrace: the client receives the real card number while the stored telemetry shows [REDACTED]" width="820">

<sub>Real output from a running agent — the client gets the original bytes, the telemetry never sees the card.</sub>

</div>

---

## Contents

- [Why OpticTrace?](#why-optictrace)
- [How it works](#how-it-works) — [request flow](#request-flow-two-lanes-one-tee-point) · [architecture](#architecture-components-and-who-talks-to-whom)
- [Quickstart](#quickstart)
- [`optic.yaml` reference](#opticyaml-reference)
- [What's supported today](#whats-supported-today)
- [Surfaces](#surfaces) — [CLI](#cli) · [control-plane API](#control-plane-api-9095) · [metrics](#metrics-exposed)
- [Pull-request reviews](#pull-request-reviews)
- [Traffic-powered tooling](#traffic-powered-tooling)
- [Export plugins](#export-plugins)
- [Framework SDKs](#framework-sdks)
- [Developer dashboard](#developer-dashboard)
- [Deployment](#deployment)
- [Measured overhead](#measured-overhead) · [verified behavior](#verified-behavior)
- [Roadmap](#roadmap) — what to build next, and why
- [Changelog](CHANGELOG.md)
- [Contributing](#contributing)

---

## Why OpticTrace?

API observability usually forces a bad trade: log everything (and leak credit cards into
your log pipeline) or log nothing useful. OpticTrace makes the trade-off **declarative and
reviewable**:

```yaml
rules:
  - name: redact-payment-secrets
    match: { path: "/api/v1/payments/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.credit_card.number"]   # any nesting depth
    labels:
      tenant: "header:X-Tenant-ID"               # a real Prometheus dimension
```

- 🔍 **Capture-by-default, restrict-by-rule** — everything is observable unless a rule says otherwise, and the rules live in your repo where they get code-reviewed.
- 🛡️ **Traffic is never mutated** — governance applies to what gets *recorded*; clients and upstreams always see original bytes.
- 📊 **Prometheus-native** — request counts, error rates, P50/P95/P99 per route, plus your own label dimensions extracted from headers or query params.
- 🖥️ **Built-in developer dashboard** — live charts, a searchable request inspector, a config linter, served by the same single binary.
- ⚡ **Built for the hot path** — rules compile once at startup; restricted routes skip capture entirely; body capture is size-bounded; storage is async and drops rather than blocks.

And because OpticTrace owns your real traffic history, it does things static tools can't:

- 🤖 **Reviews your pull requests** — a GitHub Action that comments on every PR with what the change does to governance, measured by replaying real traffic under both the old and new rules. It catches the change that *looks* harmless in a diff but stops redacting a card number.
- 🕵️ **Leak detector** — `optictrace scan` finds sensitive values your rules *didn't* cover. Redaction masks what you name; this catches the field you forgot, and prints the rule that would have stopped it.
- 🧪 **Testable governance** — `optictrace test` asserts your rules behave as intended, with no server and no network, so CI proves a refactor didn't stop redacting.
- 🧬 **Traffic → OpenAPI → SDK** — `optictrace spec` infers a spec from what clients *actually* send; `optictrace sdk` emits typed TypeScript, Python or Go clients.
- 🚨 **Breaking-change linter** — `optictrace check` answers *"is any live client actually using the field I'm about to remove?"* with usage counts and last-seen times. Exits non-zero in CI.
- 🎭 **Stateful mock server** — `optictrace mock` gives you a mock where `POST /cart` then `GET /cart` really returns the added item; optional AI-generated responses via Claude.
- 💰 **FinOps metering** — extract usage figures (e.g. LLM token counts) from responses, attribute cost per tenant, export billing CSVs.

---

## How it works

### The idea

Everything is captured by default; rules **subtract** from that baseline. The governing
invariant makes this safe to adopt:

> **Live traffic is never modified.** Restriction and redaction apply only to the telemetry
> OpticTrace *records*. A rule that masks `$.credit_card.number` does not strip the card
> number from the payment request — the payment still works. It strips it from what gets
> logged, stored, and exported.

### Request flow: two lanes, one tee point

A request travels one path while its telemetry travels another. The traffic lane is a plain
reverse proxy. The telemetry lane branches off a **bounded copy** and is where all
governance happens.

```mermaid
flowchart LR
    C(["Client"])
    P["OpticTrace :8080"]
    U(["Your service"])

    subgraph tel ["TELEMETRY LANE - governed before anything is written"]
        direction LR
        G["1 - Evaluate<br/>match rules, merge policy"]
        A["2 - Attach<br/>buffers, or skip entirely"]
        O["3 - Observe<br/>status, latency, bytes"]
        V["4 - Govern<br/>restrict, redact, meter"]
        F["5 - Fan out<br/>one canonical record"]
        G --> A --> O --> V --> F
    end

    S1["Console<br/>structured JSON"]
    S2["Prometheus<br/>metrics endpoint"]
    S3["SQLite<br/>async, drops before blocking"]
    S4["Exporters<br/>file, webhook, plugin"]

    C -->|"request"| P
    P -->|"forwarded verbatim"| U
    U -.->|"response"| P
    P -.->|"returned byte-for-byte"| C
    P ==>|"bounded copy"| G
    F --> S1
    F --> S2
    F --> S3
    F --> S4

    style P fill:#0a6b89,stroke:#0a6b89,color:#ffffff
    style tel fill:#f6ebd6,stroke:#8e5c0d,color:#8e5c0d
```

| Stage | What happens | Why it matters |
|---|---|---|
| **1 · Evaluate** | Method + path matched against compiled rules; every match merges into one policy | Rules compile once at startup — the hot path is a linear scan of cheap comparisons |
| **2 · Attach** | Capture buffers wired up — or skipped entirely | The policy resolves *before* capture attaches, so a restricted route allocates **no buffers at all** |
| **3 · Observe** | Upstream runs; status, latency and byte counts recorded | Metadata is always recorded, even when payload capture is fully restricted |
| **4 · Govern** | Restricted fields dropped, redacted fields masked, labels and meters extracted | Nothing downstream ever sees raw sensitive data |
| **5 · Fan out** | One canonical record handed to every sink | Console, Prometheus, store and exporters all receive the *same governed record* |

**Why a bounded copy:** capture is capped at `capture_limit_bytes` (64 KB default) and
flagged as truncated on overflow. A 2 GB upload streams through to the upstream at full
speed while telemetry stays small — the tap never becomes a bottleneck.

### Architecture: components, and who talks to whom

Traffic and control plane listen on **separate ports** by design, so the dashboard and
metrics can be firewalled independently of the API being proxied.

```mermaid
flowchart TB
    subgraph ing ["INGRESS"]
        direction LR
        I1["Sidecar :8080"]
        I2["Go middleware<br/>embedded in your app"]
        I3["SDK ingest<br/>Express, FastAPI, Gin"]
    end

    subgraph core ["CORE"]
        direction LR
        E["Rule engine<br/>compiled globs, hot-swappable"]
        X["Interceptor<br/>tees, applies policy, builds record"]
    end

    subgraph sink ["SINKS"]
        direction LR
        M["Collector<br/>private Prometheus registry"]
        W["Async writer<br/>bounded queue to SQLite"]
        D["Dispatcher<br/>per-exporter queues"]
        L["Logger<br/>slog JSON"]
    end

    subgraph ctrl ["CONTROL PLANE :9095"]
        direction LR
        API["Admin API<br/>logs, stats, usage, reload"]
        MET["Metrics endpoint"]
        UI["Dashboard<br/>Next.js static export"]
    end

    subgraph tools ["OFFLINE TOOLS - read the captured history"]
        direction LR
        T1["spec<br/>to OpenAPI"]
        T2["check<br/>spec vs. usage"]
        T3["sdk<br/>to TypeScript"]
        T4["mock<br/>to stateful server"]
    end

    ing --> core
    core --> sink
    M --> ctrl
    W --> ctrl
    D --> ctrl
    W -.-> tools

    style core fill:#0a6b89,stroke:#0a6b89,color:#ffffff
```

Everything above ships in a **single binary** — the dashboard is compiled in as static files.
The offline tools are commands you run against captured history, not long-running services.

**Two deployment modes share one code path:**

- **Sidecar / gateway** — `optictrace run` reverse-proxies to your service.
- **Embedded** — native middleware inside your app ([Go](#go--net-http--gin), [Express](#nodejs--express), [FastAPI](#python--fastapi)). SDKs apply governance **in-process**, so sensitive data never leaves your app raw, then ship governed records to the agent.

---

## Quickstart

### Docker Compose (agent + demo API + Prometheus)

```bash
git clone https://github.com/dwarka-prasad/optictrace && cd optictrace
docker compose up --build
```

| URL | What |
|---|---|
| `http://localhost:8080` | your API, proxied through OpticTrace |
| `http://localhost:9095` | dashboard · `/metrics` · query APIs |
| `http://localhost:9090` | Prometheus, pre-configured to scrape OpticTrace |

### Install

```bash
brew install dwarka-prasad/tap/optictrace     # macOS and Linux
go install github.com/dwarka-prasad/optictrace/cmd/optictrace@latest
```

Or grab a signed binary from [releases](https://github.com/dwarka-prasad/optictrace/releases).
The Homebrew formula ships an annotated `optic.yaml` and its rule tests, so
`optictrace validate` works the moment it's installed.

<sub>On Linux, Homebrew pulls in its own `glibc`/`gcc` for any formula — OpticTrace
itself is a static, CGO-free binary and needs neither, so the tarball or
`go install` is lighter if you'd rather skip that.</sub>

### From source

```bash
go build -o bin/ ./cmd/...
(cd ui && npm install && npm run build)   # optional: the embedded dashboard
./bin/optictrace validate -config optic.yaml
./bin/optictrace run -config optic.yaml
```

Send traffic through `service.listen`, then open `http://localhost:9095`.

---

## `optic.yaml` reference

Parsing is **strict**: unknown keys are rejected rather than silently ignored, so a typo
like `restirct:` fails at load instead of quietly disabling your governance.

```yaml
# ── identity ──────────────────────────────────────────────
version: 1

service:
  name: payments-api
  listen: ":8080"                    # proxied traffic
  upstream: "http://localhost:9000"

# ── where telemetry goes ──────────────────────────────────
telemetry:
  admin_listen: "127.0.0.1:9095"     # dashboard + /metrics + APIs (loopback by default)
  cors_origins: []                   # browser origins allowed cross-origin; none by default
  console_log: true                  # structured JSON on stdout
  metrics:
    enabled: true
    buckets: [0.005, 0.05, 0.5, 5]   # latency histogram bounds (seconds)
  auth:                              # control-plane authentication (off by default)
    token_env: OPTICTRACE_ADMIN_TOKEN  # preferred: keeps the secret out of git
    # token: "literal-token"           # alternative, discouraged
    allow_health: true                 # keep /healthz open for probes
  tls:                               # optional HTTPS for the control plane
    cert_file: /etc/optictrace/tls.crt
    key_file:  /etc/optictrace/tls.key
  store:
    driver: sqlite                   # sqlite | postgres | clickhouse | none                   # sqlite | none
    dsn: optictrace.db
    queue_size: 4096                 # async queue; overflow drops, never blocks
    retention_max_rows: 100000       # oldest rows pruned
    retention_max_age: 720h
    analysis_max_rows: 20000         # cap for scan/spec/suggest/review reads          # ...and anything older than 30 days
  exporters:                         # fan out governed records
    - { name: audit, type: file,    path: ./export/audit.jsonl }
    - { name: siem,  type: webhook, url: "https://siem.internal/ingest",
        headers: { Authorization: "Bearer ..." }, batch_size: 100, flush_interval: 5s }
    - { name: mine,  type: command, command: ["python3", "my_exporter.py"] }
  billing:                           # cost attribution (FinOps)
    consumer_label: tenant
    currency: USD
    prices:
      per_request: 0.0001
      per_gb: 0.05
      per_meter_unit: { tokens: 0.000002 }   # $2 per 1M tokens

# ── the opt-out baseline ──────────────────────────────────
defaults:
  capture: { request_body: true, response_body: true, headers: true }
  capture_limit_bytes: 65536         # per-body telemetry cap (traffic unaffected)

# ── rules: evaluated top-to-bottom, actions merge ─────────
rules:
  - name: no-capture-on-auth
    match:
      path: "/api/v1/auth/**"        # * = one segment, ** = zero or more
      methods: [POST]                # optional; omitted = all methods
    restrict: [request_body, response_body, headers, query]

  - name: redact-payment-secrets
    match: { path: "/api/v1/payments/**" }
    redact:
      headers: [Authorization, X-Api-Key]
      query_params: [api_key, token] # ?api_key=… masked in captured queries
      json_fields:
        - "$.credit_card.number"     # exact dotted path
        - "$.*.ssn"                  # * = any single key
        - "$.**.card_token"          # ** = any nesting depth
    labels:
      tenant: "header:X-Tenant-ID"   # Prometheus dimension + log field
      plan:   "query:plan"
    sample: 0.25                     # capture bodies for 25% of matches
                                     # (metrics & metadata stay complete)

  - name: meter-ai-tokens
    match: { path: "/api/v1/ai/**" }
    restrict: [request_body, response_body]   # prompts stay private...
    meter:
      tokens: "$.usage.total_tokens"          # ...but tokens are still counted
```

**How rules merge.** Rules are *not* first-match-wins. Every matching rule contributes:
restrictions only ever **narrow** capture, while redactions, labels and meters
**accumulate**. Later rules win on conflicting scalars like `sample`. That lets a broad
redaction rule and a narrow restriction rule compose instead of fighting.

**Arrays and depth.** JSON paths traverse arrays implicitly, so `$.items.price` covers every
element of an `items` list. `$.**` descends to any depth — which matters when an upstream
echoes a payload back inside a wrapper and would otherwise leak the field you just masked.

**Hot reload.** `kill -HUP <pid>` or `POST /api/reload` swaps the rule engine atomically;
in-flight requests finish under their old policy. An invalid config is rejected and the old
rules stay live.

---

## What's supported today

✅ Shipped · 🟡 Partial or deliberate limit · ⬜ Not yet

### Governance engine

| Capability | Status | Notes |
|---|:--:|---|
| Path globbing | ✅ | `*` = one segment, `**` = zero or more; shell patterns inside a segment; optional method filters |
| Restriction | ✅ | Disable `request_body`, `response_body` or `headers` capture per rule |
| Redaction | ✅ | Mask headers by name and JSON fields by path, incl. wildcard and recursive descent |
| Custom labels | ✅ | Extracted from headers or query params; become real Prometheus dimensions |
| Body sampling | ✅ | Capture payloads for a fraction of matches; metrics and metadata stay complete |
| Tail-based sampling | ✅ | `keep_errors` and `keep_slower_than` rescue 5xx and slow requests that a uniform draw would have discarded |
| Metering | ✅ | Pull numbers out of responses by JSON path — works even on fully restricted routes |
| Hot reload | ✅ | `SIGHUP` or API; invalid configs rejected, old rules stay live |
| Strict validation | ✅ | Unknown keys rejected at load; `optictrace validate` for CI |
| Rule unit tests | ✅ | `optictrace test` asserts matched rules, capture flags, redacted output, labels, meters and leak absence |
| Leak detection | ✅ | `optictrace scan` finds sensitive values outside your rules and suggests the fix; masked output only |

### Observability & storage

| Capability | Status | Notes |
|---|:--:|---|
| Prometheus exporter | ✅ | Ten metric families on a **private registry**, so embedding never collides with an app's own |
| Bounded cardinality | ✅ | `route` is always a rule glob or normalized pattern — `/users/42` → `/users/:id` |
| SQLite payload store | ✅ | Pure-Go driver (no CGO), WAL mode, async writer that drops under backpressure |
| Retention & erasure | ✅ | Row-count *and* age-based pruning; `optictrace purge` deletes everything held for one consumer |
| Label cardinality guard | ✅ | Caps distinct values per custom label (default 500); overflow collapses to `__over_limit__` and is counted |
| Postgres driver | ✅ | Multi-node store with JSONB aggregation and `percentile_cont`; shares a conformance suite with SQLite |
| ClickHouse driver | ⬜ | The interface is proven by two implementations now; a column store is the next natural driver |
| OpenTelemetry export | ✅ | `type: otlp` exporter emits spans over OTLP/HTTP JSON; no SDK dependency |

### Storage at scale

SQLite is right for a sidecar with a single writer. When several agents — or
several replicas of one agent — need shared history, point them at Postgres:

```yaml
telemetry:
  store:
    driver: postgres
    dsn: "postgres://optic:secret@db:5432/optictrace?sslmode=require"
```

Both drivers implement the same `LogStore` interface and are held to it by a
shared conformance suite, so behaviour cannot quietly diverge. Postgres pushes
percentiles (`percentile_cont`), usage grouping and label matching into the
database via JSONB, where SQLite scans and aggregates in Go.

Run the Postgres half of the suite locally with:

```bash
docker run -d -e POSTGRES_PASSWORD=optic -e POSTGRES_DB=optictrace -p 5432:5432 postgres:16-alpine
OPTICTRACE_TEST_POSTGRES='postgres://postgres:optic@localhost:5432/optictrace?sslmode=disable' \
  go test ./internal/store
```

## Export plugins

| Capability | Status | Notes |
|---|:--:|---|
| `file` | ✅ | Appends JSON Lines, rotates at a size threshold |
| `webhook` | ✅ | POSTs batched JSON arrays with custom headers; one retry, then the batch counts as failed |
| `otlp` | ✅ | Emits OpenTelemetry spans to a collector; bodies never attached |
| `command` — **custom plugin hook** | ✅ | Spawns any executable, streams one JSON record per line to stdin; stderr folded into the agent log; crashed plugins restart with backoff |
| Delivery guarantee | 🟡 | **At-most-once, deliberately.** Each exporter has its own bounded queue and worker, so a dead plugin drops only its own records and never stalls the request path |

### Pull-request reviews

Every other command is one you have to remember to run. This one runs itself,
on every pull request, and answers the question a reviewer actually has:
**does this change make governance weaker?**

```yaml
# .github/workflows/governance-review.yml
- uses: dwarka-prasad/optictrace@v0
  with:
    agent-url: ${{ vars.OPTICTRACE_AGENT_URL }}   # an agent watching staging
    token: ${{ secrets.OPTICTRACE_TOKEN }}
    window: 24h
```

It posts one comment that updates in place:

> ### ✗ This change weakens governance on 4 point(s)
>
> | | Route | Change | Requests affected |
> |---|---|---|--:|
> | ✗ | `POST /api/v1/payments/**` | stops redacting `$.**.credit_card.cvv` | 34 |
> | ✗ | `POST /api/v1/payments/**` | stops redacting query param `api_key` | 34 |
> | ⚠ | `POST /api/v1/auth/**` | now captures request bodies (was restricted) | 34 |
> | ⚠ | `POST /api/v1/payments/**` | drops label `region` (breaks its Prometheus dimension) | 34 |

**How it knows.** It evaluates the *same captured traffic* under the base
branch's `optic.yaml` and the PR's, then reports where the two disagree. A
rule reordering that silently stops masking a field is invisible in a text
diff and obvious here — and every row carries the number of real requests it
affects, so the finding is arguable rather than theoretical.

**Why it won't get muted.** By default a PR fails only for what *it* changed.
Pre-existing leaks are reported for context but don't block, because failing
every pull request for a problem someone else introduced is how a bot gets
ignored — and an ignored bot protects nothing. Once your backlog is clear,
`fail-on: critical` stops new ones creeping in.

The comment also carries a coverage score (share of traffic governed by a
rule, routes with rules, sensitive-looking fields handled), any leaks found,
and — with `spec:` set — changes that would break clients seen in traffic.
404s are excluded from coverage, since you can't write a rule for a route
that doesn't exist.

No staging environment? Point it at a JSONL export instead:

```bash
optictrace review -config optic.yaml -base-config /tmp/base.yaml \
  -from-file examples/traffic-sample.jsonl
```

See [`examples/workflows/governance-review.yml`](examples/workflows/governance-review.yml)
for a complete workflow. This repo dogfoods it in
[`.github/workflows/governance.yml`](.github/workflows/governance.yml).

## Traffic-powered tooling

| Capability | Status | Notes |
|---|:--:|---|
| Infer OpenAPI from traffic | ✅ | `required` = present in *every* request; `integer`+`float` widen to `number`; ID segments collapse to path templates; redacted fields still contribute name and type |
| Breaking-change linter | ✅ | Reports usage counts and last-seen times; exits non-zero on breaking findings |
| TypeScript SDK generation | ✅ | Dependency-free typed fetch client; passes `tsc --strict` |
| Python / Go SDK generation | ✅ | `-lang python` emits TypedDict models + urllib client; `-lang go` emits structs + net/http client |
| Stateful mock server | ✅ | Real CRUD state on collection/item routes; schema-conforming data elsewhere with field-name heuristics |
| AI-generated mock responses | 🟡 | Implemented behind `-ai` + `ANTHROPIC_API_KEY` with deterministic fallback, but **not yet exercised against the live API** |
| Query-parameter capture | ✅ | Captured and governed via `redact.query_params` / `restrict: [query]`; feeds spec inference and the leak scanner |

### Integration & deployment

| Capability | Status | Notes |
|---|:--:|---|
| Sidecar + embedded modes | ✅ | Reverse proxy and Go `http.Handler` middleware sharing one interception path |
| Express / FastAPI / Gin SDKs | ✅ | Express and FastAPI carry semantically identical engine ports, so redaction happens in-process |
| Docker / Compose / Helm | ✅ | Multi-stage non-root image; Compose stack with Prometheus; chart with probes, optional PVC and ServiceMonitor |
| Admin-port authentication | ✅ | Optional bearer token (constant-time, `token_env`) + TLS. **Off by default** — enable it whenever the port could be reachable |
| WebSockets | ✅ | Upgrades pass through; the exchange is recorded as a `101`, and the connection itself is not inspected |
| HTTP/2 (h2c) | ✅ | Opt-in via `service.http2: true` |
| gRPC | ⬜ | Needs `service.http2`, and even then bodies are length-prefixed protobuf — without descriptors there is nothing to redact or meter. Use the SDK middleware |
| GraphQL | ✅ | Set `service.graphql_paths`; the operation name then becomes part of the route and is matchable with `match.graphql_operation` |

---

## Surfaces

### CLI

| Command | Does |
|---|---|
| `optictrace run` | Start proxy + control plane |
| `optictrace validate` | Lint `optic.yaml` (CI-friendly) |
| `optictrace test` | Assert rules behave as intended; exit 1 on failure |
| `optictrace scan` | Find sensitive values your rules missed; exit 1 on findings |
| `optictrace review` | PR report: policy diff, coverage, leaks, breaking changes |
| `optictrace purge` | Erase all stored records for one consumer (erasure requests) |
| `optictrace suggest` | Propose rules for sensitive-looking field *names* |
| `optictrace replay` | Re-issue captured traffic against a target and diff statuses |
| `optictrace spec` | Infer OpenAPI from captured traffic |
| `optictrace check` | Spec vs. live usage; exit 1 on breaking findings |
| `optictrace sdk` | Generate a typed client (`-lang typescript\|python\|go`) |
| `optictrace mock` | Serve a stateful mock from a spec |
| `optictrace version` | Print the build version |

### Control-plane API `:9095`

| Endpoint | Returns |
|---|---|
| `GET /metrics` | Prometheus exposition |
| `GET /healthz` | Liveness + uptime |
| `GET /api/logs` | Filtered captured exchanges |
| `GET /api/logs/{id}` | One exchange in full |
| `GET /api/stats` | Aggregates, time series, percentiles |
| `GET /api/routes` | Per-route latency breakdown |
| `GET /api/rules/stats` | Rules joined with live match counts |
| `GET /api/usage` | Per-consumer usage and cost (`&format=csv`) |
| `GET /api/scan` | Sensitive values found outside your rules (masked) |
| `GET /api/services` | Per-service aggregates (fleet view) |
| `GET /api/spec` | OpenAPI inferred from traffic |
| `GET /api/export` | CSV or JSONL download of captured records |
| `GET /api/config` | Current config + validity |
| `POST /api/config/validate` | Lint a candidate config |
| `POST /api/reload` | Re-read config, hot-swap engine |
| `POST /api/ingest` | Accept governed records from SDKs |
| `GET /api/system` | Agent health, store size, exporter stats |

### Metrics exposed

| Metric | Type | Labels |
|---|---|---|
| `optictrace_requests_total` | counter | `method route status status_class` + yours |
| `optictrace_request_duration_seconds` | histogram | `method route` + yours |
| `optictrace_request_size_bytes` | histogram | `method route` |
| `optictrace_response_size_bytes` | histogram | `method route` |
| `optictrace_inflight_requests` | gauge | — |
| `optictrace_store_dropped_total` | counter | — |
| `optictrace_sdk_ingested_total` | counter | — |
| `optictrace_exported_total` | counter | `exporter` |
| `optictrace_export_failed_total` | counter | `exporter` |
| `optictrace_export_dropped_total` | counter | `exporter` |
| `optictrace_label_capped_total` | counter | `label` |
| `optictrace_label_distinct_values` | gauge | `label` |

P99 per route:

```promql
histogram_quantile(0.99,
  sum by (le, route) (rate(optictrace_request_duration_seconds_bucket[5m])))
```

---

## Pull-request reviews

Every other command is one you have to remember to run. This one runs itself,
on every pull request, and answers the question a reviewer actually has:
**does this change make governance weaker?**

```yaml
# .github/workflows/governance-review.yml
- uses: dwarka-prasad/optictrace@v0
  with:
    agent-url: ${{ vars.OPTICTRACE_AGENT_URL }}   # an agent watching staging
    token: ${{ secrets.OPTICTRACE_TOKEN }}
    window: 24h
```

It posts one comment that updates in place:

> ### ✗ This change weakens governance on 4 point(s)
>
> | | Route | Change | Requests affected |
> |---|---|---|--:|
> | ✗ | `POST /api/v1/payments/**` | stops redacting `$.**.credit_card.cvv` | 34 |
> | ✗ | `POST /api/v1/payments/**` | stops redacting query param `api_key` | 34 |
> | ⚠ | `POST /api/v1/auth/**` | now captures request bodies (was restricted) | 34 |
> | ⚠ | `POST /api/v1/payments/**` | drops label `region` (breaks its Prometheus dimension) | 34 |

**How it knows.** It evaluates the *same captured traffic* under the base
branch's `optic.yaml` and the PR's, then reports where the two disagree. A
rule reordering that silently stops masking a field is invisible in a text
diff and obvious here — and every row carries the number of real requests it
affects, so the finding is arguable rather than theoretical.

**Why it won't get muted.** By default a PR fails only for what *it* changed.
Pre-existing leaks are reported for context but don't block, because failing
every pull request for a problem someone else introduced is how a bot gets
ignored — and an ignored bot protects nothing. Once your backlog is clear,
`fail-on: critical` stops new ones creeping in.

The comment also carries a coverage score (share of traffic governed by a
rule, routes with rules, sensitive-looking fields handled), any leaks found,
and — with `spec:` set — changes that would break clients seen in traffic.
404s are excluded from coverage, since you can't write a rule for a route
that doesn't exist.

No staging environment? Point it at a JSONL export instead:

```bash
optictrace review -config optic.yaml -base-config /tmp/base.yaml \
  -from-file examples/traffic-sample.jsonl
```

See [`examples/workflows/governance-review.yml`](examples/workflows/governance-review.yml)
for a complete workflow. This repo dogfoods it in
[`.github/workflows/governance.yml`](.github/workflows/governance.yml).

## Traffic-powered tooling

All of these read the same governed traffic history in the payload store.

### Catch what your rules missed

Redaction only masks what you **name**. The failure that actually bites is the
field nobody wrote a rule for — a new endpoint ships and secrets land in the
store. `scan` inverts the model: it reads records that already passed
governance and flags values that *look* sensitive anyway.

```bash
optictrace scan -window 24h
```

```
✗ [critical] github-token in POST /api/v1/orders → request_body.$.debug_token
    a GitHub personal access / app token · seen 4× (last 8s ago) · sample gh•••••••••••••89
    fix: redact:
           json_fields: ["$.debug_token"]

⚠ [high] credit-card in POST /api/v1/orders → response_body.$.echo.payment.pan
    a Luhn-valid card number — PCI-DSS scope · seen 4× (last 8s ago) · sample 55••••••••••59
    fix: redact:
           json_fields: ["$.echo.payment.pan"]

scanned 8 record(s): 2 critical, 2 high, 3 medium
```

Detectors are structural — issuer prefixes, Luhn and mod-97 checksums, PEM
framing — not "looks random", so order IDs and timestamps don't trip them.
**Findings never print the value they found**: a scanner that echoes a
credential has just leaked it again, into your CI logs. Every sample is
masked, and the suggested rule is copy-pasteable into `optic.yaml`.

Exits non-zero at or above `-fail-on` (default `high`), so it gates CI.
Also available at `GET /api/scan`.

### Test your governance rules

Rules are security-critical but, without tests, verifiable only by eyeball or
by pushing live traffic. `optictrace test` runs assertions against the real
engine — no server, no network:

```yaml
# optic.test.yaml
- name: auth routes record metadata only
  request:
    method: POST
    path: /api/v1/auth/login
    body: { username: ada, password: hunter2 }
    response: { token: session-token }
  expect:
    matched_rules: [no-capture-on-auth]
    captures_request_body: false
    not_contains: ["hunter2", "session-token"]   # the assertion that matters

- name: tail sampling rescues server errors
  request: { method: POST, path: /api/v1/ai/complete, status: 500 }
  expect: { keeps_body: true }
```

```bash
optictrace test -config optic.yaml -tests optic.test.yaml
# ✓ 6/6 rule test(s) passed against optic.yaml
```

Every `expect` field is optional, so a case asserts only what it's about and
won't break on unrelated config changes. See [`optic.test.yaml`](optic.test.yaml)
for the full shipped example.

### Infer a spec, lint a proposal, generate an SDK

```bash
# Learn an OpenAPI 3 doc from the last 24h of real traffic
optictrace spec -window 24h -out openapi.yaml

# CI gate: does the proposed spec still cover live usage?
optictrace check -spec proposed.yaml -window 24h
#   ✗ [breaking] POST /api/v1/payments/charge: clients send request field
#     "credit_card" (28 time(s), last 22m ago) but the spec omits it
# exit code 1 → the pipeline fails before a real client does

# Typed TypeScript client, from a spec file or straight from traffic
optictrace sdk -lang typescript -out client.ts
```

Redaction never hides *structure* — masked fields still contribute their name and type to
inference, so governance and documentation don't fight.

### Stateful mock server

```bash
optictrace mock -spec openapi.yaml -listen :7070
```

Collection/item routes (`/cart` + `/cart/{id}`) get real CRUD state: what you POST is what
later GETs return, PATCH merges, DELETE 404s afterwards. Other operations return
schema-conforming data with realistic values (emails look like emails, prices like prices).
Add `-ai` with `ANTHROPIC_API_KEY` set and non-CRUD responses are generated by Claude with
full request context — any failure falls back to the deterministic generator, so the mock
never needs the network.

### Suggest rules, replay traffic

```bash
# Propose governance for sensitive-looking FIELD NAMES.
# `scan` reads values; `suggest` reads names — run both.
optictrace suggest -window 24h
#   ✗ [high] json_field "$.payment.card_number" on /api/v1/orders
#       payment card data is PCI-DSS scope (seen 3×)
#   10 suggestion(s); 2 sensitive-looking field(s) already covered by your rules
optictrace suggest -apply proposed-rules.yaml   # review, then merge

# Re-issue captured traffic against staging and diff status codes.
optictrace replay -target https://staging.internal -rate 50
#   replayed 6/7 record(s) in 2ms
#   skipped 1:
#     1 × request body was not captured (restricted or sampled out)
#   status match: 6 · diverged: 0 · failed: 0
```

Replay is honest about its limits: OpticTrace stores **governed** records, so
a redacted field replays as `[REDACTED]` and a restricted body was never
stored at all. Those requests are skipped with the reason stated rather than
sent as something they weren't. That makes replay a tool for exercising
routing and regression shape, not for reproducing a payment.

### Usage & cost attribution (FinOps)

`GET /api/usage` and the **Usage** dashboard page show per-tenant requests, data, compute
time, metered units and estimated cost; `&format=csv` produces a billing export. Metering is
independent of capture: a fully restricted route still meters, reading the payload for the
number without ever storing it.

---

## Storage at scale

SQLite is right for a sidecar with a single writer. When several agents — or
several replicas of one agent — need shared history, point them at Postgres:

```yaml
telemetry:
  store:
    driver: postgres
    dsn: "postgres://optic:secret@db:5432/optictrace?sslmode=require"
```

Both drivers implement the same `LogStore` interface and are held to it by a
shared conformance suite, so behaviour cannot quietly diverge. Postgres pushes
percentiles (`percentile_cont`), usage grouping and label matching into the
database via JSONB, where SQLite scans and aggregates in Go.

Run the Postgres half of the suite locally with:

```bash
docker run -d -e POSTGRES_PASSWORD=optic -e POSTGRES_DB=optictrace -p 5432:5432 postgres:16-alpine
OPTICTRACE_TEST_POSTGRES='postgres://postgres:optic@localhost:5432/optictrace?sslmode=disable' \
  go test ./internal/store
```

## Export plugins

Every governed record — post-restriction, post-redaction, so no export path can ever see raw
sensitive data — also fans out to the output plugins declared in `optic.yaml`.

A **command plugin** receives one JSON record per stdin line. That's the whole contract —
ship to Kafka, S3, BigQuery, a SIEM, anywhere:

```python
#!/usr/bin/env python3
import sys, json
for line in sys.stdin:
    record = json.loads(line)     # already restricted/redacted
    ship_somewhere(record)
```

See [`examples/exporters/`](examples/exporters/) for a working CSV plugin.

---

## Writing an extension

Almost all of OpticTrace lives under `internal/`, which Go forbids other modules
from importing — that keeps the implementation free to change. The one exception
is [`ext/`](ext), the extension surface: the record types and the two plugin
interfaces, and nothing else. It follows semantic versioning; nothing under
`internal/` does.

A driver becomes configurable purely by being linked into the binary:

```go
package main

import (
    "github.com/dwarka-prasad/optictrace"
    "github.com/dwarka-prasad/optictrace/ext"
)

func init() {
    ext.RegisterStore("s3", func(dsn string, s ext.Settings) (ext.Store, error) {
        return newS3Store(dsn, s.String("bucket", ""), s.Int("shards", 4))
    })
}
```

```yaml
telemetry:
  store:
    driver: s3                    # accepted because it's registered
    dsn: "s3://archive"
    settings:                     # your keys; the core doesn't validate these
      bucket: optic-archive
      shards: 8
```

`ext.RegisterExporter` works the same way for output plugins
(`telemetry.exporters[].type`).

### Verify it against the same suite the built-in drivers run

`ext/exttest` exports the conformance suite. Two drivers means two chances to
drift apart; the suite is what stops them answering the same question
differently — including the regression test for the erasure bug where purging
a tenant named `acme_1` also destroyed `acmeX1`.

```go
func TestConformance(t *testing.T) {
    exttest.RunStoreSuite(t, func(t *testing.T) ext.Store {
        s, err := NewMyStore(dsn)
        if err != nil { t.Fatal(err) }
        t.Cleanup(func() { s.Close() })
        return s   // must be empty
    })
}
```

[`examples/memstore`](examples/memstore) is a complete worked example: an
in-memory store in **its own module**, deliberately outside the
`github.com/dwarka-prasad/optictrace/...` path prefix so it genuinely cannot
reach `internal/`. It passes the full suite using only `ext`. CI builds it on
every PR, so a hole in the extension surface fails the build.

### Authentication, authorization and audit

The admin surface has three more hooks: `ext.RegisterAuthenticator`,
`ext.RegisterAuthorizer` and `ext.RegisterAuditor`, plus
`ext.RegisterAdminRoutes` for a login callback.

Policy is written against **capabilities**, never URLs. Every route declares
what it exposes, and the core owns that mapping — because only the core knows
which handlers return captured payloads:

| Capability | Routes | What it grants |
|---|---|---|
| `public` | `/healthz`, login callbacks | reachable without credentials |
| `metrics` | `/metrics` | Prometheus exposition |
| `read:stats` | `/api/stats`, `/api/routes`, `/api/services`, `/api/usage`, … | aggregates only, no payloads |
| `read:payload` | `/api/logs`, `/api/logs/{id}` | **captured request/response bodies** |
| `export` | `/api/export` | **bulk egress of the whole store** |
| `analyse` | `/api/scan`, `/api/spec` | reads payloads, returns derived output |
| `read:config` | `/api/config` | the governance policy |
| `ingest` | `/api/ingest` | SDK writes |
| `admin` | `/api/reload` | changes agent state |
| `ui` | `/` | dashboard assets |

`read:payload` and `export` are separate on purpose: "can inspect one request
while debugging" and "can download everything" are different grants, and
conflating them is how access reviews go badly.

Three properties the core guarantees, each with a test:

- **Fail closed.** A panicking authenticator yields 401; a panicking authorizer
  yields 403. An extension bug cannot open the API.
- **Composition narrows.** Every registered authorizer must allow, so adding
  one can never widen access.
- **Denials don't leak.** The reason goes to the audit trail and the log, never
  to the caller.

An audit event carries what was *reached*, not just which URL was called —
record count, ids, the filter used, the tenant — because "alice listed logs"
answers no question an auditor would ask.

[`examples/adminauth`](examples/adminauth) is a complete worked example: SSO
with a redirect-and-callback flow, RBAC over the capabilities above, and a
JSONL audit log — again in its own module, again unable to reach `internal/`.

### What extensions inherit

Records handed to a `Store` or an `Exporter` are already governed — restricted
fields absent, redacted fields holding the placeholder. Governance sits upstream
of every sink, so no extension can see raw sensitive data and none has to be
trusted with it. Two obligations follow: don't reconstruct what governance
removed, and make `Purge` actually delete before it returns — it backs erasure
requests.

---

## Multi-tenant tagging

One API, many tenants, the same path for all of them. Tags turn that into
something you can segregate, meter and bill.

```yaml
rules:
  # Baseline: every API call gets a tenant, a region and a default tier.
  - name: tag-baseline
    match: { path: "/api/**" }
    labels:
      tenant: "header:X-Tenant-ID"
      region: "header:X-Region|^([a-z]{2})-"   # eu-west-1 -> eu
      tier:   "static:standard"

  # Criteria: gold and platinum plans are tagged premium instead.
  - name: tag-premium
    match:
      path: "/api/**"
      headers:
        X-Plan: "^(gold|platinum)$"            # regex
    labels:
      tier: "static:premium"

  # Tenant carried in the URL rather than a header.
  - name: tag-tenant-from-path
    match: { path: "/api/v1/tenants/*/**" }
    labels:
      tenant: "path:4"                         # 1-indexed segment
```

Same endpoint, segregated:

```
/api/orders                     tenant=acme     tier=premium   region=eu
/api/orders                     tenant=globex   tier=standard  region=us
/api/orders?mode=sandbox        tenant=acme     tier=standard  env=sandbox
/api/v1/tenants/umbrella/orders tenant=umbrella tier=standard  region=eu
```

### Label sources

| Source | Example | Value |
|---|---|---|
| `header:<Name>` | `header:X-Tenant-ID` | the request header |
| `query:<name>` | `query:tenant` | a query parameter |
| `path:<n>` | `path:4` | the 4th path segment, 1-indexed |
| `static:<value>` | `static:premium` | a constant — this is how you **tag** |

Any source takes an optional `|<regex>` suffix with exactly one capture group,
and that group becomes the label. A non-match yields an empty label rather than
the raw value, so a mistyped pattern produces a missing tag rather than a
misleading one.

### Criteria

`match.headers` and `match.query` take regular expressions. All listed
conditions must hold, so adding one narrows the rule. Patterns are unanchored
like Go's `regexp` — write `^` and `$` for a whole-value match, and `"."` for
"present and non-empty".

**There is no separate `tags:` block, deliberately.** Rules already merge top to
bottom with later rules winning, so a broad default plus a narrow override is
all conditional tagging needs — and it reuses machinery that already governs
redaction, sampling and metering rather than adding a second thing to learn.

### What tags do for you

- **Prometheus dimensions** — `optictrace_requests_total{tenant="acme",tier="premium"}`
- **Cost attribution** — `/api/usage?label=tier` groups by any tag, not just tenant
- **Erasure requests** — `optictrace purge -label tenant -value acme`
- **Rules** can then target a tagged class for redaction or sampling

Values are client-controlled, so they pass through the cardinality guard
(`telemetry.metrics.max_label_values`) before becoming Prometheus labels.

---

## Framework SDKs

SDKs evaluate the same `optic.yaml` in-process and POST governed records to the agent's
`/api/ingest` — one dashboard and one metrics endpoint across your whole stack.

### Node.js / Express

```js
const optictrace = require('@optictrace/express');
app.use(optictrace({ configPath: 'optic.yaml', agentUrl: 'http://localhost:9095' }));
```

### Python / FastAPI

```python
from optictrace_fastapi import OpticTraceMiddleware
app.add_middleware(OpticTraceMiddleware,
                   config_path="optic.yaml", agent_url="http://localhost:9095")
```

### Go / net-http + Gin

```go
agent, _ := optictrace.New("optic.yaml")
defer agent.Close()
agent.ServeAdmin("ui/out")                            // metrics + dashboard on :9095

http.ListenAndServe(":8080", agent.Middleware(mux))   // net/http
r.Use(optictracegin.Middleware(agent))                // Gin
```

---

## Developer dashboard

`ui/` is a Next.js (App Router) + Tailwind + Recharts app, statically exported and served by
the agent itself — no separate frontend deployment.

<img src="docs/assets/dashboard-inspector.png" alt="Request Inspector showing a captured payment with card number, CVV, email and Authorization header all masked, the matched rule named, and non-sensitive fields left intact" width="100%">

<sub>The Inspector, mid-investigation: redacted values are highlighted, the rule responsible is named, and everything non-sensitive is still there to debug with.</sub>

| Page | Shows |
|---|---|
| **Overview** | Live request volume, error rate, latency charts; top routes with per-route P95 |
| **Routes** | Every route with sortable P50/P95/P99, error rates, traffic volume |
| **Inspector** | Searchable/filterable exchanges; redacted fields highlighted; CSV/JSONL export |
| **Usage** | Per-consumer requests, data, compute, meters and estimated cost |
| **Governance** | Each rule's actions (restrict/redact/labels/sample/meter) with live match counts |
| **Config** | View `optic.yaml`, lint edits live against the running agent, trigger hot reload |
| **System** | Agent health, store size, per-exporter delivery/failure/drop counters |

<details>
<summary>More screenshots</summary>

**Overview** — golden signals and top routes
<img src="docs/assets/dashboard-overview.png" width="100%">

**Routes** — every route with sortable P50/P95/P99
<img src="docs/assets/dashboard-routes.png" width="100%">

**Usage** — per-tenant consumption, meters and estimated cost
<img src="docs/assets/dashboard-usage.png" width="100%">

**Governance** — each rule's actions with live match counts
<img src="docs/assets/dashboard-governance.png" width="100%">

</details>

Develop it with `cd ui && npm run dev`. The dev server runs on a different port, so
add its origin to `telemetry.cors_origins` (e.g. `["http://localhost:3001"]`) — the
agent sends no CORS headers unless an origin is explicitly allowed.

---

## Deployment

- **Docker** — multi-stage [`Dockerfile`](Dockerfile) (UI build → pure-Go build → non-root Alpine image).
- **Compose** — [`docker-compose.yml`](docker-compose.yml) runs OpticTrace + demo upstream + Prometheus + Grafana, with the dashboard and alert rules provisioned:

<img src="docs/assets/grafana.png" alt="The provisioned Grafana dashboard showing request rate, error rate, latency percentiles and agent health" width="100%">

- **Helm** — [`deploy/helm/optictrace`](deploy/helm/optictrace) with ConfigMap-managed `optic.yaml`, health probes, optional PVC and ServiceMonitor.

---

## Measured overhead

The claim "built for the hot path" deserves numbers rather than adjectives.
`go test ./internal/proxy -bench=. -benchmem -run='^$'` compares a bare
handler against the same handler wrapped by the interceptor:

| Policy | ns/op | Added vs. baseline | allocs/op |
|---|---:|---:|---:|
| Baseline (no OpticTrace) | 2,050 | — | 25 |
| Restricted route (capture off) | 2,267 | **+0.22 µs** | 29 |
| Full capture + redaction | 7,434 | **+5.4 µs** | 211 |
| …plus Prometheus with a custom label | 7,567 | +5.5 µs | 215 |
| Rule evaluation alone (no HTTP) | 812 | — | 7 |

<sub>12th Gen Intel i5-1235U, Go 1.25, `-benchtime=2s`, parallel. Reproduce with `make bench`.</sub>

Read the **absolute** deltas, not the ratios: the baseline includes
`httptest` request construction, which inflates it and flatters the
percentages. What the numbers say:

- **Restricting a route really is near-free** (+0.22 µs). The policy resolves before any buffer is attached, so a route you've told OpticTrace to leave alone costs almost nothing — this is the design claim, and it holds.
- **Full capture with depth-recursive redaction costs about 5.4 µs per request.** Against a typical API call of 1–100 ms that's 0.005–0.5% of the request, but it is not free, and it's dominated by JSON parse + re-serialize. Use `sample` with `keep_errors` on very hot routes.
- **Prometheus observation is noise** (+0.13 µs) even with a custom label dimension.

## Verified behavior

These aren't design intentions — each was observed end to end with real traffic through the
proxy, not asserted from the code:

- **Redaction holds under echo.** A payment request carrying a card number came back echoed inside a wrapper by the upstream; both the request and the nested response copy stored `[REDACTED]`, while the client received the real number.
- **Restriction is total.** A login request's password and the response token appear nowhere in logs, store, or exports — only method, path, status and latency were recorded.
- **Metering survives restriction.** An AI route with both bodies restricted still recorded `tokens: 63` attributed to a tenant, with the completion text absent everywhere.
- **Labels reach Prometheus.** Series carried `tenant="acme"` and `region="ap-south-1"` as real dimensions, with routes normalized to `/api/v1/users/:id`.
- **The linter catches real breakage.** A proposed spec dropping a field was rejected with *"clients send request field `credit_card` (28 times, last 22m ago)"* and a non-zero exit.
- **Plugins receive governed data only.** A Python CSV plugin and a file exporter both ran live; neither output contained a card number or a restricted payload.
- **A clean clone works.** Cloned fresh from GitHub: builds, six test packages pass, CLI runs.

---

## Roadmap

Ordered by value, not by ease. Each item states the problem it solves — if the rationale
doesn't hold for your use case, the item shouldn't be built.

### Tier 1 — ✅ shipped in v0.5.0

These closed the sharpest risks in the design and are all live now:

- **Leak detector** (`optictrace scan`) — governance is no longer only a deny-list you maintain; it has a safety net that catches the field you forgot and prints the rule that fixes it.
- **Label cardinality guard** — custom label values come from arbitrary request headers, so one buggy client could previously have created unbounded series. Now capped, with overflow visible as a metric.
- **Tail-based sampling** — uniform sampling discarded exactly the requests worth keeping. `keep_errors` and `keep_slower_than` rescue them after the outcome is known.
- **Rule unit tests** (`optictrace test`) — governance rules are safe to refactor now that CI can prove they still redact.

### Tier 2 — ✅ shipped in v0.6.0

- **Query-string capture** — with `redact.query_params` shipped alongside it, because capturing `?api_key=…` without a way to mask it would have been a governance regression. Query params now appear in inferred specs and are scanned for leaks.
- **Time-based retention + per-consumer purge** — `retention_max_age` expresses a policy the way policies are written ("keep 30 days"), and `optictrace purge -value acme` answers erasure requests.
- **Admin authentication + TLS** — bearer token (constant-time compare, `token_env` so secrets stay out of git) and optional HTTPS. Health probes stay open so orchestrators keep working.
- **Published benchmarks** — see [Measured overhead](#measured-overhead). The "restricted routes are near-free" claim is now a number: +0.22 µs.
- **Python and Go SDK generators** — `optictrace sdk -lang python|go`, both dependency-free.

### Tier 3 — ✅ shipped in v0.7.0

- **Postgres driver** — a second `LogStore` for multi-node deployments, with percentile and usage aggregation pushed into the database. Both drivers run the *same* conformance suite, so they can't drift apart.
- **OTLP export** — governed records become OpenTelemetry spans, shipped as a fourth exporter type so it reuses the existing batching and isolation. Bodies are deliberately never attached to spans.
- **Traffic replay** — `optictrace replay` re-issues captured traffic and diffs status codes, reporting what governance made unreplayable rather than faking it.
- **Rule suggestions** — `optictrace suggest` reads field *names* where `scan` reads *values*; together they cover both halves.
- **Fleet view** — `/api/services` aggregates across services when many SDKs report into one agent.
- **Grafana + alerts** — a provisioned dashboard and 7 alert rules (validated with `promtool`), wired into `docker compose`.
- **Release engineering** — goreleaser config (validated with `goreleaser check`) for signed, SBOM'd, multi-arch binaries, a Homebrew cask, and multi-platform images.

### Known gaps

Documented so nobody discovers them the hard way:

- Rule match counts use a `LIKE` scan over stored JSON — fine at the default 100k-row retention, worth an indexed join table beyond that.
- The AI mock path is implemented but has never run against the live Anthropic API.
- Hijacked connections (WebSockets) pass through; once upgraded, the bytes are
  between client and upstream, so the record covers the exchange up to the `101`.
  Their duration is a connection lifetime, so they are marked as streams and kept
  out of latency percentiles.
- Streaming responses (SSE, chunked) reach the client as they are produced, but
  telemetry is emitted when the stream closes — a long-lived stream is invisible
  until then, apart from `optictrace_streams_open`.
- Admin authentication is available but **off by default**; enable `telemetry.auth` if the port is reachable.

---

## Contributing

Bug reports, rule-engine edge cases, and new SDK targets are all welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Ground rules worth repeating:

1. **Governance invariants are non-negotiable.** Proxied traffic is never mutated; telemetry never blocks a request. Any PR that could leak a restricted or redacted value needs a test proving it doesn't.
2. **The rule engine is portable.** `internal/engine` (Go), `sdks/express/engine.js` and `sdks/fastapi/.../engine.py` must stay semantically identical.

```bash
go build ./... && go test ./...        # Go agent
cd ui && npm install && npm run dev    # dashboard
./scripts/demo.sh                      # full local stack
```

## Project layout

```
cmd/optictrace/     agent binary (run · validate · test · scan · suggest · purge ·
                    replay · spec · check · sdk · mock · version)
internal/config/    optic.yaml schema + strict validation
internal/engine/    compiled rule engine: globs, policy merge, redaction, meters
internal/proxy/     interception (reverse proxy + embeddable middleware)
internal/metrics/   Prometheus collector with dynamic label schemas
internal/store/     LogStore interface, SQLite driver, async writer, usage aggregation
internal/export/    output plugins: file · webhook · command (custom executables)
internal/scan/      leak detector: structural detectors, masked findings, fix suggestions
internal/suggest/   name-based rule proposals (complements scan's value checks)
internal/review/    pull-request review: policy diff, coverage score, Markdown report
internal/replay/    re-issue captured traffic against a target
internal/ruletest/  optic.test.yaml runner (pure engine, no server)
internal/spec/      traffic→OpenAPI inference, spec-vs-traffic linter, TS SDK gen
internal/mock/      stateful mock server (+ optional Claude-generated responses)
internal/admin/     admin API + dashboard hosting
ui/                 Next.js dashboard (static export)
sdks/               express · fastapi · gin
deploy/             compose bits, Helm chart, Grafana dashboard, Prometheus alerts
examples/           exporter plugins, CI workflows, a traffic fixture
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

[Apache 2.0](LICENSE)
