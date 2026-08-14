<div align="center">

# 👁️ OpticTrace

**Declarative API telemetry & governance — like OpenAPI, but for observability.**

One `optic.yaml` controls what your API traffic reveals: which routes are monitored,
which payloads are captured, what gets redacted, and which request attributes become
Prometheus dimensions.

[Quickstart](#quickstart) · [How it works](#how-it-works) · [`optic.yaml` reference](#opticyaml-reference) ·
[Dashboard](#developer-dashboard) · [SDKs](#framework-sdks) · [Deploy](#deployment) · [Contributing](CONTRIBUTING.md)

</div>

---

## Why OpticTrace?

API observability usually means choosing between two bad options: log everything
(and leak credit cards into your log pipeline) or log nothing useful. OpticTrace
makes the trade-off **declarative and reviewable**:

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
- 🛡️ **Traffic is never mutated** — governance applies to what gets *recorded*, clients and upstreams always see original bytes.
- 📊 **Prometheus-native** — request counts, error rates, P50/P95/P99 latency histograms per route, plus your own label dimensions extracted from headers or query params.
- 🖥️ **Built-in developer dashboard** — live charts, a searchable request inspector (redactions visible), and a config linter, served by the same single binary.
- ⚡ **Built for the hot path** — rules compile once at startup; restricted routes skip capture entirely; body capture is size-bounded; storage is async and drops rather than blocks.

And because OpticTrace owns your real traffic history, it can do things static tools can't:

- 🧬 **Traffic → OpenAPI → SDK** — `optictrace spec` infers a spec from what clients *actually* send (stale-docs killer); `optictrace sdk` emits a typed TypeScript client from it.
- 🚨 **Breaking-change linter** — `optictrace check -spec proposed.yaml` answers *"is any live client actually using the field I'm about to remove?"* with usage counts and last-seen times. CI-native (exit 1 on breaking).
- 🎭 **Stateful mock server** — `optictrace mock -spec openapi.yaml` spins up a mock where `POST /cart` then `GET /cart` really returns the added item; optional AI-generated responses via Claude.
- 💰 **FinOps metering** — extract usage figures (e.g. LLM token counts) from responses per rule, attribute cost per tenant, export billing CSVs.

## How it works

```
                        ┌────────────────────────────────────────────┐
             :8080      │  OpticTrace agent                          │
  client ─────────────▶ │  1. evaluate optic.yaml rules (per req)    │ ──▶ upstream
                        │  2. tee bounded copies of traffic          │ ◀── response
  client ◀───────────── │  3. restrict / redact captured telemetry   │
                        │  4. fan out: console · Prometheus · SQLite │
                        └───────────────┬────────────────────────────┘
                                :9095   │ admin listener (firewall separately)
                 ┌──────────────┬───────┴──────┬─────────────────┐
                 ▼              ▼              ▼                 ▼
             /metrics      dashboard      /api/logs        /api/ingest
            (Prometheus)   (Next.js)     (inspector)     (framework SDKs)
```

Two deployment modes share one code path:

- **Sidecar / gateway** — `optictrace run` reverse-proxies to your service.
- **Embedded** — native middleware inside your app: [Go](#go--nethttp--gin), [Express](#nodejs--express), [FastAPI](#python--fastapi). SDKs apply governance **in-process** (sensitive data never leaves your app raw) and ship governed records to the agent.

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

### From source

```bash
go build -o bin/ ./cmd/...
(cd ui && npm install && npm run build)   # optional: the embedded dashboard
./bin/optictrace validate -config optic.yaml
./bin/optictrace run -config optic.yaml
```

Send traffic through `service.listen`, then open `http://localhost:9095`.

## `optic.yaml` reference

```yaml
version: 1

service:
  name: payments-api
  listen: ":8080"                    # sidecar listen address
  upstream: "http://localhost:9000"  # where traffic is forwarded

telemetry:
  admin_listen: ":9095"              # metrics + dashboard + APIs
  console_log: true                  # structured JSON on stdout
  metrics:
    enabled: true
    buckets: [0.005, 0.05, 0.5, 5]   # optional latency histogram bounds (s)
  store:
    driver: sqlite                   # sqlite | none
    dsn: optictrace.db
    queue_size: 4096                 # async queue; overflow drops, never blocks
    retention_max_rows: 100000       # oldest rows pruned

defaults:
  capture: { request_body: true, response_body: true, headers: true }
  capture_limit_bytes: 65536         # per-body telemetry cap (traffic unaffected)

rules:
  - name: no-capture-on-auth
    match:
      path: "/api/v1/auth/**"        # * = one segment, ** = zero or more
      methods: [POST]                # optional; omitted = all methods
    restrict: [request_body, response_body, headers]

  - name: redact-payment-secrets
    match: { path: "/api/v1/payments/**" }
    redact:
      headers: [Authorization, X-Api-Key]
      json_fields:
        - "$.credit_card.number"     # exact dotted path
        - "$.*.ssn"                  # * = any single key
        - "$.**.card_token"          # ** = any nesting depth
    labels:
      tenant: "header:X-Tenant-ID"   # Prometheus dimension + log field
      plan:   "query:plan"
    sample: 0.25                     # capture bodies for 25% of matches
                                     # (metrics & metadata stay complete)
```

**Rule semantics:** rules evaluate top-to-bottom and *merge* — restrictions only
ever narrow capture; redactions and labels accumulate; later rules win on
conflicting scalars. Arrays traverse implicitly (`$.items.price` covers every
element of `items`).

**Hot reload:** `kill -HUP <pid>` or `POST /api/reload` — the rule engine swaps
atomically; in-flight requests finish under their old policy. An invalid config
is rejected and the old rules stay live.

## Prometheus metrics

| Metric | Type | Labels |
|---|---|---|
| `optictrace_requests_total` | counter | `method route status status_class` + your labels |
| `optictrace_request_duration_seconds` | histogram | `method route` + your labels |
| `optictrace_request_size_bytes` / `_response_size_bytes` | histogram | `method route` |
| `optictrace_inflight_requests` | gauge | |
| `optictrace_store_dropped_total` | counter | backpressure drops |
| `optictrace_sdk_ingested_total` | counter | records from SDKs |

P99 per route:

```promql
histogram_quantile(0.99,
  sum by (le, route) (rate(optictrace_request_duration_seconds_bucket[5m])))
```

The `route` label is always the matched rule's glob or a normalized pattern
(`/users/42` → `/users/:id`) — cardinality stays bounded by design.

## Developer dashboard

`ui/` is a Next.js (App Router) + Tailwind + Recharts app, statically exported
and served by the agent itself — no separate frontend deployment.

- **Overview** — live request volume, error rate, and latency charts; top routes with per-route P95.
- **Routes** — every route with sortable P50/P95/P99, error rates, and traffic volume.
- **Inspector** — search and filter captured exchanges; redacted fields are highlighted, restricted routes show a governance notice; **Export** downloads the current filter set as CSV or JSONL.
- **Usage** — per-consumer requests, data, compute, custom meters (e.g. tokens), and estimated cost with billing CSV export.
- **Governance** — each rule's actions (restrict/redact/labels/sample/meter) with live match counts, and what share of traffic is governed.
- **Config** — view `optic.yaml`, lint edits live against the running agent, trigger hot reload.
- **System** — agent health, store size, and per-exporter delivery/failure/drop counters.

Develop it with `cd ui && npm run dev` (talks to the agent on `:9095` via CORS).

## Traffic-powered tooling

All of these read the same governed traffic history in the payload store.

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

Also available over HTTP: `GET /api/spec?window=24h` on the admin port.
Redaction never hides *structure* — masked fields still contribute their name
and type to inference, so governance and documentation don't fight.

### Stateful mock server

```bash
optictrace mock -spec openapi.yaml -listen :7070
```

Collection/item routes (`/cart` + `/cart/{id}`) get real CRUD state: what you
POST is what later GETs return, PATCH merges, DELETE 404s afterwards. Other
operations return schema-conforming data with realistic values (emails look
like emails, prices like prices). Add `-ai` with `ANTHROPIC_API_KEY` set and
non-CRUD responses are generated by Claude with full request context — any
failure falls back to the deterministic generator, so the mock never needs
the network.

### Usage & cost attribution (FinOps)

```yaml
rules:
  - name: meter-ai-tokens
    match: { path: "/api/v1/ai/**" }
    restrict: [request_body, response_body]  # prompts stay private...
    meter:
      tokens: "$.usage.total_tokens"         # ...but tokens are still counted
    labels:
      tenant: "header:X-Tenant-ID"

telemetry:
  billing:
    consumer_label: tenant
    currency: USD
    prices:
      per_request: 0.0001
      per_gb: 0.05
      per_meter_unit: { tokens: 0.000002 }   # $2 per 1M tokens
```

`GET /api/usage` (and the **Usage** dashboard page) then shows per-tenant
requests, data, compute time, metered units, and estimated cost —
`&format=csv` produces a billing export. Metering is independent of capture:
a fully restricted route still meters, reading the payload for the number
without ever storing it.

## Export plugins

Every governed record — post-restriction, post-redaction, so no export path
can ever see raw sensitive data — also fans out to the output plugins declared
in `optic.yaml`:

```yaml
telemetry:
  exporters:
    - name: audit-log            # append JSONL, size-rotated
      type: file
      path: ./export/audit.jsonl

    - name: siem                 # POST JSON batches to any HTTP endpoint
      type: webhook
      url: https://siem.internal/ingest
      headers: { Authorization: "Bearer ..." }
      batch_size: 100
      flush_interval: 5s

    - name: my-plugin            # CUSTOM PLUGIN: any executable, any language
      type: command
      command: ["python3", "examples/exporters/csv_exporter.py", "traffic.csv"]
```

A **command plugin** receives one JSON record per stdin line — that's the
whole contract. Ship to Kafka, S3, BigQuery, a SIEM, anywhere:

```python
#!/usr/bin/env python3
import sys, json
for line in sys.stdin:
    record = json.loads(line)     # already restricted/redacted
    ship_somewhere(record)
```

Exporters are isolated: each gets its own bounded queue and worker, delivery
is batched and at-most-once, and a slow or crashed plugin drops only its own
records (visible in `optictrace_export_*` metrics and the System page) — the
request path is never affected. One-off exports are also available as
downloads: `GET /api/export?format=csv|jsonl` with the same filters as
`/api/logs`, or the Export button in the Inspector.

## Framework SDKs

SDKs evaluate the same `optic.yaml` in-process and POST governed records to the
agent's `/api/ingest` — one dashboard and one metrics endpoint across your stack.

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
agent.ServeAdmin("ui/out")                    // metrics + dashboard on :9095

http.ListenAndServe(":8080", agent.Middleware(mux))   // net/http
r.Use(optictracegin.Middleware(agent))                // Gin
```

## Deployment

- **Docker** — multi-stage [`Dockerfile`](Dockerfile) (UI build → pure-Go build → ~30 MB Alpine image, non-root).
- **Compose** — [`docker-compose.yml`](docker-compose.yml) runs OpticTrace + demo upstream + Prometheus.
- **Helm** — [`deploy/helm/optictrace`](deploy/helm/optictrace) with ConfigMap-managed `optic.yaml`, health probes, optional PVC and ServiceMonitor.

## Project layout

```
cmd/optictrace/     agent binary (run · validate · spec · check · sdk · mock · version)
internal/config/    optic.yaml schema + strict validation
internal/engine/    compiled rule engine: globs, policy merge, redaction, meters
internal/proxy/     interception (reverse proxy + embeddable middleware)
internal/metrics/   Prometheus collector with dynamic label schemas
internal/store/     LogStore interface, SQLite driver, async writer, usage aggregation
internal/export/    output plugins: file · webhook · command (custom executables)
internal/spec/      traffic→OpenAPI inference, spec-vs-traffic linter, TS SDK gen
internal/mock/      stateful mock server (+ optional Claude-generated responses)
internal/admin/     admin API + dashboard hosting
ui/                 Next.js dashboard (static export)
sdks/               express · fastapi · gin
deploy/             compose bits + Helm chart
examples/           exporter plugin examples
```

## Contributing

Bug reports, rule-engine edge cases, and new SDK targets are all welcome —
see [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are labeled
[`good-first-issue`](https://github.com/dwarka-prasad/optictrace/labels/good-first-issue).

## License

[Apache 2.0](LICENSE)
