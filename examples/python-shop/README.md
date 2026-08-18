# Python shop — the OpticTrace SDK end to end

Three FastAPI services making **real** HTTP calls to each other, governed
in-process by the OpticTrace SDK, reporting into one agent running in
**collector mode** (no proxy — nothing is in the request path).

```
  POST /api/v1/orders                          storefront :8101
        │                                          │
        ├── GET  /api/v1/catalog/{sku}   ────────► catalog    :8102
        └── POST /api/v1/payments/charge ────────► payments   :8103
                                                   │
                          all three ───────────────┴──► agent :9095
```

## Run it

```bash
./run.sh                     # venv, agent, three services, then drive traffic
.venv/bin/python verify.py   # 25 assertions against the live stack

# optional: Prometheus + Grafana against the same agent
docker compose -f docker-compose.observability.yml up -d
#   http://localhost:9090   Prometheus
#   http://localhost:3000   Grafana (anonymous, or admin/optictrace)
```

- `http://127.0.0.1:9095` — OpticTrace dashboard
- `http://127.0.0.1:8101` — the public API

## What it demonstrates

**Governance runs inside the service.** The SDK evaluates `optic.yaml` in
process, so the card number is masked in the service that saw it and never
crosses a process boundary in the clear. The agent stores what it is given.

**Correlation is a fact, not a guess.** The middleware adopts (or starts) a
W3C trace and puts the span in a `ContextVar`. `outbound_headers()` carries
*this* hop's span to the next one, so downstream calls become children rather
than siblings. One order looks like this:

```
storefront  POST /api/v1/orders            200  span=83c03ddd parent=-
  catalog   GET  /api/v1/catalog/SKU-100   200  span=3a2c0d92 parent=83c03ddd
  payments  POST /api/v1/payments/charge   200  span=e0f134d5 parent=83c03ddd
```

**Your logs land under the request that wrote them.** `OpticTraceLogHandler`
reads the same ContextVar, so ordinary `log.info(...)` calls are filed against
the span — nothing at the call site knows about OpticTrace:

```
payments  POST /api/v1/payments/charge  200
    [debug] charging card [REDACTED] for 129.00
    [info ] charge requested  amount=129.0 order_ref=ord-SKU-100
    [info ] charge captured   amount=129.0
```

`payments.py` logs the card number **on purpose** — that is how the leak
actually happens — and it is stored redacted, because log lines run through
the same policy as payloads.

**Capture and attribution are separate.** `/api/v1/login` records no body and
no headers, yet still resolves its tenant label, so the request is billable
without any of it being stored.

**Metering is independent of capture.** `meter: {order_value: "$.total"}` reads
the response bytes even where the body is not stored.

## Files

| | |
|---|---|
| `optic.yaml` | one policy, loaded by all three services and the agent |
| `services/instrument.py` | the only OpticTrace-aware code — 40 lines |
| `services/{storefront,catalog,payments}.py` | ordinary FastAPI |
| `drive.py` | traffic across tenants, regions, plans, declines and 404s |
| `verify.py` | 25 assertions — leaks, correlation, billing, sampling |

## Notes

The agent runs with **no `service.listen` and no `upstream`**. That is
collector mode: there is nothing to proxy because the SDK is already in the
request path. Its admin port stays on `127.0.0.1`, which is why the Prometheus
container uses the host network rather than the admin port being republished.
