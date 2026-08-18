# Lead pipeline — a test application

Three services, each behind its own OpticTrace sidecar, all reporting into one
store. It exists to exercise the governance surface end to end and to **assert**
the result: `verify.py` fails if a guarantee regresses, rather than printing
output for a human to squint at.

```
client ──▶ :8001 ─▶ leads ──▶ :8002 ─▶ scoring ──▶ :8003 ─▶ bureau
           sidecar   :7001    sidecar    :7002     sidecar    :7003
             │                   │                    │
             └───────────── one store, one trace ─────┘
```

## Run it

```bash
./run.sh          # in one terminal — builds and starts everything
./drive.sh 28     # send lead traffic from several partners
./verify.py       # assert 19 guarantees
```

`run.sh` wipes the store on start, so each run is clean. Dashboards are on
:9001 (leads), :9002 (scoring), :9003 (bureau).

## The scenario

A lead API called by Flipkart, Samsung, Amazon and Xiaomi. **Same endpoint,
same tenant, same product** — the only thing separating the callers is
`$.lead.source` in the payload. That is deliberately the hard case:

- **Attribution from the body** — `partner: "json:$.**.source"`
- **Classification by criteria** — `match.body` splits marketplace from OEM
- **From the response** — `decision: "json_response:$.decision"`
- **PII masked both ways** — the lead service echoes the applicant back, so a
  request-only rule would leak on the way out
- **Trace correlation** — one request across three services becomes a tree
- **Sampling with a floor** — scoring keeps one body in four but never drops a
  failure (`sample: 0.25` + `keep_errors: true`)
- **Metering** — token counts pulled from the scoring response and priced per
  partner

```
trace e39bef0f595ca85327980df59e1b6514
  leads     POST /api/v1/leads     200   6.82ms  partner=flipkart channel=marketplace
     └─ scoring   POST /api/v1/score     200   5.26ms
        └─ bureau    POST /api/v1/history   200   4.02ms
```

## The bureau sidecar is deliberately under-governed

`optic/bureau.yaml` has **no rule** covering the card number and Aadhaar in the
third-party response. That is the point: `optictrace scan` should find both, and
`verify.py` asserts it does. A governance tool whose value you cannot see
failing is a governance tool nobody trusts.

```
$ curl -s localhost:9003/api/scan | jq '.findings[].kind'
"credit-card"
"aadhaar"
```

## Proving the assertions bite

A suite that cannot fail is worthless. Weaken a rule and re-run:

```bash
# remove '- "$.**.phone"' from optic/leads.yaml
curl -X POST localhost:9001/api/reload
./verify.py
#   ✗ PII is redacted in the stored REQUEST body
#         raw PII survived ['9876500000']: {"lead":{"phone":"9876500000",…
#   ✗ PII is redacted in the stored RESPONSE body too
#   2 check(s) failed
```

Put the line back, reload, and it goes green again — the PII checks assert on a
probe request **this run** sent, so a leak recorded under an earlier config does
not fail the suite forever.

## Notes

The applications are almost uninstrumented on purpose. Each one does exactly
one tracing-related thing — forward the inbound `traceparent` to its downstream
call — which is the application's job in any tracing setup and is all the
sidecars need to reassemble the tree. An OTel SDK would do it for you.

All three sidecars share one SQLite file; WAL mode handles the concurrent
writers at this volume. For anything real use Postgres or ClickHouse.
