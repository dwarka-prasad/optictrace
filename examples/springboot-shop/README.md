# springboot-optictrace

A real Spring Boot 3 service instrumented with the OpticTrace **Java servlet
SDK**, used to check the SDK against an actual servlet container rather than
against the dynamic proxies in its own test suite.

It is a small shop API: a checkout endpoint that fans out to a catalog read and
a payment charge, plus a login route and a health check.

```
POST /api/v1/orders            → GET /api/v1/catalog/{sku}
                               → POST /api/v1/payments/charge
POST /api/v1/auth/login
GET  /api/v1/health            (deliberately ungoverned)
```

The two inner calls are real HTTP calls back into the same process, so one
checkout produces three spans. They join into one trace because
`CheckoutController` copies `TraceContext.outboundHeaders()` onto each outbound
request — that is the only tracing code in the application.

## Running it

All paths below are relative to this directory.

```bash
# 1. build and install the SDK into the local Maven repo (it is not on Central)
(cd ../../sdks/java && mvn install -DskipTests)

# 2. the agent, in collector mode — no proxy, it only stores and aggregates
../../bin/optictrace run -config optic.yaml -ui ../../ui/out

# 3. the application
mvn package -DskipTests
java -jar target/springboot-optictrace-1.0.0.jar

# 4. traffic: several tenants, a mix of routes, some failures
./drive-traffic.sh 80
```

Dashboard: <http://127.0.0.1:9095>

## What it demonstrates

| | |
|---|---|
| **In-process redaction** | The card number and CVV are masked inside the JVM that saw them. `4111111111111111` never reaches the agent, on either hop. |
| **Correlation** | The three legs of a checkout share a trace id, and the two inner legs name the outer one as parent. Never matched by timestamp. |
| **Application logs** | `PaymentsController` logs the raw card number at FINE, the way a service does while someone is debugging. It is stored `[REDACTED]`, filed against the exact span that wrote it. |
| **Attribution** | `X-Tenant-ID` / `X-Region` / `X-Plan` become labels, forwarded across the internal hops so the usage page bills the whole trace, not just its first leg. |
| **Sampling** | Catalog reads are sampled at 0.4, with `keep_slower_than: 200ms`. The record is always written; only the body is sampled. |
| **Trace id to the caller** | Responses carry `X-Trace-Id`, so a support conversation can start from a screenshot instead of a timestamp. |
| **Inner spans** | `ProductRepository` names every operation: an H2 query, a cache lookup, an index refresh nested inside an insert, and the acquirer call in `PaymentsController`. The waterfall shows all of them under the hop that ran them. |
| **Governed attributes** | `saveOrder` deliberately records an *interpolated* statement, the way a driver logging its own SQL would. The customer's email is stored `[REDACTED]` — which is why span attributes are governed at all. |
| **An N+1, on purpose** | `stockFor` runs one query per sku. On the breakdown it shows as one named operation with a ×4 per-request multiplier — the shape no latency chart can show you. |

## Wiring

All of it is in [`OpticTraceConfig`](src/main/java/com/example/shop/OpticTraceConfig.java):
a `FilterRegistrationBean` at `HIGHEST_PRECEDENCE` so the filter sees the bytes
the client sent, and an `OpticTraceLogHandler` on the `com.example.shop` logger.

One non-obvious detail: JUL filters on the **logger** level before a handler is
ever consulted, and its default is `INFO`. Without `setLevel(Level.FINE)` the
masked debug line would never be shipped — and the demo would look like
redaction was working when in fact nothing had been sent.

## Governance review

```bash
../../bin/optictrace scan    -config optic.yaml -window 1h   # inspects values
../../bin/optictrace suggest -config optic.yaml -window 1h   # inspects names
```

```bash
../../bin/optictrace scan -config optic.yaml -window 1h              # values
curl -s localhost:9095/api/spans/breakdown?window=1h | jq            # where the time went
```

`scan` reports clean. `suggest` still proposes masking `$.customer.name` and
`$.name` on the catalog — both left in place on purpose, so the example has a
real finding to look at rather than a contrived one. `/api/v1/health` is
ungoverned for the same reason.
