# OpticTrace — Java / Jakarta Servlet SDK

Evaluates the same `optic.yaml` as the OpticTrace agent, **in-process**, so a
card number is masked inside the service that saw it and never crosses a
process boundary in the clear. Only the governed record is shipped.

Works with anything on Jakarta Servlet 5+: Spring Boot 3, Quarkus, Jetty,
Tomcat.

```xml
<dependency>
  <groupId>io.github.dwarka-prasad</groupId>
  <artifactId>optictrace-servlet</artifactId>
  <version>0.9.0</version>
</dependency>
```

## Spring Boot

```java
@Bean
FilterRegistrationBean<OpticTraceFilter> optictrace() throws IOException {
    var f = new OpticTraceFilter("optic.yaml", "http://localhost:9095", "checkout");
    var reg = new FilterRegistrationBean<>(f);
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE);   // see the bytes the client sees
    return reg;
}
```

## Your logs, under the request that wrote them

```java
Logger.getLogger("").addHandler(
    new OpticTraceLogHandler("http://localhost:9095", "checkout"));
```

Nothing at the call site changes. The span comes from the ThreadLocal the
filter sets, so an ordinary `log.info(...)` is filed against the exact request
that produced it — never matched by timestamp, which under concurrent traffic
would file one tenant's line inside another tenant's request.

## Calls this service makes downstream

```java
HttpRequest.Builder b = HttpRequest.newBuilder(uri);
TraceContext.outboundHeaders().forEach(b::header);
```

This carries **this** hop's span, so the next service nests under it rather
than becoming its sibling.

## What it does

| | |
|---|---|
| Restriction | `restrict: [request_body, response_body, headers]` |
| Redaction | headers, query params, and JSON paths with `*` / `**` descent |
| Labels | `header:` `query:` `path:<n>` `static:` `json:` `json_response:`, each with an optional `\|<regex>` capture |
| Meters | numeric paths for billing — read from the raw response even when the body is not stored |
| Sampling | `sample`, plus tail-based `keep_errors` and `keep_slower_than` |
| Trace | adopts an inbound `traceparent` or starts one |
| App logs | `OpticTraceLogHandler` |

**Live traffic is never modified.** The response is teed as it is written, so
the client receives exactly the bytes the application produced and a streaming
response still streams.

## Tests

```bash
mvn compile exec:java -Dexec.mainClass=io.github.dwarkaprasad.optictrace.SelfTest

# Or with no build tool at all:
javac -d out -cp "$DEPS" src/main/java/io/github/dwarkaprasad/optictrace/*.java
javac -d out -cp "$DEPS:out" src/test/java/io/github/dwarkaprasad/optictrace/SelfTest.java
java -cp "$DEPS:out" io.github.dwarkaprasad.optictrace.SelfTest
```

57 checks, no test framework. **Set `OPTIC_AGENT_URL` to also assert that a
live agent accepts what this SDK produces** — the Python SDK passed every
offline check it had while a real agent rejected 100% of its records, because
nothing ever asked one. Run it that way in CI.

## Notes

`jakarta.servlet-api` is `provided`: pulling a servlet API into an application
that already has one gets the filter loaded by a different classloader than the
one serving requests.

### Spring Boot 2 / Tomcat 9 (`javax.servlet`)

```bash
./scripts/gen-javax.sh          # -> target/javax-src
```

The two servlet APIs differ only in package name for everything this SDK
touches, so the javax variant is **generated** rather than kept as a second
copy. Two copies of the same engine drift, and the copy nobody runs is the one
that drifts. The script fails if a `jakarta.` reference survives the rewrite —
that would mean a new API surface it does not know about — and CI compiles *and
runs* the generated variant against `javax.servlet-api:4.0.1`, so it is tested
rather than assumed.
