package io.github.dwarkaprasad.optictrace;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Dependency-free test suite for the Java SDK: {@code java SelfTest}.
 *
 * <p>Set OPTIC_AGENT_URL to also ship the records to a live agent — which is
 * the check that matters most. The Python SDK passed its own unit tests for
 * weeks while delivering zero records to a real agent, because nothing ever
 * asked one whether it had accepted them.
 */
public final class SelfTest {

    private static int passed = 0;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        engineChecks();
        traceChecks();
        filterChecks();
        logChecks();

        System.out.println();
        if (failures.isEmpty()) {
            System.out.println("✓ " + passed + " checks passed");
        } else {
            System.out.println("✗ " + failures.size() + " of " + (passed + failures.size()) + " checks FAILED");
            failures.forEach(f -> System.out.println("   " + f));
            System.exit(1);
        }
    }

    private static final String CONFIG = """
            version: 1
            service:
              name: java-test
              trace: { response_header: X-Trace-Id }
            defaults:
              capture: { request_body: true, response_body: true, headers: true }
            rules:
              - name: redact-payments
                match:
                  path: "/payments/**"
                  methods: [POST]
                redact:
                  headers: [Authorization]
                  query_params: [api_key]
                  json_fields:
                    - "$.**.card.number"
                    - "$.*.ssn"
                labels:
                  tenant: "header:X-Tenant-ID"
                  region: "header:X-Region|^([a-z]{2})-"
                  channel: "static:direct"
                  area: "path:1"
                  partner: "json:$.**.source"
                  outcome: "json_response:$.status"
              - name: meter-ai
                match: { path: "/ai/**" }
                restrict: [response_body]
                meter:
                  tokens: "$.usage.total_tokens"
              - name: sample-hot-reads
                match: { path: "/hot/**" }
                sample: 0.0001
                keep_errors: true
                keep_slower_than: 10ms
              - name: no-capture-on-auth
                match: { path: "/auth/**" }
                restrict: [request_body, response_body, headers]
                labels:
                  tenant: "header:X-Tenant-ID"
            """;

    @SuppressWarnings("unchecked")
    private static Engine engine() {
        return new Engine((Map<String, Object>) new Yaml().load(CONFIG));
    }

    // ------------------------------------------------------------------
    private static void engineChecks() {
        Engine e = engine();

        check("glob: ** matches nested", e.evaluate("POST", "/payments/charge/v2").matchedRules.contains("redact-payments"));
        check("glob: ** matches zero segments", e.evaluate("POST", "/payments").matchedRules.contains("redact-payments"));
        check("glob: unrelated path does not match", e.evaluate("POST", "/orders").matchedRules.isEmpty());
        check("methods narrow a rule", e.evaluate("GET", "/payments/charge").matchedRules.isEmpty());

        Policy p = e.evaluate("POST", "/payments/charge");

        // Redaction, including recursive descent through an echoing upstream.
        byte[] body = """
                {"source":"flipkart","card":{"number":"4111111111111111","cvv":"123"},
                 "echo":{"card":{"number":"4111111111111111"}},"customer":{"ssn":"123-45-6789"},
                 "amount":4200}
                """.getBytes();
        String governed = p.redactBody(body, "application/json");
        check("card number masked", !governed.contains("4111111111111111"));
        check("card number masked at any depth (echo)", countOf(governed, "[REDACTED]") >= 3);
        check("ssn masked via $.*", !governed.contains("123-45-6789"));
        check("unrelated fields survive", governed.contains("4200") && governed.contains("flipkart"));
        check("cvv NOT masked (not named by a rule)", governed.contains("123"));

        check("header masked", "[REDACTED]".equals(p.sanitizeHeaders(Map.of("authorization", "Bearer x")).get("authorization")));
        check("other headers survive", "acme".equals(p.sanitizeHeaders(Map.of("x-tenant-id", "acme")).get("x-tenant-id")));
        check("query credential masked, page kept",
                p.sanitizeQuery("api_key=live_sk_1&page=2").equals("api_key=[REDACTED]&page=2"));

        // Labels, resolved from the GOVERNED body.
        JsonNode req = parse(governed);
        JsonNode res = parse("{\"status\":\"captured\"}");
        Map<String, String> h = Map.of("x-tenant-id", "acme", "x-region", "ap-south-1");
        check("label header:", "acme".equals(Policy.labelValue("header:X-Tenant-ID", h, Map.of(), "/payments/charge", req, res)));
        check("label regex capture", "ap".equals(Policy.labelValue("header:X-Region|^([a-z]{2})-", h, Map.of(), "/payments/charge", req, res)));
        check("label regex miss yields empty", "".equals(Policy.labelValue("header:X-Region|^(zz)-", h, Map.of(), "/p", req, res)));
        check("label static:", "direct".equals(Policy.labelValue("static:direct", h, Map.of(), "/p", req, res)));
        check("label path: is 1-based", "payments".equals(Policy.labelValue("path:1", h, Map.of(), "/payments/charge", req, res)));
        check("label query:", "gold".equals(Policy.labelValue("query:plan", h, Map.of("plan", "gold"), "/p", req, res)));
        check("label json: reads the body", "flipkart".equals(Policy.labelValue("json:$.**.source", h, Map.of(), "/p", req, res)));
        check("label json_response:", "captured".equals(Policy.labelValue("json_response:$.status", h, Map.of(), "/p", req, res)));
        check("a label can never read a masked value",
                !"4111111111111111".equals(Policy.labelValue("json:$.**.card.number", h, Map.of(), "/p", req, res)));

        // Meters, independent of capture.
        Policy ai = e.evaluate("POST", "/ai/complete");
        check("restrict turns off response capture", !ai.captureResponseBody);
        check("meters still extracted from a restricted body",
                Double.valueOf(128.0).equals(ai.extractMeters("{\"usage\":{\"total_tokens\":128}}".getBytes()).get("tokens")));
        check("meters sum across arrays",
                Double.valueOf(30.0).equals(e.evaluate("POST", "/ai/x")
                        .extractMeters("{\"usage\":[{\"total_tokens\":10},{\"total_tokens\":20}]}".getBytes()).get("tokens")));

        // Tail-based sampling. sample is a draw made up front; keep_errors and
        // keep_slower_than rescue what is worth having once the outcome is known.
        Policy hot = e.evaluate("GET", "/hot/reads");
        check("tail rules force buffering even at a tiny sample rate", hot.tailSampled());
        check("an unsampled fast 200 keeps no body", !hot.keepBody(false, 200, 1));
        check("keep_errors rescues a 5xx", hot.keepBody(false, 500, 1));
        // keep_errors means 5xx. A 404 is usually the client's problem, and
        // rescuing it would defeat the sampling it works alongside.
        check("keep_errors does NOT rescue a 4xx", !hot.keepBody(false, 404, 1));
        check("keep_slower_than rescues a slow request", hot.keepBody(false, 200, 25));
        check("a drawn request always keeps its body", hot.keepBody(true, 200, 1));

        Policy auth = e.evaluate("POST", "/auth/login");
        check("restrict disables all capture", !auth.captureRequestBody && !auth.captureResponseBody && !auth.captureHeaders);
        check("attribution survives capture restriction", auth.labelSources().containsKey("tenant"));
    }

    private static void traceChecks() {
        TraceContext adopted = TraceContext.fromHeader("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        check("inbound trace adopted", adopted.traceId.equals("4bf92f3577b34da6a3ce929d0e0e4736"));
        check("caller's span becomes the parent", adopted.parentSpanId.equals("00f067aa0ba902b7"));
        check("this hop gets a fresh span", !adopted.spanId.equals("00f067aa0ba902b7") && adopted.spanId.length() == 16);

        TraceContext fresh = TraceContext.fromHeader("total garbage");
        check("malformed header starts a new trace, does not fail", fresh.traceId.length() == 32 && fresh.parentSpanId.isEmpty());
        check("all-zero trace id rejected",
                !TraceContext.fromHeader("00-" + "0".repeat(32) + "-00f067aa0ba902b7-01").traceId.equals("0".repeat(32)));
        check("header round-trips", adopted.header().equals("00-" + adopted.traceId + "-" + adopted.spanId + "-01"));

        TraceContext.set(adopted);
        check("outbound headers carry THIS hop's span, not the caller's",
                TraceContext.outboundHeaders().get("traceparent").contains(adopted.spanId));
        TraceContext.clear();
        check("no span outside a request", TraceContext.outboundHeaders().isEmpty());
    }

    // ------------------------------------------------------------------
    @SuppressWarnings("unchecked")
    private static void filterChecks() throws Exception {
        Map<String, Object> cfg = (Map<String, Object>) new Yaml().load(CONFIG);
        // Content assertions run against a filter with NO agent, so the record
        // is printed and can be read back. Delivery is proved separately below:
        // conflating the two would mean neither is checked properly.
        OpticTraceFilter filter = new OpticTraceFilter(cfg, null, "java-test", false);

        byte[] requestBody = "{\"source\":\"flipkart\",\"card\":{\"number\":\"4111111111111111\"},\"amount\":42}".getBytes();
        byte[] responseBody = "{\"status\":\"captured\",\"charge_id\":\"ch_1\"}".getBytes();

        Captured out = invoke(filter, "POST", "/payments/charge", "api_key=live_sk_1&page=2",
                Map.of("content-type", "application/json", "authorization", "Bearer topsecret123",
                        "x-tenant-id", "acme", "x-region", "ap-south-1"),
                requestBody, responseBody, 201);

        check("client receives the ORIGINAL bytes — traffic is never modified",
                new String(out.clientBytes).equals(new String(responseBody)));

        Map<String, Object> rec = out.record;
        check("record was produced", rec != null);
        if (rec != null) {
            String json = Policy.mapper().writeValueAsString(rec);
            check("card number never reaches the record", !json.contains("4111111111111111"));
            check("bearer token never reaches the record", !json.contains("topsecret123"));
            check("query credential masked in the record", !json.contains("live_sk_1"));
            check("timestamp is RFC3339 UTC (the bug that broke the Python SDK)",
                    String.valueOf(rec.get("time")).endsWith("Z"));
            check("trace id present", String.valueOf(rec.get("trace_id")).length() == 32);
            check("span id present", String.valueOf(rec.get("span_id")).length() == 16);
            check("route is the rule pattern, not the raw path", "/payments/**".equals(rec.get("route")));
            check("status recorded", Integer.valueOf(201).equals(rec.get("status")));
            Map<String, String> labels = (Map<String, String>) rec.get("labels");
            check("tenant label", "acme".equals(labels.get("tenant")));
            check("region label captured by regex", "ap".equals(labels.get("region")));
            check("partner label read from the payload", "flipkart".equals(labels.get("partner")));
            check("outcome label read from the response", "captured".equals(labels.get("outcome")));
            // The only thread from a customer's screenshot back to the record.
            // The Go proxy has always echoed it; the SDKs silently ignored the
            // setting until a real Spring Boot app was pointed at one.
            check("trace id echoed to the caller on the configured header",
                    String.valueOf(rec.get("trace_id")).equals(out.responseHeaders().get("x-trace-id")));
            check("trace header set before the first byte, or a container drops it",
                    out.traceHeaderSetBeforeBody());
        }

        // Restricted route: metadata only, but still attributable.
        Captured auth = invoke(filter, "POST", "/auth/login", null,
                Map.of("content-type", "application/json", "x-tenant-id", "acme"),
                "{\"password\":\"hunter2\"}".getBytes(), "{\"token\":\"abc\"}".getBytes(), 200);
        Map<String, Object> ar = auth.record;
        check("restricted route records nothing sensitive",
                ar != null && !Policy.mapper().writeValueAsString(ar).contains("hunter2"));
        check("restricted route captures no headers", ar != null && !ar.containsKey("request_headers"));
        check("restricted route is still attributed to a tenant",
                ar != null && "acme".equals(((Map<String, String>) ar.get("labels")).get("tenant")));

        // Metering with the body deliberately not stored.
        Captured ai = invoke(filter, "POST", "/ai/complete", null, Map.of("content-type", "application/json"),
                "{\"prompt\":\"hi\"}".getBytes(), "{\"usage\":{\"total_tokens\":128}}".getBytes(), 200);
        check("meters extracted even though the response body is restricted",
                ai.record != null && ai.record.containsKey("meters"));
        check("restricted response body not stored", ai.record != null && !ai.record.containsKey("response_body"));

        filter.destroy();

        // Delivery: does a real agent ACCEPT what this SDK produces? The
        // Python SDK passed every offline check it had while a live agent
        // rejected 100% of its records.
        String agent = System.getenv("OPTIC_AGENT_URL");
        if (agent != null && !agent.isEmpty()) {
            OpticTraceFilter shipping = new OpticTraceFilter(cfg, agent, "java-test", false);
            invoke(shipping, "POST", "/payments/charge", null,
                    Map.of("content-type", "application/json", "x-tenant-id", "acme", "x-region", "ap-south-1"),
                    requestBody, responseBody, 201);
            Thread.sleep(1500);
            shipping.destroy();
            String stored = httpGet(agent + "/api/logs?window=5m&limit=50");
            check("a live agent accepted a record from this SDK", stored.contains("\"source\":\"java\""));
        }
    }

    /**
     * Proves the log handler actually DELIVERS, by asking the agent whether it
     * accepted the line. Skipped without OPTIC_AGENT_URL — but this is the
     * check that would have caught the Python SDK shipping nothing for weeks,
     * so it is worth running in CI against a real agent rather than mocked.
     */
    private static void logChecks() throws Exception {
        String agent = System.getenv("OPTIC_AGENT_URL");
        if (agent == null || agent.isEmpty()) {
            System.out.println("  · log delivery checks skipped (set OPTIC_AGENT_URL)");
            return;
        }

        OpticTraceLogHandler handler = new OpticTraceLogHandler(agent, "java-test");
        java.util.logging.Logger log = java.util.logging.Logger.getLogger("optictrace-selftest");
        log.setUseParentHandlers(false);
        log.setLevel(java.util.logging.Level.ALL);
        handler.setLevel(java.util.logging.Level.ALL);
        log.addHandler(handler);

        TraceContext ctx = TraceContext.fromHeader(null);
        TraceContext.set(ctx);
        log.info("java sdk selftest line");
        log.warning("careless debug: Bearer topsecret123");
        TraceContext.clear();
        log.info("emitted with no request in flight");   // orphan

        handler.close();
        Thread.sleep(1500);

        check("log handler reported no delivery failures (" + handler.failed() + " failed, "
                + handler.sent() + " sent, last=" + handler.lastError() + ")", handler.failed() == 0);

        String body = httpGet(agent + "/api/applogs?span=" + ctx.spanId);
        check("the agent stored the lines against this span", body.contains("java sdk selftest line"));
        check("a token logged by mistake is stored redacted",
                !body.contains("topsecret123") && body.contains("[REDACTED]"));
    }

    private static String httpGet(String url) throws Exception {
        java.net.http.HttpClient c = java.net.http.HttpClient.newHttpClient();
        return c.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(url)).build(),
                java.net.http.HttpResponse.BodyHandlers.ofString()).body();
    }

    // --- a minimal servlet environment --------------------------------
    private record Captured(Map<String, Object> record, byte[] clientBytes,
                           Map<String, String> responseHeaders, boolean traceHeaderSetBeforeBody) {
    }

    /**
     * Drives the real filter through dynamic proxies rather than a servlet
     * container: the code under test is the shipping code path, not a
     * reimplementation of it.
     */
    @SuppressWarnings("unchecked")
    private static Captured invoke(OpticTraceFilter filter, String method, String path, String query,
                                   Map<String, String> headers, byte[] requestBody, byte[] responseBody,
                                   int status) throws Exception {
        ByteArrayOutputStream clientSink = new ByteArrayOutputStream();
        Map<String, String> responseHeaders = new LinkedHashMap<>();
        responseHeaders.put("content-type", "application/json");
        int[] statusHolder = {status};
        // A header set after the first byte is written is silently discarded by
        // a real container, so the ORDER is the thing worth asserting.
        boolean[] traceHeaderBeforeBody = {false};

        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
                SelfTest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                requestHandler(method, path, query, headers, requestBody));

        HttpServletResponse response = (HttpServletResponse) Proxy.newProxyInstance(
                SelfTest.class.getClassLoader(), new Class<?>[]{HttpServletResponse.class},
                responseHandler(clientSink, responseHeaders, statusHolder, traceHeaderBeforeBody));

        List<Map<String, Object>> captured = new ArrayList<>();
        // The filter prints the record when no agent is configured; capture it
        // by intercepting stdout so the assertions read the real output.
        java.io.PrintStream original = System.out;
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        System.setOut(new java.io.PrintStream(sink));
        try {
            filter.doFilter(request, response, (req, res) -> {
                req.getInputStream().readAllBytes();          // the app reads its body
                res.getOutputStream().write(responseBody);    // and writes its response
            });
        } finally {
            System.setOut(original);
        }
        for (String line : sink.toString().split("\n")) {
            if (line.startsWith("{")) captured.add(Policy.mapper().readValue(line, Map.class));
        }
        return new Captured(captured.isEmpty() ? null : captured.get(captured.size() - 1),
                clientSink.toByteArray(), responseHeaders, traceHeaderBeforeBody[0]);
    }

    private static InvocationHandler requestHandler(String method, String path, String query,
                                                    Map<String, String> headers, byte[] body) {
        ByteArrayInputStream in = new ByteArrayInputStream(body);
        return (proxy, m, args) -> switch (m.getName()) {
            case "getMethod" -> method;
            case "getRequestURI" -> path;
            case "getQueryString" -> query;
            case "getRemoteAddr" -> "127.0.0.1";
            case "getContentType" -> headers.get("content-type");
            case "getCharacterEncoding" -> "UTF-8";
            case "getHeaderNames" -> Collections.enumeration(headers.keySet());
            case "getHeader" -> headers.get(String.valueOf(args[0]).toLowerCase(Locale.ROOT));
            case "getInputStream" -> new ServletInputStream() {
                public int read() {
                    return in.read();
                }

                public int read(byte[] b, int off, int len) {
                    return in.read(b, off, len);
                }

                public boolean isFinished() {
                    return in.available() == 0;
                }

                public boolean isReady() {
                    return true;
                }

                public void setReadListener(ReadListener l) {
                }
            };
            default -> defaultValue(m);
        };
    }

    private static InvocationHandler responseHandler(ByteArrayOutputStream sink,
                                                     Map<String, String> headers, int[] status,
                                                     boolean[] traceHeaderBeforeBody) {
        return (proxy, m, args) -> switch (m.getName()) {
            case "setHeader", "addHeader" -> {
                String name = String.valueOf(args[0]);
                if (name.equalsIgnoreCase("X-Trace-Id") && sink.size() == 0) {
                    traceHeaderBeforeBody[0] = true;
                }
                headers.put(name.toLowerCase(Locale.ROOT), String.valueOf(args[1]));
                yield null;
            }
            case "getStatus" -> status[0];
            case "setStatus" -> {
                status[0] = (int) args[0];
                yield null;
            }
            case "getContentType" -> headers.get("content-type");
            case "getCharacterEncoding" -> "UTF-8";
            case "getHeaderNames" -> headers.keySet();
            case "getHeader" -> headers.get(String.valueOf(args[0]).toLowerCase(Locale.ROOT));
            case "getOutputStream" -> new ServletOutputStream() {
                public void write(int b) {
                    sink.write(b);
                }

                public void write(byte[] b, int off, int len) {
                    sink.write(b, off, len);
                }

                public boolean isReady() {
                    return true;
                }

                public void setWriteListener(WriteListener l) {
                }
            };
            default -> defaultValue(m);
        };
    }

    private static Object defaultValue(Method m) {
        Class<?> t = m.getReturnType();
        if (!t.isPrimitive()) return null;
        if (t == boolean.class) return false;
        if (t == int.class) return 0;
        if (t == long.class) return 0L;
        return null;
    }

    // --- helpers -------------------------------------------------------
    private static JsonNode parse(String s) {
        try {
            return Policy.mapper().readTree(s);
        } catch (Exception e) {
            return null;
        }
    }

    private static int countOf(String haystack, String needle) {
        int n = 0, i = 0;
        while ((i = haystack.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    private static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  ✓ " + name);
        } else {
            failures.add(name);
            System.out.println("  ✗ " + name);
        }
    }
}
