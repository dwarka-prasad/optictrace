package io.github.dwarkaprasad.optictrace;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * OpticTrace servlet filter — governance, correlation and telemetry for any
 * Jakarta Servlet application (Spring Boot, Quarkus, Jetty, Tomcat).
 *
 * <pre>{@code
 * @Bean
 * FilterRegistrationBean<OpticTraceFilter> optictrace() {
 *     return new FilterRegistrationBean<>(
 *         new OpticTraceFilter("optic.yaml", "http://localhost:9095", "checkout"));
 * }
 * }</pre>
 *
 * <p>Governance runs in-process: the payload is masked inside the service that
 * saw it, and only the governed record is shipped. Live traffic is never
 * modified — the client receives exactly the bytes the application produced.
 */
public final class OpticTraceFilter implements Filter {

    private final Engine engine;
    private final String service;
    private final Shipper shipper;
    private final boolean consoleLog;
    private final String traceResponseHeader;

    public OpticTraceFilter(String configPath, String agentUrl, String serviceName) throws IOException {
        this(loadConfig(configPath), agentUrl, serviceName, false);
    }

    public OpticTraceFilter(Map<String, Object> config, String agentUrl, String serviceName, boolean consoleLog) {
        this.engine = new Engine(config);
        this.service = serviceName != null && !serviceName.isEmpty() ? serviceName : engine.serviceName();
        this.consoleLog = consoleLog;
        this.traceResponseHeader = engine.traceResponseHeader();
        this.shipper = agentUrl == null || agentUrl.isEmpty()
                ? null
                : new Shipper(agentUrl.replaceAll("/+$", "") + "/api/ingest", 4096, 1, Duration.ofSeconds(5));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> loadConfig(String path) throws IOException {
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            return (Map<String, Object>) new Yaml().load(in);
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        if (!(req instanceof HttpServletRequest request) || !(res instanceof HttpServletResponse response)) {
            chain.doFilter(req, res);
            return;
        }

        String method = request.getMethod();
        String path = request.getRequestURI();
        Policy policy = engine.evaluate(method, path);
        // The up-front draw. Tail-based rules can rescue a request this draw
        // discarded, but only once the outcome is known — so when they are
        // configured the bytes are buffered regardless and the decision is
        // made at the end.
        boolean drew = policy.sampleRate >= 1.0 || ThreadLocalRandom.current().nextDouble() < policy.sampleRate;
        boolean buffer = drew || policy.tailSampled();

        Map<String, String> requestHeaders = headersOf(request);

        // Adopt the caller's trace or start one, and publish it before the
        // application runs so its logs and outbound calls can name this span.
        TraceContext ctx = TraceContext.fromHeader(request.getHeader(TraceContext.HEADER));
        TraceContext.set(ctx);

        // Echo the trace id back to the caller, if configured. Set BEFORE the
        // chain runs: once the application writes a byte the response is
        // committed and a header set afterwards is silently discarded — which
        // would look exactly like the feature working until someone tried to
        // use it on a real response.
        if (!traceResponseHeader.isEmpty()) {
            response.setHeader(traceResponseHeader, ctx.traceId);
        }

        CapturingRequest wrappedReq = new CapturingRequest(request, buffer && policy.captureRequestBody, policy.captureLimit);
        // Response bytes are buffered when the body is stored OR when a meter
        // needs them: metering is independent of capture, so restricting the
        // body must not silently zero the billing.
        CapturingResponse wrappedRes = new CapturingResponse(response,
                (buffer && policy.captureResponseBody) || policy.hasMeters(), policy.captureLimit);

        long start = System.nanoTime();
        int status = 200;
        try {
            chain.doFilter(wrappedReq, wrappedRes);
            status = wrappedRes.getStatus();
        } finally {
            wrappedRes.flushCapture();
            double durationMs = (System.nanoTime() - start) / 1_000_000.0;
            TraceContext.clear();

            // The record is ALWAYS emitted: metrics and metadata are never
            // sampled, and a request that produced no record at all is
            // invisible to every count and percentile. Sampling decides
            // whether the BODY is stored, and the tail-based rules rescue the
            // bodies worth having after the outcome is known.
            boolean keepBody = policy.keepBody(drew, status, durationMs);
            Map<String, Object> record = buildRecord(request, wrappedReq, wrappedRes, policy,
                    requestHeaders, method, path, status, durationMs, ctx, keepBody);
            if (consoleLog || shipper == null) {
                System.out.println(writeJson(record));
            }
            if (shipper != null) shipper.enqueue(record);
        }
    }

    private Map<String, Object> buildRecord(HttpServletRequest request, CapturingRequest req,
                                            CapturingResponse res, Policy policy,
                                            Map<String, String> requestHeaders, String method, String path,
                                            int status, double durationMs, TraceContext ctx,
                                            boolean keepBody) {
        Map<String, Object> record = new LinkedHashMap<>();
        // RFC3339 with a 'Z'. The agent parses strictly; the FastAPI SDK once
        // sent "+0530" and had every record rejected with a 400.
        record.put("time", Instant.now().toString());
        record.put("service", service);
        record.put("method", method);
        record.put("path", path);
        record.put("route", policy.routePattern.isEmpty() ? path : policy.routePattern);
        record.put("status", status);
        record.put("duration_ms", durationMs);
        record.put("remote", request.getRemoteAddr() == null ? "" : request.getRemoteAddr());
        record.put("source", "java");
        record.put("req_bytes", req.byteCount());
        record.put("resp_bytes", res.byteCount());
        record.put("trace_id", ctx.traceId);
        record.put("span_id", ctx.spanId);
        if (!ctx.parentSpanId.isEmpty()) record.put("parent_span_id", ctx.parentSpanId);

        String query = request.getQueryString();
        if (query != null && !query.isEmpty()) record.put("query", policy.sanitizeQuery(query));
        if (!policy.matchedRules.isEmpty()) record.put("matched_rules", policy.matchedRules);

        if (policy.captureHeaders) {
            record.put("request_headers", policy.sanitizeHeaders(requestHeaders));
            record.put("response_headers", policy.sanitizeHeaders(res.headers()));
        }

        byte[] reqBody = req.captured();
        String governedRequest = null;
        if (reqBody.length > 0 && policy.captureRequestBody && keepBody) {
            governedRequest = policy.redactBody(reqBody, request.getContentType());
            record.put("request_body", governedRequest);
            if (req.truncated()) record.put("req_truncated", true);
        }

        byte[] respBody = res.captured();
        String governedResponse = null;
        if (respBody.length > 0) {
            Map<String, Double> meters = policy.extractMeters(respBody);
            if (!meters.isEmpty()) record.put("meters", meters);
            // Buffered for metering is not the same as allowed to be stored,
            // and neither is buffered for a tail rule that did not fire.
            if (policy.captureResponseBody && keepBody) {
                governedResponse = policy.redactBody(respBody, res.getContentType());
                record.put("response_body", governedResponse);
                if (res.truncated()) record.put("resp_truncated", true);
            }
        }

        if (!policy.labelSources().isEmpty()) {
            record.put("labels", resolveLabels(policy, requestHeaders, request.getQueryString(), path,
                    governedRequest, governedResponse, reqBody, respBody));
        }
        return record;
    }

    /**
     * Resolve labels from the GOVERNED bodies, so a label can never copy a
     * value the policy just masked into a Prometheus dimension.
     */
    private Map<String, String> resolveLabels(Policy policy, Map<String, String> headers, String rawQuery,
                                              String path, String governedRequest, String governedResponse,
                                              byte[] reqBody, byte[] respBody) {
        Map<String, String> query = parseQuery(rawQuery);
        JsonNode reqDoc = parseJson(governedRequest != null ? governedRequest.getBytes() : redactedOrNull(policy, reqBody));
        JsonNode respDoc = parseJson(governedResponse != null ? governedResponse.getBytes() : redactedOrNull(policy, respBody));

        Map<String, String> out = new LinkedHashMap<>();
        policy.labelSources().forEach((name, src) ->
                out.put(name, Policy.labelValue(src, headers, query, path, reqDoc, respDoc)));
        return out;
    }

    /** A body not stored can still be labelled — but only after redaction runs over it. */
    private byte[] redactedOrNull(Policy policy, byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        String governed = policy.redactBody(raw, "application/json");
        return governed.startsWith("<") ? null : governed.getBytes();
    }

    private static JsonNode parseJson(byte[] raw) {
        if (raw == null || raw.length == 0) return null;
        try {
            return Policy.mapper().readTree(raw);
        } catch (Exception e) {
            return null;
        }
    }

    static Map<String, String> parseQuery(String query) {
        Map<String, String> out = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return out;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) out.putIfAbsent(pair.substring(0, eq), pair.substring(eq + 1));
        }
        return out;
    }

    private static Map<String, String> headersOf(HttpServletRequest request) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String name : Collections.list(request.getHeaderNames())) {
            out.put(name.toLowerCase(Locale.ROOT), request.getHeader(name));
        }
        return out;
    }

    private static String writeJson(Object o) {
        try {
            return Policy.mapper().writeValueAsString(o);
        } catch (Exception e) {
            return "{}";
        }
    }

    @Override
    public void destroy() {
        if (shipper != null) shipper.close();
    }
}
