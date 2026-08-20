package io.github.dwarkaprasad.optictrace;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Records inner spans: the operations that run while a request is being served.
 *
 * <p>{@link OpticTraceFilter} records the HTTP exchange. This records what
 * happened inside it — a query, a cache lookup, an outbound call — which is
 * the difference between "this request took 300ms" and "this request took
 * 300ms, 280 of them in one query".
 *
 * <pre>{@code
 * OpticTraceSpans spans = new OpticTraceSpans("http://localhost:9095", "checkout");
 *
 * try (InnerSpan sp = spans.start("db.query", "db")) {
 *     sp.set("db.statement", SQL);
 *     ResultSet rs = stmt.executeQuery();
 *     sp.setInt("db.rows", count);
 * } catch (SQLException e) {
 *     // the span records the failure through fail(), see InnerSpan
 *     throw e;
 * }
 * }</pre>
 *
 * <p>Attributes are governed by the agent before storage, so a statement that
 * quotes its parameters is redacted before anything is written. Pass the
 * statement TEMPLATE where you can: the safest secret is the one never sent.
 *
 * <p>Shipping is fire-and-forget on a background worker. An application must
 * never be slower, or fail, because its telemetry sink is unhappy.
 */
public final class OpticTraceSpans implements AutoCloseable {

    /**
     * The innermost open span per thread, so operations nest: a query inside a
     * transaction parents to the transaction rather than jumping to the
     * request.
     *
     * <p>Inheritable for the same reason {@link TraceContext} is — work handed
     * to a child thread stays correlated. A deque rather than a single value
     * because spans nest and close in reverse order.
     */
    private static final InheritableThreadLocal<Deque<String>> OPEN =
            new InheritableThreadLocal<>() {
                @Override
                protected Deque<String> initialValue() {
                    return new ArrayDeque<>();
                }
            };

    private final Shipper shipper;
    private final String service;

    public OpticTraceSpans(String agentUrl, String service) {
        this(agentUrl, service, 10_000, 200, Duration.ofSeconds(5));
    }

    /**
     * @param agentUrl the agent's base URL. Empty or null makes every span
     *                 inert, so instrumentation can stay in place in an
     *                 environment with no agent rather than being guarded by
     *                 an {@code if} at each call site.
     */
    public OpticTraceSpans(String agentUrl, String service, int queueSize, int batchSize,
                           Duration timeout) {
        this.service = service;
        this.shipper = agentUrl == null || agentUrl.isEmpty()
                ? null
                : new Shipper(agentUrl.replaceAll("/+$", "") + "/api/spans/ingest",
                queueSize, batchSize, timeout);
    }

    /**
     * Opens a span for an operation.
     *
     * <p>{@code kind} classifies it for the waterfall and the breakdown: db,
     * cache, http, queue, rpc, internal. Outside a request the span has no
     * parent, and the agent drops it by default — work belonging to no request
     * cannot be attributed to one.
     */
    public InnerSpan start(String name, String kind) {
        return new InnerSpan(this, name, kind);
    }

    /** Delivery counters, so "are my spans arriving?" has an answer. */
    public long sent() {
        return shipper == null ? 0 : shipper.sent.get();
    }

    public long failed() {
        return shipper == null ? 0 : shipper.failed.get();
    }

    public long dropped() {
        return shipper == null ? 0 : shipper.dropped.get();
    }

    @Override
    public void close() {
        if (shipper != null) shipper.close();
    }

    /** One operation in flight. Closed with try-with-resources. */
    public static final class InnerSpan implements AutoCloseable {
        private final OpticTraceSpans owner;
        private final String name;
        private final String kind;
        private final long startNanos;
        private final Instant startedAt;
        private final String traceId;
        private final String spanId;
        private final String parentSpanId;
        private final Map<String, String> attrs = new LinkedHashMap<>();
        private String failure;
        private boolean ended;

        private InnerSpan(OpticTraceSpans owner, String name, String kind) {
            this.owner = owner;
            this.name = name;
            this.kind = kind;
            this.startNanos = System.nanoTime();
            this.startedAt = Instant.now();
            this.spanId = TraceContext.randomHex(16);

            TraceContext ctx = TraceContext.current();
            this.traceId = ctx == null ? "" : ctx.traceId;
            String parent = ctx == null ? "" : ctx.spanId;
            Deque<String> open = OPEN.get();
            if (!open.isEmpty()) {
                parent = open.peek();
            }
            this.parentSpanId = parent;
            open.push(this.spanId);
        }

        /**
         * Attaches an attribute. Conventional keys — db.statement, db.rows,
         * cache.key, cache.hit, http.method, http.url, http.status — are what
         * the dashboard reads.
         */
        public InnerSpan set(String key, String value) {
            if (key != null && value != null) attrs.put(key, value);
            return this;
        }

        public InnerSpan setInt(String key, long value) {
            return set(key, Long.toString(value));
        }

        /**
         * Marks the operation as failed. A null throwable is a no-op.
         *
         * <p>A failed operation survives the agent's min_duration filter: "it
         * returned in 200µs" and "it returned in 200µs with an error" are not
         * the same event, and the second is the one someone is looking for.
         */
        public InnerSpan fail(Throwable t) {
            if (t != null) {
                failure = t.getClass().getSimpleName()
                        + (t.getMessage() == null ? "" : ": " + t.getMessage());
            }
            return this;
        }

        /** The span's own id, for code that needs to correlate something else to it. */
        public String spanId() {
            return spanId;
        }

        /**
         * Ends the span and queues it. Idempotent: try-with-resources plus an
         * explicit close is a natural thing to write, and must not double count.
         */
        @Override
        public void close() {
            if (ended) return;
            ended = true;

            // Pop THIS span wherever it sits rather than assuming it is on
            // top: an operation closed out of order (a stream held past its
            // enclosing block) would otherwise leave the stack wrong for
            // everything that follows it.
            OPEN.get().remove(spanId);

            if (owner.shipper == null) return;
            double ms = (System.nanoTime() - startNanos) / 1_000_000.0;

            Map<String, Object> span = new LinkedHashMap<>();
            // RFC3339 UTC — the agent parses strictly, and this SDK's Python
            // sibling had every record rejected for sending "+0530".
            span.put("start", startedAt.toString());
            span.put("service", owner.service);
            span.put("trace_id", traceId);
            span.put("span_id", spanId);
            if (!parentSpanId.isEmpty()) span.put("parent_span_id", parentSpanId);
            span.put("name", name);
            span.put("kind", kind == null ? "" : kind);
            span.put("duration_ms", ms);
            span.put("source", "java");
            if (failure != null) span.put("error", failure);
            if (!attrs.isEmpty()) span.put("attrs", attrs);
            owner.shipper.enqueue(span);
        }
    }
}
