package io.github.dwarkaprasad.optictrace;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

/**
 * Ships application log lines to OpticTrace, correlated to the span serving them.
 *
 * <pre>{@code
 * Logger.getLogger("").addHandler(new OpticTraceLogHandler("http://localhost:9095", "checkout"));
 * }</pre>
 *
 * <p>Nothing about how the application logs has to change: the span comes from
 * the ThreadLocal the filter sets, not from anything the call site passes.
 * Instrumentation you have to remember at every call site is instrumentation
 * that will be missing where it matters.
 *
 * <p>Lines emitted with no request in flight — startup, scheduled jobs — carry
 * no span. The agent decides what happens to them; by default they are dropped
 * and counted, because attaching them to whichever request happened to be
 * running would cross-attribute tenants.
 */
public final class OpticTraceLogHandler extends Handler {

    private final Shipper shipper;
    private final String service;

    public OpticTraceLogHandler(String agentUrl, String service) {
        this(agentUrl, service, 10_000, 200, java.time.Duration.ofSeconds(5));
    }

    public OpticTraceLogHandler(String agentUrl, String service, int queueSize, int batchSize,
                                java.time.Duration timeout) {
        this.service = service;
        this.shipper = new Shipper(
                agentUrl.replaceAll("/+$", "") + "/api/applogs/ingest", queueSize, batchSize, timeout);
    }

    @Override
    public void publish(LogRecord record) {
        if (!isLoggable(record)) return;
        TraceContext ctx = TraceContext.current();

        Map<String, Object> line = new LinkedHashMap<>();
        line.put("time", Instant.ofEpochMilli(record.getMillis()).toString());
        line.put("service", service);
        line.put("trace_id", ctx == null ? "" : ctx.traceId);
        line.put("span_id", ctx == null ? "" : ctx.spanId);
        line.put("level", levelName(record.getLevel()));
        line.put("message", formatMessage(record));
        line.put("source", "java");

        if (record.getThrown() != null) {
            line.put("fields", Map.of("exception", String.valueOf(record.getThrown())));
        }
        shipper.enqueue(line);
    }

    /** java.util.logging levels mapped onto the agent's severity names. */
    private static String levelName(Level level) {
        int v = level.intValue();
        if (v >= Level.SEVERE.intValue()) return "error";
        if (v >= Level.WARNING.intValue()) return "warn";
        if (v >= Level.INFO.intValue()) return "info";
        if (v >= Level.FINE.intValue()) return "debug";
        return "trace";
    }

    private String formatMessage(LogRecord record) {
        String msg = record.getMessage() == null ? "" : record.getMessage();
        Object[] params = record.getParameters();
        if (params == null || params.length == 0) return msg;
        try {
            return java.text.MessageFormat.format(msg, params);
        } catch (IllegalArgumentException e) {
            return msg;   // a message that is not a MessageFormat pattern is fine as-is
        }
    }

    public long sent() {
        return shipper.sent.get();
    }

    public long failed() {
        return shipper.failed.get();
    }

    public String lastError() {
        return shipper.lastError;
    }

    @Override
    public void flush() {
    }

    @Override
    public void close() {
        shipper.close();
    }
}
