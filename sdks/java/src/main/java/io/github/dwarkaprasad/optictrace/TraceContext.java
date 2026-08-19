package io.github.dwarkaprasad.optictrace;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * W3C trace context.
 *
 * <p>Correlation must be a fact, not a guess. A span generated here is written
 * onto the record AND published to the application, so a log line or an
 * outbound call can name the exact request it belongs to. Matching on
 * timestamps would, under concurrent traffic, file one tenant's data inside
 * another tenant's request.
 */
public final class TraceContext {

    public static final String HEADER = "traceparent";

    private static final SecureRandom RNG = new SecureRandom();
    private static final Pattern TRACEPARENT =
            Pattern.compile("^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$");

    /**
     * The span currently being served. Inheritable so work handed to a child
     * thread stays correlated; frameworks that hop pools should propagate it
     * explicitly with {@link #set}.
     */
    private static final InheritableThreadLocal<TraceContext> CURRENT = new InheritableThreadLocal<>();

    public final String traceId;
    public final String spanId;
    public final String parentSpanId;
    public final boolean sampled;

    private TraceContext(String traceId, String spanId, String parentSpanId, boolean sampled) {
        this.traceId = traceId;
        this.spanId = spanId;
        this.parentSpanId = parentSpanId;
        this.sampled = sampled;
    }

    /**
     * Adopt an inbound traceparent, or start a fresh trace when there is not a
     * usable one. A malformed header starts a new trace rather than failing
     * anything: losing correlation is a nuisance, failing a request over a bad
     * header would be a fault.
     */
    public static TraceContext fromHeader(String raw) {
        if (raw != null) {
            Matcher m = TRACEPARENT.matcher(raw.trim());
            if (m.matches()) {
                String version = m.group(1), trace = m.group(2), parent = m.group(3);
                boolean ok = !version.equals("ff")
                        && !trace.equals("0".repeat(32))
                        && !parent.equals("0".repeat(16));
                if (ok) {
                    boolean sampled = (Integer.parseInt(m.group(4), 16) & 1) == 1;
                    return new TraceContext(trace, hex(8), parent, sampled);
                }
            }
        }
        return new TraceContext(hex(16), hex(8), "", true);
    }

    public String header() {
        return "00-" + traceId + "-" + spanId + "-" + (sampled ? "01" : "00");
    }

    public static TraceContext current() {
        return CURRENT.get();
    }

    static void set(TraceContext ctx) {
        CURRENT.set(ctx);
    }

    static void clear() {
        CURRENT.remove();
    }

    /**
     * Headers for a call this service makes downstream, so the next hop nests
     * under this one.
     *
     * <p>Carries THIS hop's span, not the caller's. Forwarding the inbound
     * header unchanged would make every downstream call a sibling of this
     * request rather than a child, and the tree flattens into a list.
     */
    public static Map<String, String> outboundHeaders() {
        TraceContext ctx = CURRENT.get();
        return ctx == null ? Map.of() : Map.of(HEADER, ctx.header());
    }

    private static String hex(int bytes) {
        byte[] b = new byte[bytes];
        RNG.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }
}
