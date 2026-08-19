package io.github.dwarkaprasad.optictrace;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * OpticTrace rule engine — Java port, semantics-identical to the Go engine.
 *
 * <p>Governance runs IN-PROCESS: a payload is restricted and redacted inside
 * the service that saw it, so sensitive values never cross a process boundary
 * in the clear. Only the governed record is shipped to the agent.
 *
 * <p>The three ports (Go, JavaScript, Python) and this one must agree on what
 * a rule means. Where they cannot — a source that needs data this middleware
 * does not have — the answer is an empty value, never a guessed one: the same
 * optic.yaml producing different Prometheus series depending on which runtime
 * served the request is worse than a missing label.
 */
public final class Engine {

    public static final String REDACTED = "[REDACTED]";

    private final String serviceName;
    private final String traceResponseHeader;
    private final boolean defaultRequestBody;
    private final boolean defaultResponseBody;
    private final boolean defaultHeaders;
    private final int captureLimit;
    private final List<Rule> rules = new ArrayList<>();

    @SuppressWarnings("unchecked")
    public Engine(Map<String, Object> cfg) {
        if (cfg == null || !Integer.valueOf(1).equals(cfg.get("version"))) {
            throw new IllegalArgumentException(
                    "optic.yaml: unsupported version " + (cfg == null ? null : cfg.get("version")));
        }
        Map<String, Object> service = map(cfg.get("service"));
        this.serviceName = str(service.get("name"), "");
        this.traceResponseHeader = str(map(service.get("trace")).get("response_header"), "");

        Map<String, Object> defaults = map(cfg.get("defaults"));
        Map<String, Object> capture = map(defaults.get("capture"));
        this.defaultRequestBody = !Boolean.FALSE.equals(capture.get("request_body"));
        this.defaultResponseBody = !Boolean.FALSE.equals(capture.get("response_body"));
        this.defaultHeaders = !Boolean.FALSE.equals(capture.get("headers"));
        Object limit = defaults.get("capture_limit_bytes");
        this.captureLimit = limit instanceof Number ? ((Number) limit).intValue() : 65536;

        List<Object> raw = list(cfg.get("rules"));
        for (int i = 0; i < raw.size(); i++) {
            rules.add(new Rule(map(raw.get(i)), i));
        }
    }

    public String serviceName() {
        return serviceName;
    }

    /**
     * Header to echo the trace id back to the caller on, or "" for none.
     *
     * <p>This is the only thread from a customer's screenshot back to the
     * record. Without it a support conversation starts at "roughly what time?",
     * which under concurrency identifies the wrong request.
     */
    public String traceResponseHeader() {
        return traceResponseHeader;
    }

    /** Evaluate every rule against a request. Later rules win on capture flags; redactions, labels and meters accumulate. */
    public Policy evaluate(String method, String urlPath) {
        Policy p = new Policy(defaultRequestBody, defaultResponseBody, defaultHeaders, captureLimit);
        List<String> segs = splitPath(urlPath);
        String upper = method == null ? "GET" : method.toUpperCase(Locale.ROOT);

        for (Rule r : rules) {
            if (r.methods != null && !r.methods.contains(upper)) continue;
            if (!matchSegments(r.pathSegments, segs)) continue;
            r.applyTo(p);
        }
        return p;
    }

    // --- path globbing -------------------------------------------------

    static List<String> splitPath(String p) {
        String t = p == null ? "" : p.replaceAll("^/+", "").replaceAll("/+$", "");
        if (t.isEmpty()) return Collections.emptyList();
        return List.of(t.split("/"));
    }

    /** Segment-wise glob: {@code *} is one segment, {@code **} is zero or more. */
    static boolean matchSegments(List<String> pattern, List<String> segs) {
        if (pattern.isEmpty()) return segs.isEmpty();
        if (pattern.get(0).equals("**")) {
            if (pattern.size() == 1) return true;
            List<String> rest = pattern.subList(1, pattern.size());
            for (int i = 0; i <= segs.size(); i++) {
                if (matchSegments(rest, segs.subList(i, segs.size()))) return true;
            }
            return false;
        }
        if (segs.isEmpty()) return false;
        if (!globSegment(pattern.get(0), segs.get(0))) return false;
        return matchSegments(pattern.subList(1, pattern.size()), segs.subList(1, segs.size()));
    }

    /**
     * Shell-style match WITHIN one segment, so {@code /api/v1/user-*} works.
     * Translated to a regex rather than hand-walked, with every regex
     * metacharacter quoted — a path segment is attacker-controlled input, and
     * a rule that matches more than it says is a governance hole.
     */
    static boolean globSegment(String pattern, String value) {
        StringBuilder re = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            switch (c) {
                case '*' -> re.append("[^/]*");
                case '?' -> re.append("[^/]");
                default -> re.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return value.matches(re.toString());
    }

    // --- helpers -------------------------------------------------------

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) {
        if (o instanceof List) return (List<Object>) o;
        if (o == null) return Collections.emptyList();
        return List.of(o);
    }

    static String str(Object o, String fallback) {
        return o == null ? fallback : String.valueOf(o);
    }
}
