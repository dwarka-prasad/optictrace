package io.github.dwarkaprasad.optictrace;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The decision for one request: what may be captured, what must be masked, what to label and meter. */
public final class Policy {

    private static final ObjectMapper JSON = new ObjectMapper();

    public boolean captureRequestBody;
    public boolean captureResponseBody;
    public boolean captureHeaders;
    public final int captureLimit;

    public final List<String> matchedRules = new ArrayList<>();
    public String routePattern = "";
    public double sampleRate = 1.0;
    public boolean keepErrors;
    public Long keepSlowerThanMs;

    final LinkedHashSet<String> redactHeaders = new LinkedHashSet<>();
    final LinkedHashSet<String> redactQueryParams = new LinkedHashSet<>();
    final List<List<String>> redactPaths = new ArrayList<>();
    final Map<String, String> labels = new LinkedHashMap<>();
    final Map<String, List<List<String>>> meters = new LinkedHashMap<>();

    Policy(boolean req, boolean resp, boolean headers, int limit) {
        this.captureRequestBody = req;
        this.captureResponseBody = resp;
        this.captureHeaders = headers;
        this.captureLimit = limit;
    }

    /**
     * Whether the BODY may be stored for this exchange.
     *
     * <p>Mirrors engine.Policy.KeepBody. Two details matter for parity: the
     * record is always emitted — metrics and metadata are never sampled — and
     * keep_errors means 5xx, not 4xx. A 404 is usually the client's problem and
     * counting it as an error to rescue would defeat the sampling it is meant
     * to work with.
     */
    public boolean keepBody(boolean drew, int status, double elapsedMs) {
        if (drew) return true;
        if (keepErrors && status >= 500) return true;
        return keepSlowerThanMs != null && elapsedMs >= keepSlowerThanMs;
    }

    /** Whether any tail-based rule applies, so bytes must be buffered up front. */
    public boolean tailSampled() {
        return keepErrors || keepSlowerThanMs != null;
    }

    public boolean hasMeters() {
        return !meters.isEmpty();
    }

    public Map<String, String> labelSources() {
        return labels;
    }

    /** Replace the value of every named header, keeping the key so its presence is still visible. */
    public Map<String, String> sanitizeHeaders(Map<String, String> headers) {
        Map<String, String> out = new LinkedHashMap<>();
        headers.forEach((k, v) ->
                out.put(k, redactHeaders.contains(k.toLowerCase(Locale.ROOT)) ? Engine.REDACTED : v));
        return out;
    }

    /**
     * Mask named query parameters, keeping order and keeping everything else.
     * A credential in a query string is still a credential, and it lands in the
     * recorded URL rather than a header — a separate place needing a separate rule.
     */
    public String sanitizeQuery(String query) {
        if (query == null || query.isEmpty() || redactQueryParams.isEmpty()) return query == null ? "" : query;
        StringBuilder out = new StringBuilder();
        for (String pair : query.split("&")) {
            if (out.length() > 0) out.append('&');
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            if (eq >= 0 && redactQueryParams.contains(key.toLowerCase(Locale.ROOT))) {
                out.append(key).append('=').append(Engine.REDACTED);
            } else {
                out.append(pair);
            }
        }
        return out.toString();
    }

    /** Redact a JSON body, returning the governed text. Non-JSON is summarised rather than stored. */
    public String redactBody(byte[] raw, String contentType) {
        if (raw == null || raw.length == 0) return "";
        if (contentType != null && !contentType.toLowerCase(Locale.ROOT).contains("json")) {
            return "<" + contentType + " body, " + raw.length + " bytes captured>";
        }
        try {
            JsonNode doc = JSON.readTree(raw);
            for (List<String> path : redactPaths) redactPath(doc, path);
            return JSON.writeValueAsString(doc);
        } catch (Exception e) {
            // Unparsable: describe it rather than storing bytes no rule could
            // have masked. Failing open here would defeat the whole point.
            return "<unparsable body, " + raw.length + " bytes>";
        }
    }

    /** Mask one dotted path. {@code *} is any key at one level, {@code **} any depth; arrays traverse implicitly. */
    static void redactPath(JsonNode node, List<String> path) {
        if (node == null || path.isEmpty()) return;
        if (node instanceof ArrayNode arr) {
            for (JsonNode child : arr) redactPath(child, path);
            return;
        }
        if (!(node instanceof ObjectNode obj)) return;

        String seg = path.get(0);
        List<String> rest = path.subList(1, path.size());

        if (seg.equals("**")) {
            if (!rest.isEmpty()) redactPath(obj, rest);          // may match here...
            for (String key : new ArrayList<>(iterable(obj))) {
                redactPath(obj.get(key), path);                   // ...and deeper
            }
            return;
        }
        if (seg.equals("*")) {
            for (String key : new ArrayList<>(iterable(obj))) {
                if (rest.isEmpty()) obj.put(key, Engine.REDACTED);
                else redactPath(obj.get(key), rest);
            }
            return;
        }
        if (obj.has(seg)) {
            if (rest.isEmpty()) obj.put(seg, Engine.REDACTED);
            else redactPath(obj.get(seg), rest);
        }
    }

    private static List<String> iterable(ObjectNode obj) {
        List<String> keys = new ArrayList<>();
        obj.fieldNames().forEachRemaining(keys::add);
        return keys;
    }

    /**
     * Pull numeric usage out of a response body.
     *
     * <p>Reads the RAW bytes, not the stored body: metering is independent of
     * capture, which is what lets a rule keep a prompt private while still
     * counting the tokens in it.
     */
    public Map<String, Double> extractMeters(byte[] raw) {
        Map<String, Double> out = new LinkedHashMap<>();
        if (meters.isEmpty() || raw == null || raw.length == 0) return out;
        JsonNode doc;
        try {
            doc = JSON.readTree(raw);
        } catch (Exception e) {
            return out;
        }
        meters.forEach((name, paths) -> {
            double[] acc = {0.0};
            boolean[] found = {false};
            for (List<String> p : paths) sumNumeric(doc, p, acc, found);
            if (found[0]) out.put(name, acc[0]);
        });
        return out;
    }

    static void sumNumeric(JsonNode node, List<String> path, double[] acc, boolean[] found) {
        if (node == null) return;
        if (path.isEmpty()) {
            if (node.isNumber()) {
                acc[0] += node.doubleValue();
                found[0] = true;
            }
            return;
        }
        if (node instanceof ArrayNode arr) {
            for (JsonNode child : arr) sumNumeric(child, path, acc, found);
            return;
        }
        if (!(node instanceof ObjectNode obj)) return;

        String seg = path.get(0);
        List<String> rest = path.subList(1, path.size());
        if (seg.equals("**")) {
            if (!rest.isEmpty()) sumNumeric(obj, rest, acc, found);
            obj.fieldNames().forEachRemaining(k -> sumNumeric(obj.get(k), path, acc, found));
            return;
        }
        if (seg.equals("*")) {
            obj.fieldNames().forEachRemaining(k -> sumNumeric(obj.get(k), rest, acc, found));
            return;
        }
        if (obj.has(seg)) sumNumeric(obj.get(seg), rest, acc, found);
    }

    /**
     * Resolve one label source.
     *
     * <p>Sources are {@code kind:key}, optionally followed by {@code |<regex>}
     * whose single capture group narrows the value — that is how
     * {@code header:X-Region|^([a-z]{2})-} turns ap-south-1 into ap.
     */
    public static String labelValue(String src, Map<String, String> headers, Map<String, String> query,
                                    String path, JsonNode requestBody, JsonNode responseBody) {
        int bar = src.indexOf('|');
        String spec = bar < 0 ? src : src.substring(0, bar);
        String regex = bar < 0 ? null : src.substring(bar + 1);

        int colon = spec.indexOf(':');
        String kind = colon < 0 ? spec : spec.substring(0, colon);
        String key = colon < 0 ? "" : spec.substring(colon + 1);

        String value = switch (kind) {
            case "header" -> headers.getOrDefault(key.toLowerCase(Locale.ROOT), "");
            case "query" -> query.getOrDefault(key, "");
            case "static" -> key;
            case "path" -> {
                List<String> segs = Engine.splitPath(path);
                try {
                    int idx = Integer.parseInt(key);   // 1-based, matching the Go engine
                    yield idx >= 1 && idx <= segs.size() ? segs.get(idx - 1) : "";
                } catch (NumberFormatException e) {
                    yield "";
                }
            }
            case "json" -> firstString(requestBody, key);
            case "json_response" -> firstString(responseBody, key);
            default -> "";
        };

        if (regex == null || value.isEmpty()) return value;
        Matcher m = Pattern.compile(regex).matcher(value);
        if (!m.find()) return "";
        // One capture group narrows the value; no group means "matched, keep it all".
        return m.groupCount() >= 1 ? Engine.str(m.group(1), "") : value;
    }

    /** First value at a dotted path, supporting {@code *} and {@code **}, read from the ALREADY-REDACTED body. */
    static String firstString(JsonNode doc, String spec) {
        if (doc == null || !spec.startsWith("$.")) return "";
        List<String> path = List.of(spec.substring(2).split("\\."));
        JsonNode found = firstNode(doc, path);
        if (found == null || found.isNull()) return "";
        return found.isValueNode() ? found.asText() : "";
    }

    private static JsonNode firstNode(JsonNode node, List<String> path) {
        if (node == null) return null;
        if (path.isEmpty()) return node;
        if (node instanceof ArrayNode arr) {
            for (JsonNode child : arr) {
                JsonNode hit = firstNode(child, path);
                if (hit != null) return hit;
            }
            return null;
        }
        if (!(node instanceof ObjectNode obj)) return null;

        String seg = path.get(0);
        List<String> rest = path.subList(1, path.size());
        if (seg.equals("**")) {
            if (!rest.isEmpty()) {
                JsonNode here = firstNode(obj, rest);
                if (here != null) return here;
            }
            List<String> keys = iterable(obj);
            for (String k : keys) {
                JsonNode hit = firstNode(obj.get(k), path);
                if (hit != null) return hit;
            }
            return null;
        }
        if (seg.equals("*")) {
            for (String k : iterable(obj)) {
                JsonNode hit = firstNode(obj.get(k), rest);
                if (hit != null) return hit;
            }
            return null;
        }
        return obj.has(seg) ? firstNode(obj.get(seg), rest) : null;
    }

    static ObjectMapper mapper() {
        return JSON;
    }
}
