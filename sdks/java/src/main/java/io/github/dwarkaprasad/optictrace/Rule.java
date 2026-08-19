package io.github.dwarkaprasad.optictrace;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** One compiled optic.yaml rule. */
final class Rule {

    final String name;
    final String rawPattern;
    final List<String> pathSegments;
    final Set<String> methods;          // null means every method
    final Set<String> restrict;
    final List<String> redactHeaders;   // lowercase
    final List<String> redactQueryParams;
    final List<List<String>> redactPaths;
    final Map<String, String> labels;
    final Map<String, List<List<String>>> meters;
    final Double sample;
    final boolean keepErrors;
    final Long keepSlowerThanMs;

    Rule(Map<String, Object> r, int index) {
        this.name = Engine.str(r.get("name"), "#" + index);

        Map<String, Object> match = Engine.map(r.get("match"));
        String path = Engine.str(match.get("path"), "");
        if (!path.startsWith("/")) {
            throw new IllegalArgumentException(
                    "optic.yaml rule " + name + ": match.path must start with '/'");
        }
        this.rawPattern = path;
        this.pathSegments = Engine.splitPath(path);

        List<Object> ms = Engine.list(match.get("methods"));
        if (ms.isEmpty()) {
            this.methods = null;
        } else {
            Set<String> s = new HashSet<>();
            for (Object m : ms) s.add(String.valueOf(m).toUpperCase(Locale.ROOT));
            this.methods = s;
        }

        Set<String> restrictions = new HashSet<>();
        for (Object o : Engine.list(r.get("restrict"))) restrictions.add(String.valueOf(o));
        this.restrict = restrictions;

        Map<String, Object> redact = Engine.map(r.get("redact"));
        List<String> headers = new ArrayList<>();
        for (Object o : Engine.list(redact.get("headers"))) {
            headers.add(String.valueOf(o).toLowerCase(Locale.ROOT));
        }
        this.redactHeaders = headers;

        List<String> qp = new ArrayList<>();
        for (Object o : Engine.list(redact.get("query_params"))) {
            qp.add(String.valueOf(o).toLowerCase(Locale.ROOT));
        }
        this.redactQueryParams = qp;

        List<List<String>> paths = new ArrayList<>();
        for (Object o : Engine.list(redact.get("json_fields"))) {
            paths.add(jsonPath(String.valueOf(o), name));
        }
        this.redactPaths = paths;

        Map<String, String> lbl = new LinkedHashMap<>();
        Engine.map(r.get("labels")).forEach((k, v) -> lbl.put(k, String.valueOf(v)));
        this.labels = lbl;

        Map<String, List<List<String>>> mtr = new LinkedHashMap<>();
        Engine.map(r.get("meter")).forEach((k, v) -> {
            List<List<String>> parsed = new ArrayList<>();
            for (Object p : Engine.list(v)) parsed.add(jsonPath(String.valueOf(p), name));
            mtr.put(k, parsed);
        });
        this.meters = mtr;

        Object s = r.get("sample");
        this.sample = s instanceof Number ? ((Number) s).doubleValue() : null;
        this.keepErrors = Boolean.TRUE.equals(r.get("keep_errors"));
        this.keepSlowerThanMs = duration(r.get("keep_slower_than"));
    }

    /** {@code $.a.b} to {@code [a, b]}; the {@code $.} prefix is required so a typo is a config error, not a silent no-op. */
    private static List<String> jsonPath(String spec, String rule) {
        if (!spec.startsWith("$.")) {
            throw new IllegalArgumentException(
                    "optic.yaml rule " + rule + ": json path " + spec + " must start with '$.'");
        }
        return List.of(spec.substring(2).split("\\."));
    }

    /** Go-style durations ("250ms", "1s"), because optic.yaml is written for the Go agent. */
    private static Long duration(Object o) {
        if (o == null) return null;
        String v = String.valueOf(o).trim();
        try {
            if (v.endsWith("ms")) return Long.parseLong(v.substring(0, v.length() - 2).trim());
            if (v.endsWith("s")) return (long) (Double.parseDouble(v.substring(0, v.length() - 1).trim()) * 1000);
            if (v.endsWith("m")) return (long) (Double.parseDouble(v.substring(0, v.length() - 1).trim()) * 60_000);
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("optic.yaml: cannot parse duration " + v, e);
        }
    }

    void applyTo(Policy p) {
        p.matchedRules.add(name);
        p.routePattern = rawPattern;

        // Capture flags: later rules win, which is what makes a broad default
        // plus a narrow override work.
        if (restrict.contains("request_body")) p.captureRequestBody = false;
        if (restrict.contains("response_body")) p.captureResponseBody = false;
        if (restrict.contains("headers")) p.captureHeaders = false;

        p.redactHeaders.addAll(redactHeaders);
        p.redactQueryParams.addAll(redactQueryParams);
        p.redactPaths.addAll(redactPaths);
        p.labels.putAll(labels);
        p.meters.putAll(meters);

        if (sample != null) p.sampleRate = sample;
        if (keepErrors) p.keepErrors = true;
        if (keepSlowerThanMs != null) {
            p.keepSlowerThanMs = p.keepSlowerThanMs == null
                    ? keepSlowerThanMs
                    : Math.min(p.keepSlowerThanMs, keepSlowerThanMs);
        }
    }
}
