package com.example.shop;

import io.github.dwarkaprasad.optictrace.OpticTraceSpans;
import io.github.dwarkaprasad.optictrace.OpticTraceSpans.InnerSpan;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * The data layer, with each operation recorded as a span.
 *
 * <p>Instrumentation lives HERE rather than in the controllers, which is the
 * whole point: one place per kind of operation, and every caller gets the
 * breakdown without knowing it exists.
 */
@Repository
public class ProductRepository {

    private final JdbcTemplate jdbc;
    private final OpticTraceSpans spans;

    /** A stand-in for Redis. Real enough to produce hits, misses and a key. */
    private final Map<String, Model.Product> cache = new ConcurrentHashMap<>();

    public ProductRepository(JdbcTemplate jdbc, OpticTraceSpans spans) {
        this.jdbc = jdbc;
        this.spans = spans;
    }

    public Optional<Model.Product> find(String sku) {
        // The cache lookup is its own span. It is usually sub-millisecond,
        // which is exactly why telemetry.spans.min_duration exists — but a
        // MISS in front of a slow query is the pair worth seeing together.
        try (InnerSpan sp = spans.start("cache.get product", "cache")) {
            sp.set("cache.key", "product:" + sku);
            Model.Product hit = cache.get(sku);
            sp.set("cache.hit", String.valueOf(hit != null));
            if (hit != null) {
                return Optional.of(hit);
            }
        }

        try (InnerSpan sp = spans.start("db.query products", "db")) {
            // The TEMPLATE, not the interpolated statement: the safest secret
            // is the one that was never sent. The agent redacts what does
            // arrive, but it cannot un-send it.
            sp.set("db.system", "h2").set("db.statement",
                    "SELECT sku, name, price, stock FROM products WHERE sku = ?");
            List<Model.Product> rows = jdbc.query(
                    "SELECT sku, name, price, stock FROM products WHERE sku = ?",
                    (rs, i) -> new Model.Product(rs.getString("sku"), rs.getString("name"),
                            rs.getDouble("price"), rs.getInt("stock")),
                    sku);
            sp.setInt("db.rows", rows.size());
            if (rows.isEmpty()) {
                return Optional.empty();
            }
            cache.put(sku, rows.get(0));
            return Optional.of(rows.get(0));
        }
    }

    /**
     * Deliberately an N+1: one query per line rather than one for all of them.
     *
     * <p>Left in because it is what a breakdown is for. On the dashboard it
     * shows as a single named operation with a per-request multiplier far above
     * one, which is the shape no latency chart can show you.
     */
    public Map<String, Integer> stockFor(List<String> skus) {
        Map<String, Integer> out = new HashMap<>();
        for (String sku : skus) {
            try (InnerSpan sp = spans.start("db.query stock", "db")) {
                sp.set("db.system", "h2")
                        .set("db.statement", "SELECT stock FROM products WHERE sku = ?");
                List<Integer> rows = jdbc.query("SELECT stock FROM products WHERE sku = ?",
                        (rs, i) -> rs.getInt(1), sku);
                sp.setInt("db.rows", rows.size());
                rows.stream().findFirst().ifPresent(v -> out.put(sku, v));
            }
        }
        return out;
    }

    /** Writes the order, and shows what an interpolated statement looks like. */
    public void saveOrder(String ref, String sku, int qty, double amount, String email) {
        try (InnerSpan sp = spans.start("db.insert order", "db")) {
            sp.set("db.system", "h2");
            // An interpolated statement, as a driver logging its own SQL would
            // produce: the customer's email is now IN the attribute. Stored
            // [REDACTED] because telemetry.spans.redact catches it — which is
            // the reason span attributes are governed at all.
            sp.set("db.statement", String.format(
                    "INSERT INTO orders VALUES ('%s','%s',%d,%.2f,'%s')", ref, sku, qty, amount, email));
            jdbc.update("INSERT INTO orders (order_ref, sku, qty, amount, email) VALUES (?,?,?,?,?)",
                    ref, sku, qty, amount, email);
            sp.setInt("db.rows", 1);

            // A transaction-shaped nested span, so the waterfall has depth to
            // draw: this runs INSIDE the insert's span and parents to it.
            try (InnerSpan idx = spans.start("db.index refresh", "db")) {
                idx.set("db.statement", "ANALYZE TABLE orders");
                sleep(ThreadLocalRandom.current().nextInt(1, 4));
            }
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
