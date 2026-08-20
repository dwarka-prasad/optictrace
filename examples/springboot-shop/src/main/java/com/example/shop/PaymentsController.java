package com.example.shop;

import io.github.dwarkaprasad.optictrace.OpticTraceSpans;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Logger;

/** The leg that handles card data. */
@RestController
public class PaymentsController {

    private static final Logger log = Logger.getLogger("com.example.shop.payments");

    private final OpticTraceSpans spans;

    public PaymentsController(OpticTraceSpans spans) {
        this.spans = spans;
    }

    @PostMapping("/api/v1/payments/charge")
    public ResponseEntity<?> charge(@RequestBody Model.ChargeRequest req) throws InterruptedException {
        // A real service logs like this while debugging and forgets to take it
        // out. The line is stored REDACTED — that is the point of running logs
        // through the same policy as payloads.
        log.fine("charging card " + req.card().number() + " for " + req.amount());
        log.info("charge requested for " + req.orderRef());

        // The acquirer call: the hop that usually owns a payment's wall clock,
        // and the one a latency chart cannot separate from the rest.
        try (OpticTraceSpans.InnerSpan sp = spans.start("http POST acquirer", "http")) {
            sp.set("http.method", "POST")
                    .set("http.url", "https://acquirer-eu.example/charge");
            Thread.sleep(ThreadLocalRandom.current().nextInt(10, 50));
            sp.setInt("http.status", 200);
        }

        if (req.amount() > 900 && Math.random() < 0.5) {
            log.severe("charge declined: limit_exceeded for " + req.orderRef());
            return ResponseEntity.status(402).body(Map.of("status", "declined", "reason", "limit_exceeded"));
        }
        if (Math.random() < 0.06) {
            log.severe("payment gateway unreachable (acquirer-eu)");
            return ResponseEntity.status(502).body(Map.of("status", "error", "reason", "gateway"));
        }

        String chargeId = "ch_" + ThreadLocalRandom.current().nextInt(10000, 99999);
        log.info("charge captured: " + chargeId);
        return ResponseEntity.ok(Map.of("status", "captured", "charge_id", chargeId, "amount", req.amount()));
    }

    @PostMapping("/api/v1/auth/login")
    public Map<String, String> login(@RequestBody Model.LoginRequest req) {
        // Nothing here may be captured — but the tenant label still resolves,
        // so the request is still attributable for billing.
        log.info("login attempt for " + req.username());
        return Map.of("token", "session-token-abc123");
    }
}
