package com.example.shop;

import io.github.dwarkaprasad.optictrace.TraceContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.logging.Logger;

/**
 * The composite endpoint: one inbound call fans out to catalog and payments.
 *
 * <p>Those two legs are real HTTP calls back into this same process, so the
 * agent records three spans per checkout. They share a trace id only because
 * {@link TraceContext#outboundHeaders()} is copied onto each outbound request —
 * that is the whole contribution the application has to make.
 */
@RestController
public class CheckoutController {

    private static final Logger log = Logger.getLogger("com.example.shop.checkout");

    private final RestTemplate http;
    private final HttpServletRequest inbound;

    public CheckoutController(RestTemplate http, HttpServletRequest inbound) {
        this.http = http;
        this.inbound = inbound;   // a Spring request-scoped proxy
    }

    @PostMapping("/api/v1/orders")
    public ResponseEntity<?> createOrder(@RequestBody Model.OrderRequest req) {
        TraceContext ctx = TraceContext.current();
        log.info("order received for " + req.sku() + " x" + req.qty()
                + (ctx == null ? "" : " (trace " + ctx.traceId + ")"));

        Model.Product product;
        try {
            product = http.exchange(
                    "http://127.0.0.1:8080/api/v1/catalog/" + req.sku(),
                    HttpMethod.GET, new HttpEntity<>(propagate()), Model.Product.class).getBody();
        } catch (HttpStatusCodeException e) {
            log.warning("catalog rejected sku " + req.sku() + ": " + e.getStatusCode());
            return ResponseEntity.status(404).body(Map.of("error", "unknown sku", "sku", req.sku()));
        }

        if (product == null || product.stock() < req.qty()) {
            log.warning("insufficient stock for " + req.sku());
            return ResponseEntity.status(409).body(Map.of("error", "out of stock", "sku", req.sku()));
        }

        double amount = product.price() * req.qty();
        String orderRef = "ord_" + Math.abs(req.customer().email().hashCode() % 100000);
        log.info("charging " + amount + " for " + orderRef);

        ResponseEntity<Map> charge;
        try {
            charge = http.exchange(
                    "http://127.0.0.1:8080/api/v1/payments/charge", HttpMethod.POST,
                    new HttpEntity<>(new Model.ChargeRequest(amount, req.card(), orderRef), propagate()),
                    Map.class);
        } catch (HttpStatusCodeException e) {
            log.severe("payment failed for " + orderRef + ": " + e.getStatusCode());
            return ResponseEntity.status(e.getStatusCode())
                    .body(Map.of("error", "payment failed", "order_ref", orderRef));
        }

        log.info("order confirmed: " + orderRef);
        return ResponseEntity.status(201).body(Map.of(
                "order_ref", orderRef,
                "sku", product.sku(),
                "qty", req.qty(),
                "amount", amount,
                "charge", charge.getBody()));
    }

    /**
     * Copies the current span onto an outbound call so the legs join up, plus
     * the tenant context.
     *
     * <p>The trace headers are what OpticTrace needs; the tenant headers are
     * what the {@code labels:} block in optic.yaml reads. Without them the
     * inner legs record with an empty tenant, so the usage page bills the
     * customer for the checkout but not for the work the checkout caused.
     */
    private HttpHeaders propagate() {
        HttpHeaders h = new HttpHeaders();
        TraceContext.outboundHeaders().forEach(h::set);
        for (String name : new String[]{"X-Tenant-ID", "X-Region", "X-Plan"}) {
            String v = inbound.getHeader(name);
            if (v != null) h.set(name, v);
        }
        return h;
    }
}
