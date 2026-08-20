package com.example.shop;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.logging.Logger;

/** Product lookups — the hot, sampled read path. */
@RestController
public class CatalogController {

    private static final Logger log = Logger.getLogger("com.example.shop.catalog");

    private final ProductRepository products;

    public CatalogController(ProductRepository products) {
        this.products = products;
    }

    @GetMapping("/api/v1/catalog/{sku}")
    public ResponseEntity<?> product(@PathVariable String sku) throws InterruptedException {
        log.fine("catalog lookup for " + sku);
        Model.Product p = products.find(sku).orElse(null);
        if (p == null) {
            // An error worth keeping even on a sampled route — that is what
            // keep_errors is for.
            log.warning("unknown sku requested: " + sku);
            return ResponseEntity.status(404).body(Map.of("error", "no such product"));
        }
        if ("SKU-200".equals(sku) && Math.random() < 0.3) {
            // A slow tail, so keep_slower_than has something to rescue and the
            // latency percentiles are not a flat line.
            Thread.sleep(250);
            log.warning("slow catalog read for " + sku + " (cold cache)");
        }
        if (p.stock() == 0) {
            log.info("product out of stock: " + sku);
        }
        return ResponseEntity.ok(p);
    }

    @GetMapping("/api/v1/health")
    public Map<String, Object> health() {
        // Deliberately ungoverned by optic.yaml — this is what `optictrace scan`
        // and `suggest` exist to notice.
        return Map.of("ok", true, "service", "shop-api");
    }
}
