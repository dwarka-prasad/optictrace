package com.example.shop;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.Callable;

/**
 * The async case, kept as a live regression check.
 *
 * <p>A Spring MVC async handler returns from the filter chain when the request
 * is PARKED, not when it is finished — which is the one place a plain servlet
 * {@code Filter} has a sharp edge. Recording at that moment measured 3ms for a
 * 125ms request and lost the response body, so the filter now defers to the
 * container's {@code onComplete}.
 *
 * <p>The two endpoints do identical work on different threads, so their
 * recorded durations should agree. If {@code /async} ever reads as
 * near-instant again, that regression is back.
 */
@RestController
public class AsyncProbe {

    @GetMapping("/api/v1/async")
    public Callable<Map<String, Object>> async() {
        return () -> {
            Thread.sleep(120);          // work on the async thread
            return Map.of("ok", true, "where", "async thread", "slept_ms", 120);
        };
    }

    @GetMapping("/api/v1/sync")
    public Map<String, Object> sync() throws InterruptedException {
        Thread.sleep(120);              // the same work, on the request thread
        return Map.of("ok", true, "where", "request thread", "slept_ms", 120);
    }
}
