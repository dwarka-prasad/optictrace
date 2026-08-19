package io.github.dwarkaprasad.optictrace;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Delivers governed records and log lines to the agent.
 *
 * <p>Never throws into the application: telemetry must not be able to fail a
 * request. But it never succeeds silently either — failures are counted and
 * the last one is kept, so "is my telemetry actually arriving?" has an answer.
 * The Python SDK swallowed every failure with a bare except and shipped
 * nothing at all for weeks while looking perfectly healthy. Silence was the
 * bug; the malformed timestamp was only the trigger.
 */
public final class Shipper implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();
    private final URI endpoint;
    private final Duration timeout;
    private final BlockingQueue<Object> queue;
    private final Thread worker;
    private final int batchSize;
    private volatile boolean running = true;

    public final AtomicLong sent = new AtomicLong();
    public final AtomicLong failed = new AtomicLong();
    public final AtomicLong dropped = new AtomicLong();
    public volatile String lastError;

    public Shipper(String url, int queueSize, int batchSize, Duration timeout) {
        this.endpoint = URI.create(url);
        this.timeout = timeout;
        this.batchSize = batchSize;
        this.queue = new ArrayBlockingQueue<>(queueSize);
        this.worker = new Thread(this::run, "optictrace-shipper");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    /**
     * Queue one payload. Bounded on purpose: a logging storm costs a bounded
     * amount of memory and then drops visibly, rather than growing until the
     * process dies.
     */
    public void enqueue(Object payload) {
        if (!queue.offer(payload)) dropped.incrementAndGet();
    }

    private void run() {
        List<Object> batch = new java.util.ArrayList<>();
        while (running || !queue.isEmpty()) {
            try {
                Object first = queue.poll(250, java.util.concurrent.TimeUnit.MILLISECONDS);
                if (first == null) continue;
                batch.add(first);
                queue.drainTo(batch, batchSize - 1);
                post(batch);
                batch.clear();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    /** A single item posts as an object; several post as an array — the agent accepts both. */
    private void post(List<Object> batch) {
        try {
            Object payload = batch.size() == 1 ? batch.get(0) : batch;
            HttpRequest req = HttpRequest.newBuilder(endpoint)
                    .timeout(timeout)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(payload)))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 300) {
                failed.addAndGet(batch.size());
                String body = resp.body();
                lastError = "HTTP " + resp.statusCode() + ": "
                        + body.substring(0, Math.min(200, body.length()));
            } else {
                sent.addAndGet(batch.size());
            }
        } catch (Exception e) {
            failed.addAndGet(batch.size());
            lastError = e.toString();
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        running = false;
        try {
            worker.join(timeout.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
