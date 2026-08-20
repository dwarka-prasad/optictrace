package optictrace

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/tracectx"
)

// A Record covers a whole HTTP exchange. An inner span covers one operation
// INSIDE it — a query, a cache lookup, an outbound call — which is the
// difference between "this request took 300ms" and "this request took 300ms,
// 280 of them in one query".
//
// Attributes are governed on the way into the store, so a statement that
// quotes its parameters is redacted before anything is written. Pass the
// statement TEMPLATE where you can: the safest secret is the one that was
// never sent.

// spanParentKey carries the innermost span id, so operations nest.
//
// Separate from the request span in tracectx on purpose: the request span
// stays available for outbound headers and log correlation while an inner span
// is open, and a query inside a cached block should parent to the block rather
// than jumping to the request.
type spanParentKey struct{}

// SpanOptions configures a SpanRecorder. A nil value uses the defaults.
type SpanOptions struct {
	MaxQueue int           // bounded, so a burst drops visibly instead of growing
	Flush    time.Duration // batching interval
	Timeout  time.Duration
}

// SpanRecorder ships inner spans to the agent.
//
//	spans := optictrace.NewSpanRecorder("http://localhost:9095", "checkout", nil)
//	defer spans.Close()
//
//	ctx, sp := spans.Start(ctx, "db.query", "db")
//	sp.Set("db.statement", "SELECT * FROM orders WHERE id = $1")
//	defer sp.End()
//
// Shipping is fire-and-forget on a background worker: an application must
// never be slower, or fail, because its telemetry sink is unhappy.
type SpanRecorder struct {
	sink *logSink
}

// NewSpanRecorder builds a recorder shipping to the agent's span endpoint.
//
// An empty agentURL yields a recorder that does nothing — so instrumentation
// can be left in place in an environment with no agent, rather than guarded by
// an `if` at every call site.
func NewSpanRecorder(agentURL, service string, opts *SpanOptions) *SpanRecorder {
	if opts == nil {
		opts = &SpanOptions{}
	}
	if agentURL == "" {
		return &SpanRecorder{}
	}
	sink := &logSink{
		service:  service,
		url:      strings.TrimRight(agentURL, "/") + "/api/spans/ingest",
		maxQueue: orInt(opts.MaxQueue, 10_000),
		client:   &http.Client{Timeout: orDuration(opts.Timeout, 5*time.Second)},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go sink.run(orDuration(opts.Flush, 500*time.Millisecond))
	return &SpanRecorder{sink: sink}
}

// InnerSpan is one operation in flight. Not safe for concurrent use by
// several goroutines — one span is one operation, and an operation shared
// across goroutines is two operations.
type InnerSpan struct {
	rec     *SpanRecorder
	name    string
	kind    string
	start   time.Time
	trace   string
	span    string
	parent  string
	attrs   map[string]string
	failure string
	ended   bool
}

// Start opens a span for an operation and returns a context that nests
// anything started inside it.
//
// kind classifies the operation for the waterfall and the breakdown: db,
// cache, http, queue, rpc, internal. Outside a request the span has no parent
// and the agent drops it by default, which is deliberate — work that belongs
// to no request cannot be attributed to one.
func (r *SpanRecorder) Start(ctx context.Context, name, kind string) (context.Context, *InnerSpan) {
	sp := &InnerSpan{rec: r, name: name, kind: kind, start: time.Now(),
		attrs: map[string]string{}, span: tracectx.RandomHex(8)}

	if c, ok := tracectx.FromContext(ctx); ok {
		sp.trace = c.TraceID
		sp.parent = c.SpanID
	}
	// A span opened inside another parents to it, so a query inside a
	// transaction reads as nested rather than as a sibling of the request.
	if inner, ok := ctx.Value(spanParentKey{}).(string); ok && inner != "" {
		sp.parent = inner
	}
	return context.WithValue(ctx, spanParentKey{}, sp.span), sp
}

// Set attaches an attribute. Conventional keys — db.statement, db.rows,
// cache.key, cache.hit, http.method, http.url, http.status — are what the
// dashboard reads.
func (s *InnerSpan) Set(key, value string) *InnerSpan {
	if s == nil {
		return s
	}
	s.attrs[key] = value
	return s
}

// SetInt is Set for a numeric attribute, so a row count does not need
// formatting at every call site.
func (s *InnerSpan) SetInt(key string, value int64) *InnerSpan {
	return s.Set(key, strconv.FormatInt(value, 10))
}

// Fail marks the operation as failed. A nil error is a no-op, so
// `defer sp.Fail(err)` cannot be written by accident — use End for the normal
// path and Fail before it when there is an error.
//
// A failed operation survives the min_duration filter: "it returned in 200µs"
// and "it returned in 200µs with an error" are not the same event, and the
// second is the one someone is looking for.
func (s *InnerSpan) Fail(err error) *InnerSpan {
	if s == nil || err == nil {
		return s
	}
	s.failure = err.Error()
	return s
}

// End closes the span and queues it. Calling End twice is a no-op rather than
// a double count: a `defer sp.End()` alongside an explicit one in the happy
// path is a natural thing to write.
func (s *InnerSpan) End() {
	if s == nil || s.ended {
		return
	}
	s.ended = true
	if s.rec == nil || s.rec.sink == nil {
		return
	}
	dur := time.Since(s.start)

	span := map[string]any{
		// RFC3339 — the agent parses strictly, and the FastAPI SDK once had
		// every record rejected for sending "+0530".
		"start":       s.start.UTC().Format(time.RFC3339Nano),
		"service":     s.rec.sink.service,
		"trace_id":    s.trace,
		"span_id":     s.span,
		"name":        s.name,
		"kind":        s.kind,
		"duration_ms": float64(dur) / float64(time.Millisecond),
		"source":      "go",
	}
	if s.parent != "" {
		span["parent_span_id"] = s.parent
	}
	if s.failure != "" {
		span["error"] = s.failure
	}
	if len(s.attrs) > 0 {
		span["attrs"] = s.attrs
	}
	s.rec.sink.enqueue(span)
}

// Observe runs fn as a span, which is the shape most call sites want: no
// defer, no way to forget End, and the error is recorded automatically.
//
//	err := spans.Observe(ctx, "db.query", "db", func(ctx context.Context) error {
//	    return db.QueryRowContext(ctx, q).Scan(&n)
//	})
func (r *SpanRecorder) Observe(ctx context.Context, name, kind string, fn func(context.Context) error) error {
	ctx, sp := r.Start(ctx, name, kind)
	err := fn(ctx)
	sp.Fail(err)
	sp.End()
	return err
}

// Stats reports delivery, so "are my spans actually arriving?" has an answer
// rather than a guess.
func (r *SpanRecorder) Stats() (sent, failed, dropped int64, lastErr error) {
	if r == nil || r.sink == nil {
		return 0, 0, 0, nil
	}
	s := r.sink
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.failed, s.dropped, s.lastErr
}

// Close flushes anything queued. Worth calling on shutdown: the last few
// spans of the last few requests are usually the interesting ones.
func (r *SpanRecorder) Close() error {
	if r == nil || r.sink == nil {
		return nil
	}
	return r.sink.close()
}

// Transport wraps an http.RoundTripper so every outbound call is recorded as a
// span AND carries this hop's traceparent.
//
// Those two belong together: a downstream call that is timed but not
// propagated shows up as a gap someone has to guess about, and one that is
// propagated but not timed leaves the caller's own view of it missing.
//
//	client := &http.Client{Transport: spans.Transport(nil)}
func (r *SpanRecorder) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripper{rec: r, base: base}
}

type roundTripper struct {
	rec  *SpanRecorder
	base http.RoundTripper
}

func (t roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, sp := t.rec.Start(req.Context(), "http "+req.Method+" "+req.URL.Host, "http")
	sp.Set("http.method", req.Method)
	// Path, not the full URL: a query string is where credentials end up, and
	// the agent's redaction cannot help with what the SDK chose to send.
	sp.Set("http.url", req.URL.Scheme+"://"+req.URL.Host+req.URL.Path)

	// The request must not be mutated — a caller may reuse it — so propagation
	// goes onto a shallow clone, the same discipline the proxy applies to the
	// forwarded copy.
	out := req.Clone(ctx)
	for k, v := range OutboundHeaders(req.Context()) {
		out.Header.Set(k, v)
	}

	resp, err := t.base.RoundTrip(out)
	if err != nil {
		sp.Fail(err)
	} else {
		sp.SetInt("http.status", int64(resp.StatusCode))
		if resp.StatusCode >= 400 {
			// A 500 from a dependency is a failure of this operation even
			// though RoundTrip returned no error.
			sp.Fail(fmt.Errorf("upstream returned %d", resp.StatusCode))
		}
	}
	sp.End()
	return resp, err
}
