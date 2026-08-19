// Package proxy provides OpticTrace's interception layer in two flavors that
// share one code path:
//
//  1. Standalone reverse-proxy sidecar (NewReverseProxy): OpticTrace listens
//     on service.listen and forwards to service.upstream.
//  2. Embedded middleware (Interceptor.Wrap): drop OpticTrace in front of any
//     http.Handler inside an existing Go application.
//
// Per exchange, one canonical store.Record is built after governance
// (restriction, redaction, sampling) and fanned out to the configured sinks:
// structured console log, Prometheus collector, async payload store.
//
// Performance posture: the policy is resolved once per request *before* any
// capture machinery is attached, so routes that restrict capture pay almost
// nothing — no body buffering, no header copying. Captured bodies are bounded
// by capture_limit_bytes; the full stream always reaches the client untouched.
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/export"
	"github.com/dwarka-prasad/optictrace/internal/metrics"
	"github.com/dwarka-prasad/optictrace/internal/store"
	"github.com/dwarka-prasad/optictrace/internal/tracectx"
)

// Interceptor evaluates governance rules around an inner handler and emits
// telemetry to its sinks. The engine is swappable at runtime (hot reload).
type Interceptor struct {
	engine     atomic.Pointer[engine.Engine]
	logger     *slog.Logger
	name       string
	consoleLog bool

	collector  *metrics.Collector // nil = metrics disabled
	writer     *store.AsyncWriter // nil = storage disabled
	dispatcher *export.Dispatcher // nil = no exporters configured

	// gqlPaths are the path globs whose request bodies carry a GraphQL
	// operation name. Empty means the GraphQL path is never taken.
	gqlPaths [][]string
	// bodyPaths are the path globs of rules that read the request body — a
	// body criterion or a json: label. Computed from the engine so only those
	// routes buffer, and a config without body rules pays nothing.
	bodyPaths atomic.Pointer[[][]string]
	needsResp atomic.Bool

	// trace controls whether a traceparent is written anywhere. Recording ids
	// is unconditional; writing a header is not.
	propagate      bool
	responseHeader string
}

// Option configures optional telemetry sinks.
type Option func(*Interceptor)

// WithMetrics attaches a Prometheus collector.
func WithMetrics(c *metrics.Collector) Option {
	return func(ic *Interceptor) { ic.collector = c }
}

// WithStore attaches the async payload store.
func WithStore(w *store.AsyncWriter) Option {
	return func(ic *Interceptor) { ic.writer = w }
}

// WithExporters attaches the output-plugin dispatcher.
func WithExporters(d *export.Dispatcher) Option {
	return func(ic *Interceptor) { ic.dispatcher = d }
}

func NewInterceptor(cfg *config.Config, eng *engine.Engine, logger *slog.Logger, opts ...Option) *Interceptor {
	ic := &Interceptor{
		logger:     logger,
		name:       cfg.Service.Name,
		consoleLog: config.Bool(cfg.Telemetry.ConsoleLog),
	}
	for _, g := range cfg.Service.GraphQLPaths {
		ic.gqlPaths = append(ic.gqlPaths, engine.SplitPath(g))
	}
	ic.propagate = cfg.Service.Trace.Propagate()
	ic.responseHeader = cfg.Service.Trace.ResponseHeader
	ic.engine.Store(eng)
	ic.refreshBodyNeeds(eng)
	for _, o := range opts {
		o(ic)
	}
	return ic
}

// refreshBodyNeeds recomputes which routes must buffer a body. Called on
// construction and on every engine swap, so adding a body rule and reloading
// takes effect — the failure that #20 records for graphql_paths.
func (ic *Interceptor) refreshBodyNeeds(eng *engine.Engine) {
	paths := eng.BodyRulePaths()
	ic.bodyPaths.Store(&paths)
	ic.needsResp.Store(eng.NeedsResponseBody())
}

// needsRequestBody reports whether any rule reads the body on this path.
func (ic *Interceptor) needsRequestBody(urlPath string) bool {
	p := ic.bodyPaths.Load()
	if p == nil || len(*p) == 0 {
		return false
	}
	segs := engine.SplitPath(urlPath)
	for _, g := range *p {
		if engine.MatchSegments(g, segs) {
			return true
		}
	}
	return false
}

// SwapEngine atomically replaces the rule engine — the heart of config hot
// reload. In-flight requests finish under the policy they started with.
func (ic *Interceptor) SwapEngine(eng *engine.Engine) {
	ic.engine.Store(eng)
	ic.refreshBodyNeeds(eng)
}

// NewReverseProxy builds the standalone sidecar handler: interception wrapped
// around a single-host reverse proxy pointed at service.upstream.
func NewReverseProxy(cfg *config.Config, eng *engine.Engine, logger *slog.Logger, opts ...Option) (http.Handler, *Interceptor, error) {
	upstream, err := url.Parse(cfg.Service.Upstream)
	if err != nil {
		return nil, nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream error", "path", r.URL.Path, "error", err)
		w.WriteHeader(http.StatusBadGateway)
	}
	ic := NewInterceptor(cfg, eng, logger, opts...)
	return ic.Wrap(rp), ic, nil
}

// Wrap is the embedded-middleware entry point.
func (ic *Interceptor) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Resolve trace context first: every record carries it, so a request
		// that fans out across services can be reassembled afterwards.
		tc := tracectx.FromHeader(r.Header.Get(tracectx.Header))
		if ic.propagate {
			// The forwarded request carries THIS hop's traceparent — same
			// trace, our span id as the parent for whatever comes next.
			//
			// Always, not only when the caller sent nothing. Forwarding the
			// caller's header unchanged makes every downstream hop a sibling
			// of this one instead of a child, so the tree comes out flat and
			// the fan-out is unreadable. Rewriting it is what a tracing
			// sidecar is for, and an application doing its own tracing simply
			// nests under this span rather than being contradicted by it.
			//
			// Scoped deliberately: the forwarded copy only. The response and
			// the client's own request are untouched.
			r.Header.Set(tracectx.Header, tc.Header())
		}
		if ic.responseHeader != "" {
			w.Header().Set(ic.responseHeader, tc.TraceID)
		}
		// Publish the span on the request context so an embedded handler — and
		// anything it calls, including a log handler — can name the request it
		// is serving without reading headers back out.
		r = r.WithContext(tracectx.NewContext(r.Context(), tc))
		// Full attrs, not just the request line: match.headers and match.query
		// rules can only be decided with them, and a rule that cannot be
		// decided does not apply.
		policy := ic.engine.Load().EvaluateAttrs(engine.AttrsOf(r))
		// Re-publish with the resolved route now that the policy is known: a
		// per-rule `logs:` block keys on it, and the handler's log lines need
		// to carry it.
		if policy.RoutePattern != "" {
			tc.Route = policy.RoutePattern
			r = r.WithContext(tracectx.NewContext(r.Context(), tc))
		}

		// Uniform sampling draw, made up front. Tail-based rules can rescue
		// a request this draw discarded, but only once the outcome is known
		// — so when they're configured we buffer regardless and decide in
		// emit(). Metrics and metadata are never sampled.
		drew := policy.SampleRate >= 1.0 || rand.Float64() < policy.SampleRate
		buffer := drew || policy.TailSampled()

		// GraphQL puts every operation on one path, so the operation name is
		// the only thing that distinguishes them — and it lives in the body.
		// Buffer it here even when the sampling draw or a restriction would
		// otherwise skip capture: the name is needed for the route label and
		// for rules that target an operation. What gets STORED is still
		// decided by policy below, so this changes what we can see, not what
		// we keep.
		gql := ic.isGraphQL(r.URL.Path)
		// Same reasoning for body-tagged routes: the discriminator lives in
		// the payload, so it has to be read even when the sampling draw or a
		// restriction would skip capture. What gets STORED is still decided by
		// policy — this changes what we can see, not what we keep.
		needBody := gql || ic.needsRequestBody(r.URL.Path)
		if needBody {
			buffer = true
		}

		if ic.collector != nil {
			ic.collector.InflightInc()
			defer ic.collector.InflightDec()
		}

		// --- Request-side capture (tee, never consume) -------------------
		var reqBuf *limitedBuffer
		if buffer && (policy.CaptureRequestBody || needBody) && r.Body != nil {
			reqBuf = &limitedBuffer{limit: policy.CaptureLimitBytes}
			r.Body = &teeReadCloser{rc: r.Body, tee: reqBuf}
		}

		// --- Response-side capture (wrap the writer) ---------------------
		// Meters need response bytes even when body *storage* is restricted
		// or sampled out — the buffer is then used for extraction only.
		rw := &recordingWriter{ResponseWriter: w, status: http.StatusOK}
		if ic.collector != nil {
			rw.onStream = ic.collector.StreamOpened
		}
		if (buffer && policy.CaptureResponseBody) || len(policy.Meters) > 0 || ic.needsResp.Load() {
			rw.buf = &limitedBuffer{limit: policy.CaptureLimitBytes}
		}

		next.ServeHTTP(rw, r)
		if rw.streamNoted {
			ic.collector.StreamClosed()
		}

		elapsed := time.Since(start)
		if rw.hijacked && !rw.wroteHeader && isUpgrade(r) {
			// ReverseProxy writes the 101 straight to the hijacked connection,
			// so WriteHeader is never called on this wrapper. Record what
			// actually happened rather than the 200 we initialised with.
			rw.status = http.StatusSwitchingProtocols
		}
		// Re-resolve policy now that the operation is known. Sound because
		// governance applies to telemetry, not to the traffic itself — the
		// response has already gone to the client untouched either way.
		operation := ""
		var governedBody any
		bodyKnown := false
		if needBody && reqBuf != nil {
			if gql {
				operation = graphQLOperation(reqBuf.Bytes())
			}
			// Redact FIRST, then decide. A criterion or label reading a
			// redacted field would otherwise route straight around the rule
			// redacting it — the body is governed before anything looks at it.
			governedBody, bodyKnown = governedJSON(reqBuf, r.Header.Get("Content-Type"), &policy)
		}
		if operation != "" || bodyKnown {
			a := engine.AttrsOf(r)
			a.Operation = operation
			a.Body, a.BodyKnown = governedBody, bodyKnown
			policy = ic.engine.Load().EvaluateAttrs(a)
		}
		keep := policy.KeepBody(drew, rw.status, elapsed)
		ic.emit(r, rw, reqBuf, &policy, keep, elapsed, operation, governedBody, tc)
	})
}

// streamMinDuration is how long a repeatedly-flushed response must last before
// it counts as a stream rather than a slow one. SSE is recognised by content
// type regardless; this catches chunked streaming that does not announce
// itself. A second or more of incremental flushing is not a request/response
// exchange in any useful sense.
const streamMinDuration = time.Second

// isStream reports whether this exchange was a long-lived stream rather than a
// request/response pair. The distinction matters because a 10-minute SSE
// connection would otherwise land in the latency histogram as a single
// 600,000 ms observation and make the route's p95 meaningless.
func isStream(rw *recordingWriter, elapsed time.Duration) bool {
	if rw.hijacked {
		// A protocol upgrade (WebSocket) is a connection, not an exchange.
		// Its "duration" is however long the client stayed connected.
		return true
	}
	if isEventStream(rw.Header().Get("Content-Type")) {
		return true // definitive: SSE
	}
	return rw.flushes >= 2 && elapsed >= streamMinDuration
}

// isEventStream matches the SSE content type, ignoring any parameters.
func isEventStream(ct string) bool {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

// isUpgrade reports whether the client asked to switch protocols.
func isUpgrade(r *http.Request) bool {
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	return r.Header.Get("Upgrade") != ""
}

// emit builds the canonical record and fans it out to the sinks. keep is the
// final body-retention decision (uniform draw, possibly rescued by tail rules).
// isGraphQL reports whether this path is configured as a GraphQL endpoint.
func (ic *Interceptor) isGraphQL(urlPath string) bool {
	if len(ic.gqlPaths) == 0 {
		return false
	}
	segs := engine.SplitPath(urlPath)
	for _, g := range ic.gqlPaths {
		if engine.MatchSegments(g, segs) {
			return true
		}
	}
	return false
}

// governedJSON redacts a buffered JSON body under the policy and parses the
// result, so criteria and labels only ever see what governance permits.
func governedJSON(buf *limitedBuffer, contentType string, p *engine.Policy) (any, bool) {
	if buf == nil || !strings.Contains(strings.ToLower(contentType), "json") {
		return nil, false
	}
	raw := buf.Bytes()
	if red, ok := p.RedactJSONBody(raw); ok {
		raw = red
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		// A truncated or non-JSON payload is not an error worth failing over;
		// body rules simply do not match it.
		return nil, false
	}
	return doc, true
}

func (ic *Interceptor) emit(r *http.Request, rw *recordingWriter, reqBuf *limitedBuffer, p *engine.Policy, keep bool, elapsed time.Duration, operation string, reqBody any, tc tracectx.Context) {
	route := p.RoutePattern
	if route == "" {
		route = engine.NormalizeRoute(r.URL.Path)
	}
	if operation != "" {
		// One route per operation. Cardinality stays bounded because the name
		// is validated as a plain identifier and capped in length, and the
		// collector's existing label guard covers the rest.
		route += ":" + operation
	}

	stream := isStream(rw, elapsed)

	rec := &store.Record{
		Time:         time.Now(),
		Service:      ic.name,
		Method:       r.Method,
		Path:         r.URL.Path,
		Route:        route,
		Status:       rw.status,
		DurationMS:   float64(elapsed) / float64(time.Millisecond),
		Remote:       r.RemoteAddr,
		Source:       "proxy",
		ReqBytes:     requestSize(r, reqBuf),
		RespBytes:    rw.written,
		MatchedRules: p.MatchedRules,
		Stream:       stream,
		TraceID:      tc.TraceID,
		SpanID:       tc.SpanID,
		ParentSpanID: tc.ParentSpanID,
	}

	if p.CaptureHeaders {
		rec.RequestHeaders = p.SanitizeHeaders(r.Header)
		rec.ResponseHeaders = p.SanitizeHeaders(rw.Header())
	}
	if p.CaptureQuery {
		rec.Query = p.SanitizeQuery(r.URL.RawQuery)
	}
	if keep && reqBuf != nil {
		rec.RequestBody, rec.ReqTruncated = renderBody(reqBuf, r.Header.Get("Content-Type"), p)
	}
	if rw.buf != nil {
		// Meters read the raw buffer; the body is only STORED when capture
		// policy and the sampling decision both allow it.
		rec.Meters = p.ExtractMeters(rw.buf.Bytes())
		if keep && p.CaptureResponseBody {
			rec.ResponseBody, rec.RespTruncated = renderBody(rw.buf, rw.Header().Get("Content-Type"), p)
		}
	}
	if len(p.Labels) > 0 {
		// Response-body labels are parsed lazily and once, only if some label
		// actually asks for one.
		var respBody any
		respParsed := false
		rec.Labels = make(map[string]string, len(p.Labels))
		for name, src := range p.Labels {
			switch {
			case src.Kind == "json":
				rec.Labels[name] = src.ValueFromBody(reqBody)
			case src.Kind == "json_response":
				if !respParsed {
					respBody, _ = governedJSON(rw.buf, rw.Header().Get("Content-Type"), p)
					respParsed = true
				}
				rec.Labels[name] = src.ValueFromBody(respBody)
			default:
				rec.Labels[name] = src.Value(r)
			}
		}
	}

	if ic.collector != nil {
		ic.collector.Observe(metrics.Observation{
			Method: rec.Method, Route: rec.Route, Status: rec.Status,
			Duration: elapsed, ReqBytes: rec.ReqBytes, RespBytes: rec.RespBytes,
			Labels: rec.Labels, Stream: stream,
		})
	}
	if ic.writer != nil {
		ic.writer.Enqueue(rec)
	}
	if ic.dispatcher != nil {
		ic.dispatcher.Enqueue(rec)
	}
	if ic.consoleLog {
		ic.logRecord(r, rec)
	}
}

func (ic *Interceptor) logRecord(r *http.Request, rec *store.Record) {
	attrs := []slog.Attr{
		slog.String("service", rec.Service),
		slog.String("method", rec.Method),
		slog.String("path", rec.Path),
		slog.Int("status", rec.Status),
		slog.Int64("duration_ms", int64(rec.DurationMS)),
		slog.Int64("response_bytes", rec.RespBytes),
		slog.String("remote", rec.Remote),
	}
	if rec.Query != "" {
		attrs = append(attrs, slog.String("query", rec.Query))
	}
	if len(rec.MatchedRules) > 0 {
		attrs = append(attrs, slog.Any("matched_rules", rec.MatchedRules))
	}
	if rec.RequestHeaders != nil {
		attrs = append(attrs,
			slog.Any("request_headers", rec.RequestHeaders),
			slog.Any("response_headers", rec.ResponseHeaders))
	}
	if rec.RequestBody != "" {
		attrs = append(attrs, bodyLogAttr("request_body", rec.RequestBody))
	}
	if rec.ResponseBody != "" {
		attrs = append(attrs, bodyLogAttr("response_body", rec.ResponseBody))
	}
	if len(rec.Labels) > 0 {
		attrs = append(attrs, slog.Any("labels", rec.Labels))
	}
	ic.logger.LogAttrs(r.Context(), slog.LevelInfo, "http_exchange", attrs...)
}

// bodyLogAttr keeps valid JSON bodies structured in the console output
// instead of double-escaping them as strings.
func bodyLogAttr(key, body string) slog.Attr {
	if json.Valid([]byte(body)) {
		return slog.Any(key, json.RawMessage(body))
	}
	return slog.String(key, body)
}

// renderBody turns a captured body into its stored representation: JSON is
// redacted per policy; other content types are summarized, never dumped raw.
func renderBody(buf *limitedBuffer, contentType string, p *engine.Policy) (body string, truncated bool) {
	data := buf.Bytes()
	if len(data) == 0 {
		return "", false
	}
	if strings.Contains(contentType, "json") {
		if redacted, ok := p.RedactJSONBody(data); ok {
			return string(redacted), buf.truncated
		}
	}
	return "<" + contentType + " body, " + strconv.Itoa(len(data)) + " bytes captured>", buf.truncated
}

func requestSize(r *http.Request, reqBuf *limitedBuffer) int64 {
	if r.ContentLength > 0 {
		return r.ContentLength
	}
	if reqBuf != nil {
		return reqBuf.total
	}
	return 0
}

// --- capture plumbing -------------------------------------------------------

// limitedBuffer records at most `limit` bytes and discards the rest, so a
// 2 GB upload can stream through while telemetry stays bounded.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	total     int64
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.total += int64(len(p))
	if remaining := l.limit - int64(l.buf.Len()); remaining > 0 {
		if int64(len(p)) > remaining {
			l.buf.Write(p[:remaining])
			l.truncated = true
		} else {
			l.buf.Write(p)
		}
	} else if len(p) > 0 {
		l.truncated = true
	}
	return len(p), nil // report full write: we're a tap, not a bottleneck
}

func (l *limitedBuffer) Bytes() []byte { return l.buf.Bytes() }

// teeReadCloser mirrors everything the inner handler reads from the request
// body into the capture buffer, without altering read semantics.
type teeReadCloser struct {
	rc  io.ReadCloser
	tee io.Writer
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.tee.Write(p[:n]) //nolint:errcheck // limitedBuffer never fails
	}
	return n, err
}

func (t *teeReadCloser) Close() error { return t.rc.Close() }

// recordingWriter captures status code, byte count, and (optionally) a bounded
// copy of the response body while streaming everything to the real writer.
type recordingWriter struct {
	http.ResponseWriter
	status      int
	written     int64
	wroteHeader bool
	buf         *limitedBuffer // nil when response capture is restricted
	// flushes counts explicit Flush calls. A handler that flushes repeatedly
	// is streaming, which is how SSE-by-any-content-type is recognised.
	flushes int
	// hijacked records that the connection was taken over (a protocol
	// upgrade). Nothing after that point is observable through this writer.
	hijacked bool
	// onStream fires once, when the response headers identify a stream.
	onStream    func()
	streamNoted bool
}

func (w *recordingWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
		// SSE announces itself in the response headers, so a stream can be
		// counted while it is open rather than only once it ends — which for
		// a long-lived connection is the difference between seeing it and
		// not. Streams that never set the content type are still classified
		// at the end, they just don't move the live gauge.
		if w.onStream != nil && isEventStream(w.Header().Get("Content-Type")) {
			w.streamNoted = true
			w.onStream()
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.written += int64(n)
	if w.buf != nil && n > 0 {
		w.buf.Write(p[:n]) //nolint:errcheck
	}
	return n, err
}

// Flush passes through so streaming upstreams (SSE, chunked) keep working.
func (w *recordingWriter) Flush() {
	w.flushes++
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack surrenders the connection, which is how protocol upgrades
// (WebSocket) work.
//
// Without this method the wrapper is not an http.Hijacker, and because it
// embeds ResponseWriter as an *interface* it does not promote one either.
// httputil.ReverseProxy's upgrade path asks http.NewResponseController for
// the raw connection, gets ErrNotSupported, and hands the request to the
// error handler — which turned every WebSocket upgrade into a 502. The
// upgrade was not passing through uninspected, as the docs claimed; it was
// failing outright.
//
// Once hijacked, bytes flow directly between client and upstream and are
// invisible to us. That is the correct trade: the alternative is buffering a
// long-lived bidirectional stream in memory. We record the exchange up to the
// upgrade and stop there.
func (w *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, brw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, brw, err
}

// Unwrap exposes the wrapped writer to http.ResponseController, so controller
// methods this type does not implement explicitly — SetReadDeadline,
// SetWriteDeadline, and anything added in future Go releases — keep working
// through the wrapper instead of silently returning ErrNotSupported.
func (w *recordingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
