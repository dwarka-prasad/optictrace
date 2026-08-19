package optictrace

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/tracectx"
)

// SpanFromContext returns the trace and span ids of the request being served,
// for code that wants to correlate something OpticTrace does not do for it —
// an outbound call, a queue message, a row written for audit.
//
// Returns false outside a request. Startup and background work belong to no
// request, and inventing one for them would attribute their output to whichever
// request happened to be in flight.
func SpanFromContext(ctx context.Context) (traceID, spanID string, ok bool) {
	c, found := tracectx.FromContext(ctx)
	if !found {
		return "", "", false
	}
	return c.TraceID, c.SpanID, true
}

// OutboundHeaders returns the headers to attach to a call this service makes
// downstream, so the next hop nests under this one.
//
// Carries THIS hop's span, not the caller's — forwarding the inbound header
// unchanged would make every downstream call a sibling of this request rather
// than a child, and the tree flattens into a list.
func OutboundHeaders(ctx context.Context) map[string]string {
	c, ok := tracectx.FromContext(ctx)
	if !ok {
		return nil
	}
	return map[string]string{tracectx.Header: c.Header()}
}

// LogHandler is an slog.Handler that ships log records to OpticTrace,
// correlated to the span serving them.
//
//	logger := slog.New(optictrace.NewLogHandler("http://localhost:9095", "checkout", nil))
//
// Nothing at the call site changes: the span comes from the context slog
// already passes, so an ordinary logger.InfoContext(ctx, ...) is filed against
// the exact request that produced it.
//
// Use InfoContext/ErrorContext (the ...Context variants). slog's plain Info()
// passes context.Background(), which carries no span — those lines are still
// shipped, but as orphans the agent will drop by default.
type LogHandler struct {
	// sink is SHARED by every handler derived through WithAttrs/WithGroup.
	// Copying it instead would give each derived logger its own queue with no
	// goroutine draining it, so `logger.With("k", "v")` — which is most
	// logging — would silently ship nothing.
	sink  *logSink
	level slog.Leveler
	attrs []slog.Attr
	group string
}

// logSink owns the queue, the delivery goroutine and the counters.
type logSink struct {
	service  string
	url      string
	client   *http.Client
	maxQueue int

	mu     sync.Mutex
	queue  []map[string]any
	closed bool

	// Counters rather than silence. The Python SDK swallowed every delivery
	// failure and shipped nothing for weeks while looking healthy.
	sent, failed, dropped int64
	lastErr               error

	stop chan struct{}
	done chan struct{}
}

// LogHandlerOptions configures a LogHandler. A nil value uses the defaults.
type LogHandlerOptions struct {
	Level    slog.Leveler
	MaxQueue int           // bounded, so a logging storm drops visibly instead of growing
	Flush    time.Duration // batching interval
	Timeout  time.Duration
}

// NewLogHandler builds a handler shipping to the agent's app-log endpoint.
func NewLogHandler(agentURL, service string, opts *LogHandlerOptions) *LogHandler {
	if opts == nil {
		opts = &LogHandlerOptions{}
	}
	sink := &logSink{
		service:  service,
		url:      strings.TrimRight(agentURL, "/") + "/api/applogs/ingest",
		maxQueue: orInt(opts.MaxQueue, 10_000),
		client:   &http.Client{Timeout: orDuration(opts.Timeout, 5*time.Second)},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	level := opts.Level
	if level == nil {
		level = slog.LevelInfo
	}
	go sink.run(orDuration(opts.Flush, 500*time.Millisecond))
	return &LogHandler{sink: sink, level: level}
}

func (h *LogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *LogHandler) Handle(ctx context.Context, r slog.Record) error {
	line := map[string]any{
		// RFC3339 — the agent parses strictly, and the FastAPI SDK once had
		// every record rejected for sending "+0530".
		"time":    r.Time.UTC().Format(time.RFC3339Nano),
		"service": h.sink.service,
		"level":   levelName(r.Level),
		"message": r.Message,
		"source":  "go",
	}
	if c, ok := tracectx.FromContext(ctx); ok {
		line["trace_id"] = c.TraceID
		line["span_id"] = c.SpanID
	}

	fields := map[string]string{}
	for _, a := range h.attrs {
		addAttr(fields, h.group, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		addAttr(fields, h.group, a)
		return true
	})
	if len(fields) > 0 {
		line["fields"] = fields
	}

	s := h.sink
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if len(s.queue) >= s.maxQueue {
		s.dropped++
		return nil
	}
	s.queue = append(s.queue, line)
	return nil
}

func (h *LogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LogHandler{
		sink:  h.sink, // shared on purpose — see the type comment
		level: h.level,
		attrs: append(append([]slog.Attr{}, h.attrs...), attrs...),
		group: h.group,
	}
}

func (h *LogHandler) WithGroup(name string) slog.Handler {
	group := h.group
	if name != "" {
		group = strings.TrimPrefix(h.group+"."+name, ".")
	}
	return &LogHandler{sink: h.sink, level: h.level, attrs: h.attrs, group: group}
}

func (h *logSink) run(interval time.Duration) {
	defer close(h.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			h.flush()
		case <-h.stop:
			h.flush()
			return
		}
	}
}

func (h *logSink) flush() {
	h.mu.Lock()
	batch := h.queue
	h.queue = nil
	h.mu.Unlock()
	if len(batch) == 0 {
		return
	}

	body, err := json.Marshal(batch)
	if err != nil {
		h.record(len(batch), err)
		return
	}
	resp, err := h.client.Post(h.url, "application/json", bytes.NewReader(body))
	if err != nil {
		h.record(len(batch), err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		h.record(len(batch), &httpError{resp.StatusCode})
		return
	}
	h.mu.Lock()
	h.sent += int64(len(batch))
	h.mu.Unlock()
}

func (h *logSink) record(n int, err error) {
	h.mu.Lock()
	h.failed += int64(n)
	h.lastErr = err
	h.mu.Unlock()
}

// Stats reports delivery so "is my telemetry actually arriving?" has an answer.
func (h *LogHandler) Stats() (sent, failed, dropped int64, lastErr error) {
	s := h.sink
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.failed, s.dropped, s.lastErr
}

// Close drains the queue. The last lines before a shutdown are usually the
// ones explaining it.
func (h *LogHandler) Close() error {
	s := h.sink
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	close(s.stop)
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

type httpError struct{ code int }

func (e *httpError) Error() string { return "app log ingest returned HTTP " + itoa(e.code) }

func addAttr(out map[string]string, group string, a slog.Attr) {
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	out[key] = a.Value.String()
}

// levelName maps slog levels onto the agent's severity names.
func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

func orInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func orDuration(v, fallback time.Duration) time.Duration {
	if v <= 0 {
		return fallback
	}
	return v
}

func itoa(n int) string { return strings.TrimSpace(jsonNumber(n)) }

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

var _ slog.Handler = (*LogHandler)(nil)
var _ = ext.AppLog{}
