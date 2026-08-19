package optictrace

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/tracectx"
)

// collect starts a stand-in agent and returns the lines it was sent.
func collect(t *testing.T) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []map[string]any
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("agent could not decode the batch: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any{}, got...)
	}
}

func TestLogHandlerCorrelatesToTheSpanBeingServed(t *testing.T) {
	srv, lines := collect(t)
	h := NewLogHandler(srv.URL, "svc", &LogHandlerOptions{Flush: 20 * time.Millisecond})
	log := slog.New(h)

	ctx := tracectx.NewContext(context.Background(), tracectx.Context{
		TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16),
	})
	log.InfoContext(ctx, "in a request", "order", "ord-1")
	log.InfoContext(context.Background(), "outside a request")

	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	got := lines()
	if len(got) != 2 {
		t.Fatalf("agent received %d line(s), want 2", len(got))
	}

	var inReq, orphan map[string]any
	for _, l := range got {
		if l["message"] == "in a request" {
			inReq = l
		} else {
			orphan = l
		}
	}
	if inReq["span_id"] != strings.Repeat("b", 16) {
		t.Errorf("line not correlated to its span: %v", inReq["span_id"])
	}
	// A line with no request behind it must NOT borrow one. Attaching it to
	// whichever request happened to be in flight cross-attributes tenants.
	if _, has := orphan["span_id"]; has {
		t.Errorf("a line emitted outside a request was given a span: %v", orphan)
	}
	fields, _ := inReq["fields"].(map[string]any)
	if fields["order"] != "ord-1" {
		t.Errorf("attrs lost: %v", inReq["fields"])
	}
}

// logger.With(...) is most logging. Deriving a handler used to copy the sink,
// so those lines went into a queue nothing ever drained and vanished silently.
func TestDerivedHandlersShareTheSink(t *testing.T) {
	srv, lines := collect(t)
	h := NewLogHandler(srv.URL, "svc", &LogHandlerOptions{Flush: 20 * time.Millisecond})

	base := slog.New(h)
	base.With("component", "checkout").Info("from a derived logger")
	base.WithGroup("db").With("table", "orders").Info("from a grouped logger")

	h.Close()
	got := lines()
	if len(got) != 2 {
		t.Fatalf("derived loggers delivered %d of 2 lines", len(got))
	}
	for _, l := range got {
		f, _ := l["fields"].(map[string]any)
		if len(f) == 0 {
			t.Errorf("derived attrs missing: %v", l)
		}
	}
	if _, failed, _, _ := h.Stats(); failed != 0 {
		t.Errorf("%d line(s) failed to deliver", failed)
	}
}

func TestLogHandlerCountsFailuresInsteadOfSwallowingThem(t *testing.T) {
	// An agent that refuses everything: the SDK must report that, not hide it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	h := NewLogHandler(srv.URL, "svc", &LogHandlerOptions{Flush: 20 * time.Millisecond})
	slog.New(h).Info("will not arrive")
	h.Close()

	sent, failed, _, lastErr := h.Stats()
	if failed == 0 || sent != 0 {
		t.Errorf("sent=%d failed=%d — a rejected line must be counted as failed", sent, failed)
	}
	if lastErr == nil {
		t.Error("no error recorded; silence is exactly the bug this guards against")
	}
}

func TestSpanHelpersOutsideARequest(t *testing.T) {
	if _, _, ok := SpanFromContext(context.Background()); ok {
		t.Error("reported a span where there is none")
	}
	if h := OutboundHeaders(context.Background()); h != nil {
		t.Errorf("outbound headers outside a request: %v", h)
	}
	ctx := tracectx.NewContext(context.Background(), tracectx.Context{
		TraceID: strings.Repeat("c", 32), SpanID: strings.Repeat("d", 16), Sampled: true,
	})
	trace, span, ok := SpanFromContext(ctx)
	if !ok || trace != strings.Repeat("c", 32) || span != strings.Repeat("d", 16) {
		t.Errorf("SpanFromContext: %q %q %v", trace, span, ok)
	}
	if got := OutboundHeaders(ctx)["traceparent"]; !strings.Contains(got, strings.Repeat("d", 16)) {
		t.Errorf("outbound header must carry THIS hop's span, got %q", got)
	}
}

// The guarantee the SDK actually makes: a handler behind the middleware can
// name the request it is serving. Without this, Go app logs cannot correlate
// and every outbound call starts a new tree.
func TestEmbeddedHandlerSeesItsOwnSpan(t *testing.T) {
	dir := t.TempDir()
	cfg := dir + "/optic.yaml"
	if err := os.WriteFile(cfg, []byte(`
version: 1
service: { name: embedded-test }
telemetry:
  admin_listen: "127.0.0.1:0"
  metrics: { enabled: false }
  store: { driver: none }
rules:
  - name: pay
    match: { path: "/pay/**" }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	var seenTrace, seenSpan, outbound string
	h := agent.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTrace, seenSpan, _ = SpanFromContext(r.Context())
		outbound = OutboundHeaders(r.Context())["traceparent"]
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/pay/charge", strings.NewReader("{}"))
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if len(seenTrace) != 32 || len(seenSpan) != 16 {
		t.Fatalf("handler saw no span: trace=%q span=%q", seenTrace, seenSpan)
	}
	if seenTrace != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("inbound trace not adopted: %s", seenTrace)
	}
	if seenSpan == "00f067aa0ba902b7" {
		t.Error("this hop reused the caller's span instead of creating its own")
	}
	// The header a downstream call would carry must name THIS hop, or the next
	// service becomes a sibling of this request rather than its child.
	if !strings.Contains(outbound, seenSpan) {
		t.Errorf("outbound header %q does not carry this hop's span %q", outbound, seenSpan)
	}
}
