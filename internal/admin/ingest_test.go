package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

// An SDK sends whatever header names the wire carried — lower case under
// HTTP/2, and lower case from every SDK this project ships. The proxy stores
// Go's canonical form. If the agent kept both spellings, `optictrace suggest`
// would report "authorization is a credential" on a route whose own rule
// already masks it, because its coverage lookup is keyed on the canonical
// name. That is worse than silence: it teaches people to ignore the tool.
func TestIngestCanonicalisesHeaderNamesFromSDKs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "a.db")
	st, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// Close() drains outstanding records and then closes the store, so it is
	// called exactly once — at the point the test needs the record readable.
	w := store.NewAsyncWriter(st, 16, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	s := &Server{Reader: st, Writer: w, HealthOpen: true, Version: "test"}
	body, _ := json.Marshal(map[string]any{
		"time": time.Now().Format(time.RFC3339Nano), "service": "shop-api",
		"method": "POST", "path": "/api/v1/orders", "route": "/api/v1/orders",
		"status": 201, "duration_ms": 1.0, "source": "java",
		"request_headers":  map[string]string{"authorization": "[REDACTED]", "x-tenant-id": "acme"},
		"response_headers": map[string]string{"content-type": "application/json"},
	})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/ingest", bytes.NewReader(body)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("ingest status %d: %s", rec.Code, rec.Body.String())
	}
	if err := w.Close(); err != nil {
		t.Fatalf("drain: %v", err)
	}

	reopened, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.Recent(context.Background(), time.Now().Add(-time.Hour), 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("recent: %v (%d records)", err, len(got))
	}
	for name, want := range map[string]string{
		"Authorization": "[REDACTED]",
		"X-Tenant-Id":   "acme",
	} {
		if got[0].RequestHeaders[name] != want {
			t.Errorf("request header %q = %q, want %q (headers: %v)",
				name, got[0].RequestHeaders[name], want, got[0].RequestHeaders)
		}
	}
	if got[0].ResponseHeaders["Content-Type"] != "application/json" {
		t.Errorf("response headers not canonicalised: %v", got[0].ResponseHeaders)
	}
}

// A record carrying the same header twice under different spellings must not
// lose the masked value to map iteration order.
func TestCanonicalHeaderNamesKeepsFirstOnCollision(t *testing.T) {
	for i := 0; i < 200; i++ { // map order is randomised; one pass proves nothing
		out := canonicalHeaderNames(map[string]string{
			"authorization": "[REDACTED]",
			"Authorization": "[REDACTED]",
		})
		if len(out) != 1 || out["Authorization"] != "[REDACTED]" {
			t.Fatalf("collision handling: %v", out)
		}
	}
	if canonicalHeaderNames(nil) != nil {
		t.Error("nil must stay nil, so an absent header map is not stored as an empty one")
	}
}

// A driver that cannot list traces must say so plainly and name itself. The
// dashboard hides the tab on a 501; a 500 would show an error banner for a
// feature the operator never asked for.
func TestTracesEndpointDegradesOnADriverWithoutTraceSupport(t *testing.T) {
	s := &Server{Reader: readerWithoutTraces{}, HealthOpen: true, Version: "test"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/traces?window=1h", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "readerWithoutTraces") {
		t.Errorf("the message must name the driver that could not do it, got %s", rec.Body.String())
	}
}

func TestTracesEndpointPassesFiltersThrough(t *testing.T) {
	fake := &traceReader{}
	s := &Server{Reader: fake, HealthOpen: true, Version: "test"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET",
		"/api/traces?window=15m&errors=1&service=shop&q=orders&label.tenant=acme&limit=7&offset=14", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got := fake.last
	if !got.ErrorsOnly || got.Service != "shop" || got.Search != "orders" ||
		got.Labels["tenant"] != "acme" || got.Limit != 7 || got.Offset != 14 {
		t.Errorf("filters lost on the way to the store: %+v", got)
	}
	if d := time.Since(got.Since); d < 14*time.Minute || d > 16*time.Minute {
		t.Errorf("window resolved to %v ago, want ~15m", d)
	}
	// An oversized limit must be clamped, not passed on: the page size is what
	// stands between a dashboard poll and a full table scan.
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/traces?limit=100000", nil))
	if fake.last.Limit != 100 {
		t.Errorf("limit = %d, want it clamped to the default", fake.last.Limit)
	}
}

// A reader that implements ext.Store but not ext.TraceStore.
type readerWithoutTraces struct{ store.LogStore }

type traceReader struct {
	store.LogStore
	last store.TraceFilter
}

func (f *traceReader) Traces(_ context.Context, filter store.TraceFilter) ([]store.TraceSummary, int64, error) {
	f.last = filter
	return nil, 0, nil
}
