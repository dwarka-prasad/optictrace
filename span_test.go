package optictrace_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace"
)

const spanConfig = `
version: 1
service:
  name: spantest
telemetry:
  admin_listen: "127.0.0.1:0"
  console_log: false
  store:
    driver: sqlite
    dsn: %s
  spans:
    enabled: true
    min_duration: 0s
    max_per_request: 50
    max_attr_bytes: 512
    redact:
      patterns:
        - '\b\d{13,19}\b'
        - '[\w.+-]+@[\w-]+\.[\w.]+'
rules:
  - name: orders
    match:
      path: "/api/orders"
`

// The whole feature, through the real agent: an HTTP request is recorded, the
// operations inside it are recorded as children of it, and a statement that
// quoted a card number is stored redacted.
//
// Driven end-to-end on purpose. Every serious bug this project has had was
// found by running it — an SDK that passes offline checks while the agent
// rejects everything it sends looks exactly like one that works.
func TestInnerSpansReachTheAgentUnderTheirRequest(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "optic.yaml")
	if err := os.WriteFile(cfgPath,
		[]byte(fmt.Sprintf(spanConfig, filepath.Join(dir, "s.db"))), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := optictrace.New(cfgPath)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	defer agent.Close()

	admin := httptest.NewServer(agent.AdminHandler(""))
	defer admin.Close()

	spans := optictrace.NewSpanRecorder(admin.URL, "spantest", &optictrace.SpanOptions{
		Flush: 20 * time.Millisecond,
	})
	defer spans.Close()

	// A downstream service for the outbound-HTTP span to actually call.
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Propagation is part of the Transport's job, so assert it here rather
		// than trusting it.
		if r.Header.Get("traceparent") == "" {
			t.Error("Transport did not propagate traceparent to the downstream call")
		}
		w.WriteHeader(200)
	}))
	defer downstream.Close()
	client := &http.Client{Transport: spans.Transport(nil)}

	var innerErr error
	handler := agent.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// A query whose statement quotes its parameters — the normal case for
		// a driver that interpolates, and the reason attributes are governed.
		innerErr = spans.Observe(ctx, "db.query", "db", func(ctx context.Context) error {
			_, sp := spans.Start(ctx, "db.rows", "db")
			sp.Set("db.statement",
				"SELECT * FROM cards WHERE number = '4111111111111111' AND email = 'a@b.com'").
				SetInt("db.rows", 3)
			sp.End()
			time.Sleep(2 * time.Millisecond)
			return nil
		})

		// A failure, fast, which must survive any duration filter.
		_, cache := spans.Start(ctx, "redis.get", "cache")
		cache.Set("cache.key", "session:abc").Fail(errors.New("connection refused"))
		cache.End()

		req, _ := http.NewRequestWithContext(ctx, "GET", downstream.URL+"/rates", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("downstream call: %v", err)
		} else {
			resp.Body.Close()
		}
		w.WriteHeader(201)
	}))

	app := httptest.NewServer(handler)
	defer app.Close()
	resp, err := http.Post(app.URL+"/api/orders", "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if innerErr != nil {
		t.Fatalf("inner work failed: %v", innerErr)
	}

	// Drain both sides: the recorder batches, and the agent's store writer is
	// asynchronous.
	if err := spans.Close(); err != nil {
		t.Fatalf("flush spans: %v", err)
	}
	sent, failed, dropped, lastErr := spans.Stats()
	if failed > 0 || dropped > 0 {
		t.Fatalf("delivery: sent=%d failed=%d dropped=%d lastErr=%v", sent, failed, dropped, lastErr)
	}
	if sent != 4 {
		t.Fatalf("shipped %d spans, want 4 (db.query, db.rows, redis.get, http)", sent)
	}

	// Tags spelled out: Go falls back to a case-insensitive FIELD-NAME match,
	// which never matches a snake_case key, so TraceID would silently decode
	// as empty and the assertions below would fail for the wrong reason.
	var body struct {
		Spans []struct {
			Name         string            `json:"name"`
			Kind         string            `json:"kind"`
			TraceID      string            `json:"trace_id"`
			SpanID       string            `json:"span_id"`
			ParentSpanID string            `json:"parent_span_id"`
			Error        string            `json:"error"`
			DurationMS   float64           `json:"duration_ms"`
			Attrs        map[string]string `json:"attrs"`
		} `json:"spans"`
		Total int64 `json:"total"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := http.Get(admin.URL + "/api/spans?window=1h&limit=100")
		if err != nil {
			t.Fatalf("query spans: %v", err)
		}
		body.Spans = nil
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		r.Body.Close()
		if len(body.Spans) >= 4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(body.Spans) != 4 {
		t.Fatalf("agent stored %d spans, want 4", len(body.Spans))
	}

	byName := map[string]int{}
	for _, sp := range body.Spans {
		byName[sp.Name]++
		if sp.TraceID == "" || sp.ParentSpanID == "" {
			t.Errorf("%s has no request behind it (trace=%q parent=%q) — it would be dropped as an orphan",
				sp.Name, sp.TraceID, sp.ParentSpanID)
		}
	}
	for _, want := range []string{"db.query", "db.rows", "redis.get"} {
		if byName[want] != 1 {
			t.Errorf("%s stored %d times, want 1 (names seen: %v)", want, byName[want], byName)
		}
	}

	var rows, cache, outbound bool
	for _, sp := range body.Spans {
		switch sp.Name {
		case "db.rows":
			rows = true
			stmt := sp.Attrs["db.statement"]
			if strings.Contains(stmt, "4111111111111111") {
				t.Errorf("card number stored in the statement: %s", stmt)
			}
			if strings.Contains(stmt, "a@b.com") {
				t.Errorf("email stored in the statement: %s", stmt)
			}
			if !strings.Contains(stmt, "SELECT") {
				t.Errorf("redaction destroyed the statement shape: %s", stmt)
			}
			if sp.Attrs["db.rows"] != "3" {
				t.Errorf("db.rows = %q, want 3", sp.Attrs["db.rows"])
			}
		case "redis.get":
			cache = true
			if sp.Error == "" {
				t.Error("a failed cache lookup must record its error")
			}
			if sp.Kind != "cache" {
				t.Errorf("kind = %q, want cache", sp.Kind)
			}
		default:
			if sp.Kind == "http" {
				outbound = true
				if sp.Attrs["http.status"] != "200" {
					t.Errorf("outbound status = %q, want 200", sp.Attrs["http.status"])
				}
				if strings.Contains(sp.Attrs["http.url"], "?") {
					t.Errorf("query string kept on an outbound URL: %s", sp.Attrs["http.url"])
				}
			}
		}
	}
	if !rows || !cache || !outbound {
		t.Errorf("missing spans: rows=%v cache=%v outbound=%v", rows, cache, outbound)
	}

	// Nesting: db.rows ran inside db.query, so it must parent to it rather
	// than jumping to the request span.
	var queryID, rowsParent string
	for _, sp := range body.Spans {
		if sp.Name == "db.query" {
			queryID = sp.SpanID
		}
		if sp.Name == "db.rows" {
			rowsParent = sp.ParentSpanID
		}
	}
	if queryID == "" || rowsParent != queryID {
		t.Errorf("db.rows parent = %q, want db.query's id %q — operations must nest", rowsParent, queryID)
	}

	// And the breakdown, which is the "where did the time go" query.
	r, err := http.Get(admin.URL + "/api/spans/breakdown?window=1h")
	if err != nil {
		t.Fatalf("breakdown: %v", err)
	}
	defer r.Body.Close()
	var bd struct {
		Breakdown []struct {
			Name     string  `json:"name"`
			Count    int64   `json:"count"`
			Requests int64   `json:"requests"`
			TotalMS  float64 `json:"total_ms"`
		} `json:"breakdown"`
	}
	if err := json.NewDecoder(r.Body).Decode(&bd); err != nil {
		t.Fatalf("decode breakdown: %v", err)
	}
	if len(bd.Breakdown) == 0 {
		t.Fatal("breakdown is empty")
	}
	for _, b := range bd.Breakdown {
		if b.Requests == 0 {
			t.Errorf("%s: Requests=0, so the per-request multiplier cannot be computed", b.Name)
		}
	}
}

// An empty agent URL must make instrumentation inert rather than panic, so the
// same code can run in an environment with no agent.
func TestSpanRecorderWithNoAgentIsInert(t *testing.T) {
	spans := optictrace.NewSpanRecorder("", "svc", nil)
	defer spans.Close()
	ctx, sp := spans.Start(context.Background(), "db.query", "db")
	sp.Set("db.statement", "SELECT 1").SetInt("db.rows", 1).Fail(sql.ErrNoRows)
	sp.End()
	sp.End() // twice must not double count or panic
	if _, inner := spans.Start(ctx, "nested", "db"); inner == nil {
		t.Error("nested start returned nil")
	}
	if sent, failed, dropped, _ := spans.Stats(); sent|failed|dropped != 0 {
		t.Errorf("an inert recorder shipped something: %d/%d/%d", sent, failed, dropped)
	}
}
