package export

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func rec(path string) *store.Record {
	return &store.Record{Time: time.Now(), Method: "GET", Path: path, Status: 200}
}

// mockExporter records batches for dispatcher behavior tests.
type mockExporter struct {
	mu      sync.Mutex
	batches [][]*store.Record
	fail    bool
}

func (m *mockExporter) Name() string { return "mock" }
func (m *mockExporter) Type() string { return "mock" }
func (m *mockExporter) Export(_ context.Context, b []*store.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return context.DeadlineExceeded
	}
	cp := make([]*store.Record, len(b))
	copy(cp, b)
	m.batches = append(m.batches, cp)
	return nil
}
func (m *mockExporter) Close() error { return nil }

func TestDispatcherBatchingAndShutdownFlush(t *testing.T) {
	mock := &mockExporter{}
	d := &Dispatcher{logger: discard()}
	w := &worker{exp: mock, queue: make(chan *store.Record, 64), batchSize: 10, flushEach: time.Hour}
	d.workers = append(d.workers, w)
	d.wg.Add(1)
	go d.run(w)

	for i := 0; i < 25; i++ {
		d.Enqueue(rec("/x"))
	}
	d.Shutdown() // must flush the trailing partial batch of 5

	mock.mu.Lock()
	defer mock.mu.Unlock()
	total := 0
	for _, b := range mock.batches {
		total += len(b)
	}
	if total != 25 {
		t.Fatalf("expected all 25 records delivered, got %d in %d batches", total, len(mock.batches))
	}
	if len(mock.batches[0]) != 10 {
		t.Errorf("expected first batch of 10, got %d", len(mock.batches[0]))
	}
}

func TestDispatcherDropsWhenQueueFull(t *testing.T) {
	mock := &mockExporter{}
	d := &Dispatcher{logger: discard()}
	// No worker draining: queue of 4 fills, rest must drop without blocking.
	w := &worker{exp: mock, queue: make(chan *store.Record, 4), batchSize: 10, flushEach: time.Hour}
	d.workers = append(d.workers, w)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			d.Enqueue(rec("/x"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked on a full exporter queue")
	}
	if got := w.dropped.Load(); got != 96 {
		t.Errorf("expected 96 drops, got %d", got)
	}
}

func TestFileExporterWritesAndRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.jsonl")
	cfg := &config.ExporterCfg{Name: "f", Type: "file", Path: path, MaxSizeMB: 1}
	e, err := newFileExporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Export(context.Background(), []*store.Record{rec("/a"), rec("/b")}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	f, _ := os.Open(path)
	defer f.Close()
	var lines int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r store.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", lines, err)
		}
		lines++
	}
	if lines != 2 {
		t.Errorf("expected 2 JSONL lines, got %d", lines)
	}

	// Rotation: force tiny threshold.
	e2, _ := newFileExporter(cfg)
	e2.maxBytes = 10
	_ = e2.Export(context.Background(), []*store.Record{rec("/c")})
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected rotated file: %v", err)
	}
	e2.Close()
}

func TestWebhookExporter(t *testing.T) {
	var got [][]store.Record
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []store.Record
		_ = json.NewDecoder(r.Body).Decode(&batch)
		got = append(got, batch)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	e := newWebhookExporter(&config.ExporterCfg{Name: "w", Type: "webhook", URL: srv.URL})
	if err := e.Export(context.Background(), []*store.Record{rec("/a"), rec("/b")}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("webhook did not receive the batch: %+v", got)
	}
}

func TestOTLPExporterEmitsValidSpans(t *testing.T) {
	var got map[string]any
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newOTLPExporter(&config.ExporterCfg{Name: "otlp", Type: "otlp", URL: srv.URL}, "payments-api")
	// The collector path is appended automatically.
	if !strings.HasSuffix(e.endpoint, "/v1/traces") {
		t.Errorf("endpoint should target the traces signal, got %q", e.endpoint)
	}

	rec := &store.Record{
		Time: time.Now(), Method: "POST", Path: "/api/v1/payments/charge",
		Route: "/api/v1/payments/**", Status: 500, DurationMS: 12.5,
		Query:        "page=2&api_key=[REDACTED]",
		Labels:       map[string]string{"tenant": "acme"},
		Meters:       map[string]float64{"tokens": 128},
		MatchedRules: []string{"redact-payments"},
		RequestBody:  `{"secret":"must-not-be-exported"}`,
		ResponseBody: `{"also":"must-not-be-exported"}`,
	}
	if err := e.Export(context.Background(), []*store.Record{rec}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if contentType != "application/json" {
		t.Errorf("content type = %q", contentType)
	}

	raw, _ := json.Marshal(got)
	// Payload bodies must never reach a tracing backend: span attributes
	// have different retention and access rules than the payload store.
	if strings.Contains(string(raw), "must-not-be-exported") {
		t.Error("OTLP export leaked a request/response body into span attributes")
	}

	rs := got["resourceSpans"].([]any)[0].(map[string]any)
	spans := rs["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)
	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	span := spans[0].(map[string]any)
	if span["name"] != "POST /api/v1/payments/**" {
		t.Errorf("span name = %v", span["name"])
	}
	if id, _ := span["traceId"].(string); len(id) != 32 {
		t.Errorf("traceId must be 16 bytes hex, got %q", id)
	}
	if id, _ := span["spanId"].(string); len(id) != 16 {
		t.Errorf("spanId must be 8 bytes hex, got %q", id)
	}
	// 5xx must mark the span errored (STATUS_CODE_ERROR = 2).
	if code := span["status"].(map[string]any)["code"]; code != float64(2) {
		t.Errorf("5xx should set span status ERROR, got %v", code)
	}
	// Governed metadata should be present as attributes.
	attrsJSON, _ := json.Marshal(span["attributes"])
	for _, want := range []string{"optictrace.label.tenant", "acme", "optictrace.meter.tokens", "http.route", "url.query"} {
		if !strings.Contains(string(attrsJSON), want) {
			t.Errorf("span attributes missing %q", want)
		}
	}
}

func TestCommandExporterStreamsJSONL(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "plugin-out.jsonl")
	// The plugin: copy stdin to a file. `cat` is the simplest possible plugin.
	script := filepath.Join(dir, "plugin.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat > "+out+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := newCommandExporter(&config.ExporterCfg{
		Name: "c", Type: "command", Command: []string{script},
	}, discard())

	if err := e.Export(context.Background(), []*store.Record{rec("/p1"), rec("/p2")}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil { // EOF -> plugin drains and exits
		t.Fatal(err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	var lines int
	for sc.Scan() {
		var r store.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("plugin received invalid JSON: %v", err)
		}
		lines++
	}
	if lines != 2 {
		t.Errorf("plugin should have received 2 records, got %d", lines)
	}
}
