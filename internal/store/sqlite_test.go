package store

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleRecord(status int, durMS float64, path string) *Record {
	return &Record{
		Time: time.Now(), Service: "test", Method: "POST", Path: path,
		Route: "/api/**", Status: status, DurationMS: durMS,
		RequestHeaders: map[string]string{"Content-Type": "application/json"},
		RequestBody:    `{"amount":1}`,
		Labels:         map[string]string{"tenant": "acme"},
		MatchedRules:   []string{"r1"},
		ReqBytes:       12, RespBytes: 34,
	}
}

func TestSaveQueryRoundtrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.Save(ctx, sampleRecord(201, 12.5, "/api/v1/payments/charge")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, sampleRecord(500, 99, "/api/v1/orders")); err != nil {
		t.Fatal(err)
	}

	recs, total, err := s.Query(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(recs) != 2 {
		t.Fatalf("want 2 records, got total=%d len=%d", total, len(recs))
	}
	// Newest first.
	if recs[0].Path != "/api/v1/orders" {
		t.Errorf("expected newest first, got %s", recs[0].Path)
	}
	r := recs[1]
	if r.RequestHeaders["Content-Type"] != "application/json" ||
		r.Labels["tenant"] != "acme" || r.MatchedRules[0] != "r1" ||
		r.DurationMS != 12.5 {
		t.Errorf("roundtrip mismatch: %+v", r)
	}

	// Filters.
	recs, _, err = s.Query(ctx, Filter{StatusMin: 500})
	if err != nil || len(recs) != 1 || recs[0].Status != 500 {
		t.Errorf("status filter failed: %v %v", recs, err)
	}
	recs, _, _ = s.Query(ctx, Filter{PathPrefix: "/api/v1/payments"})
	if len(recs) != 1 {
		t.Errorf("path filter failed: %v", recs)
	}
	recs, _, _ = s.Query(ctx, Filter{Search: "amount"})
	if len(recs) != 2 {
		t.Errorf("body search failed: %v", recs)
	}

	got, err := s.Get(ctx, recs[0].ID)
	if err != nil || got.ID != recs[0].ID {
		t.Errorf("Get failed: %v %v", got, err)
	}
}

func TestStats(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		status := 200
		if i%10 == 0 {
			status = 500
		}
		if err := s.Save(ctx, sampleRecord(status, float64(i+1), "/api/x")); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.Stats(ctx, time.Now().Add(-time.Hour), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 100 || st.Errors != 10 {
		t.Errorf("totals wrong: %+v", st)
	}
	if st.ErrorRate != 0.1 {
		t.Errorf("error rate: %v", st.ErrorRate)
	}
	// Durations are 1..100 ms; p50 ≈ 51, p95 ≈ 96, p99 ≈ 100.
	if st.P50LatencyMS < 45 || st.P50LatencyMS > 55 {
		t.Errorf("p50 out of range: %v", st.P50LatencyMS)
	}
	if st.P99LatencyMS < 95 {
		t.Errorf("p99 out of range: %v", st.P99LatencyMS)
	}
	if st.StatusCounts["2xx"] != 90 || st.StatusCounts["5xx"] != 10 {
		t.Errorf("status counts: %v", st.StatusCounts)
	}
	if len(st.Series) == 0 || len(st.TopRoutes) == 0 {
		t.Errorf("missing series/top routes: %+v", st)
	}
	if st.TopRoutes[0].P95Latency < 90 {
		t.Errorf("route p95: %v", st.TopRoutes[0].P95Latency)
	}
}

func TestPrune(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		_ = s.Save(ctx, sampleRecord(200, 1, "/x"))
	}
	removed, err := s.Prune(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 30 {
		t.Errorf("expected 30 pruned, got %d", removed)
	}
	_, total, _ := s.Query(ctx, Filter{})
	if total != 20 {
		t.Errorf("expected 20 remaining, got %d", total)
	}
}

func TestAsyncWriterDrainsOnClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "drain.db")
	s, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	drops := 0
	w := NewAsyncWriter(s, 256, discardLogger(), WithDropCallback(func() { drops++ }))
	for i := 0; i < 100; i++ {
		w.Enqueue(sampleRecord(200, 1, "/x"))
	}
	if err := w.Close(); err != nil { // drains queue, closes store
		t.Fatal(err)
	}
	reopened, err := NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	_, total, err := reopened.Query(context.Background(), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if total+int64(drops) != 100 {
		t.Errorf("lost records: stored=%d dropped=%d", total, drops)
	}
	if drops != 0 {
		t.Errorf("queue of 256 should not drop 100 records, dropped %d", drops)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
