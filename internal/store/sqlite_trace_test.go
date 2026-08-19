package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// hop saves one recorded exchange belonging to a trace.
func hop(t *testing.T, s *SQLiteStore, at time.Time, trace, span, parent, svc, method, route string,
	status int, dur float64, labels map[string]string) {
	t.Helper()
	if err := s.Save(context.Background(), &Record{
		Time: at, Service: svc, Method: method, Path: route, Route: route,
		Status: status, DurationMS: dur, TraceID: trace, SpanID: span, ParentSpanID: parent,
		Labels: labels, RequestBody: `{"a":1}`,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
}

func traceStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A checkout fans out to two inner hops. The list must show ONE row naming the
// entry point, not three rows of equal weight — a trace list that shows every
// hop is just the record list with extra steps.
func TestTracesRollUpToTheRootHop(t *testing.T) {
	s := traceStore(t)
	base := time.Now().Add(-time.Minute)
	hop(t, s, base, "t1", "root", "", "shop", "POST", "/api/v1/orders", 201, 120,
		map[string]string{"tenant": "acme"})
	hop(t, s, base.Add(10*time.Millisecond), "t1", "cat", "root", "shop", "GET", "/api/v1/catalog/**", 200, 12, nil)
	hop(t, s, base.Add(30*time.Millisecond), "t1", "pay", "root", "payments", "POST", "/api/v1/payments/**", 200, 40, nil)

	got, total, err := s.Traces(context.Background(), ext.TraceFilter{Since: base.Add(-time.Minute)})
	if err != nil {
		t.Fatalf("traces: %v", err)
	}
	if total != 1 || len(got) != 1 {
		t.Fatalf("want 1 trace, got %d rows / total %d", len(got), total)
	}
	tr := got[0]
	if tr.Route != "/api/v1/orders" || tr.Method != "POST" {
		t.Errorf("root hop = %s %s, want POST /api/v1/orders", tr.Method, tr.Route)
	}
	if tr.Spans != 3 || tr.Services != 2 {
		t.Errorf("spans=%d services=%d, want 3 and 2", tr.Spans, tr.Services)
	}
	if tr.DurationMS != 120 {
		t.Errorf("duration = %v, want the ROOT's 120ms — the sum of concurrent hops is not a wall clock", tr.DurationMS)
	}
	if tr.Labels["tenant"] != "acme" {
		t.Errorf("root labels not carried: %v", tr.Labels)
	}
}

// An inner 5xx a retry swallowed never reaches the root status. Someone
// scanning a trace list for trouble is looking for exactly that.
func TestTracesCountInnerErrorsTheRootStatusHides(t *testing.T) {
	s := traceStore(t)
	base := time.Now().Add(-time.Minute)
	hop(t, s, base, "t1", "root", "", "shop", "POST", "/api/v1/orders", 201, 100, nil)
	hop(t, s, base.Add(time.Millisecond), "t1", "pay", "root", "payments", "POST", "/api/v1/payments/**", 502, 30, nil)
	hop(t, s, base.Add(2*time.Millisecond), "t2", "r2", "", "shop", "GET", "/api/v1/health", 200, 1, nil)

	got, _, err := s.Traces(context.Background(), ext.TraceFilter{Since: base.Add(-time.Minute)})
	if err != nil {
		t.Fatalf("traces: %v", err)
	}
	byID := map[string]ext.TraceSummary{}
	for _, tr := range got {
		byID[tr.TraceID] = tr
	}
	if byID["t1"].Status != 201 || byID["t1"].Errors != 1 {
		t.Errorf("t1 status=%d errors=%d, want a 201 root carrying 1 inner error",
			byID["t1"].Status, byID["t1"].Errors)
	}

	// errors=1 must filter on the WHOLE trace, not the root status.
	only, total, err := s.Traces(context.Background(),
		ext.TraceFilter{Since: base.Add(-time.Minute), ErrorsOnly: true})
	if err != nil {
		t.Fatalf("traces: %v", err)
	}
	if total != 1 || len(only) != 1 || only[0].TraceID != "t1" {
		t.Fatalf("errors-only = %v (total %d), want just t1", only, total)
	}
}

// When the entry service is not instrumented there is no parentless hop. The
// trace still lists, named by what WAS seen — dropping it would hide exactly
// the services nobody has got round to instrumenting.
func TestTracesFallBackToTheEarliestHopWithoutARoot(t *testing.T) {
	s := traceStore(t)
	base := time.Now().Add(-time.Minute)
	hop(t, s, base, "t1", "a", "upstream-we-never-saw", "shop", "GET", "/api/v1/catalog/**", 200, 5, nil)
	hop(t, s, base.Add(time.Second), "t1", "b", "upstream-we-never-saw", "payments", "POST", "/api/v1/payments/**", 200, 7, nil)

	got, _, err := s.Traces(context.Background(), ext.TraceFilter{Since: base.Add(-time.Minute)})
	if err != nil {
		t.Fatalf("traces: %v", err)
	}
	if len(got) != 1 || got[0].Route != "/api/v1/catalog/**" {
		t.Fatalf("want the earliest hop as the stand-in root, got %+v", got)
	}
}

// Paging must agree with the total it reports. Filtering after LIMIT — the
// obvious way to apply a label filter to a JSON blob — makes the pager show a
// total the pages cannot produce.
func TestTracesLabelFilterAppliesBeforePaging(t *testing.T) {
	s := traceStore(t)
	base := time.Now().Add(-time.Minute)
	for i := 0; i < 10; i++ {
		tenant := "acme"
		if i%2 == 1 {
			tenant = "globex"
		}
		id := string(rune('a' + i))
		hop(t, s, base.Add(time.Duration(i)*time.Second), "t"+id, "s"+id, "", "shop",
			"POST", "/api/v1/orders", 201, 10, map[string]string{"tenant": tenant})
	}
	f := ext.TraceFilter{Since: base.Add(-time.Minute), Labels: map[string]string{"tenant": "acme"}, Limit: 2}
	page, total, err := s.Traces(context.Background(), f)
	if err != nil {
		t.Fatalf("traces: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5 acme traces", total)
	}
	if len(page) != 2 {
		t.Fatalf("page = %d rows, want 2", len(page))
	}
	for _, tr := range page {
		if tr.Labels["tenant"] != "acme" {
			t.Errorf("page leaked another tenant: %v", tr.Labels)
		}
	}
	// Walk every page and check the filter holds all the way through.
	seen := 0
	for off := 0; off < 20; off += 2 {
		f.Offset = off
		rows, _, err := s.Traces(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		for _, tr := range rows {
			if tr.Labels["tenant"] != "acme" {
				t.Fatalf("offset %d leaked %v", off, tr.Labels)
			}
			seen++
		}
	}
	if int64(seen) != total {
		t.Errorf("paging yielded %d rows for a reported total of %d", seen, total)
	}
}

// The per-bucket p95 is the point of the series: an average hides the handful
// of slow requests worth looking at.
func TestStatsSeriesCarriesTailAndClientErrors(t *testing.T) {
	s := traceStore(t)
	base := time.Now().Add(-30 * time.Second)
	// 90 fast and 10 slow, so the p95 lands squarely inside the tail while the
	// mean sits an order of magnitude below it. A fixture where the two agree
	// would pass with the percentile unimplemented.
	for i := 0; i < 90; i++ {
		hop(t, s, base, "t", "s", "", "shop", "GET", "/api/v1/catalog/**", 200, 5, nil)
	}
	for i := 0; i < 10; i++ {
		hop(t, s, base, "t", "slow", "", "shop", "GET", "/api/v1/catalog/**", 200, 3000, nil)
	}
	hop(t, s, base, "t", "bad", "", "shop", "GET", "/api/v1/catalog/**", 404, 4, nil)
	hop(t, s, base, "t", "boom", "", "shop", "GET", "/api/v1/catalog/**", 500, 4, nil)

	st, err := s.Stats(context.Background(), base.Add(-time.Minute), time.Hour)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if len(st.Series) != 1 {
		t.Fatalf("want one bucket, got %d", len(st.Series))
	}
	b := st.Series[0]
	if b.P95Latency < 10*b.AvgLatency {
		t.Errorf("bucket p95 = %v against a mean of %v — the tail is not surfacing, "+
			"which is the whole reason the series carries a percentile", b.P95Latency, b.AvgLatency)
	}
	if b.ClientErrors != 1 || b.Errors != 1 {
		t.Errorf("4xx=%d 5xx=%d, want them counted apart — they need opposite responses",
			b.ClientErrors, b.Errors)
	}
	if st.BodiesKept != 102 || st.Total != 102 {
		t.Errorf("bodies kept %d of %d, want every fixture body counted", st.BodiesKept, st.Total)
	}
}
