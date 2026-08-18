// Package exttest is the acceptance suite for an ext.Store implementation.
//
// Two drivers means two chances to drift apart; four means six. This suite is
// the contract: every driver runs the identical assertions, so a query that
// quietly returns different results than the others fails here rather than in
// someone's dashboard. It is exported because an out-of-tree store deserves
// the same guarantee — and because "does my driver behave like the built-in
// ones" should be answerable by running a test, not by reading source.
//
// Usage from your driver's own test file:
//
//	func TestConformance(t *testing.T) {
//		exttest.RunStoreSuite(t, func(t *testing.T) ext.Store {
//			s, err := NewMyStore(dsn)
//			if err != nil {
//				t.Fatalf("open: %v", err)
//			}
//			t.Cleanup(func() { s.Close() })
//			return s   // MUST be empty
//		})
//	}
//
// Every sub-test calls open again and requires a store holding no records —
// truncate, use a fresh temp file, or a fresh schema. The suite makes exact
// count assertions and leftover rows will fail it.
package exttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// OpenFunc returns a fresh, EMPTY store. It is called once per sub-test and
// should register its own cleanup.
type OpenFunc func(t *testing.T) ext.Store

// Record builds a representative governed record. Exported so a driver's own
// tests can reuse the shape the suite exercises.
func Record(status int, durMS float64, path, tenant string) *ext.Record {
	return &ext.Record{
		Time: time.Now(), Service: "conf", Method: "POST", Path: path,
		Query: "page=2&api_key=[REDACTED]",
		Route: "/api/**", Status: status, DurationMS: durMS,
		RequestHeaders: map[string]string{"Content-Type": "application/json"},
		RequestBody:    `{"amount":1}`,
		Labels:         map[string]string{"tenant": tenant},
		MatchedRules:   []string{"r1"},
		Meters:         map[string]float64{"tokens": 10},
		ReqBytes:       12, RespBytes: 34,
	}
}

// RunStoreSuite runs every conformance check against one driver.
func RunStoreSuite(t *testing.T, open OpenFunc) {
	t.Helper()
	t.Run("roundtrip", func(t *testing.T) { testRoundtrip(t, open) })
	t.Run("filters", func(t *testing.T) { testFilters(t, open) })
	t.Run("usage", func(t *testing.T) { testUsage(t, open) })
	t.Run("rule_match_counts", func(t *testing.T) { testRuleMatchCounts(t, open) })
	t.Run("label_filter", func(t *testing.T) { testLabelFilter(t, open) })
	t.Run("trace_correlation", func(t *testing.T) { testTraceCorrelation(t, open) })
	t.Run("purge", func(t *testing.T) { testPurge(t, open) })
	t.Run("purge_is_literal", func(t *testing.T) { testPurgeIsLiteral(t, open) })
	t.Run("stats", func(t *testing.T) { testStats(t, open) })
	t.Run("retention_by_age", func(t *testing.T) { testPruneBefore(t, open) })
	t.Run("retention_by_rows", func(t *testing.T) { testPrune(t, open) })
	t.Run("recent_func", func(t *testing.T) { testRecentFunc(t, open) })
	t.Run("streams_excluded_from_percentiles", func(t *testing.T) { testStreams(t, open) })
}

func testRoundtrip(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	mustSave(t, s, Record(201, 12.5, "/api/v1/payments/charge", "acme"))
	mustSave(t, s, Record(500, 99, "/api/v1/orders", "globex"))

	recs, total, err := s.Query(ctx, ext.Filter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 2 || len(recs) != 2 {
		t.Fatalf("want 2 records, got total=%d len=%d", total, len(recs))
	}
	if recs[0].Path != "/api/v1/orders" {
		t.Errorf("Query must return newest first, got %s", recs[0].Path)
	}

	// Every field must survive storage. Losing labels or meters silently
	// breaks cost attribution rather than erroring.
	r := recs[1]
	if r.RequestHeaders["Content-Type"] != "application/json" ||
		r.Labels["tenant"] != "acme" || len(r.MatchedRules) == 0 || r.MatchedRules[0] != "r1" ||
		r.Meters["tokens"] != 10 || r.DurationMS != 12.5 || r.Query == "" {
		t.Errorf("roundtrip lost data: %+v", r)
	}

	got, err := s.Get(ctx, recs[0].ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != recs[0].ID {
		t.Errorf("Get(%d) returned id %d", recs[0].ID, got.ID)
	}

	if n, err := s.Count(ctx); err != nil || n != 2 {
		t.Errorf("Count = %d, %v; want 2", n, err)
	}
}

func testFilters(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	mustSave(t, s, Record(201, 12.5, "/api/v1/payments/charge", "acme"))
	mustSave(t, s, Record(500, 99, "/api/v1/orders", "globex"))

	for _, tc := range []struct {
		name string
		f    ext.Filter
		want int
	}{
		{"status floor", ext.Filter{StatusMin: 500}, 1},
		{"path prefix", ext.Filter{PathPrefix: "/api/v1/payments"}, 1},
		{"body search", ext.Filter{Search: "amount"}, 2},
		// Method matching must fold case, or the dashboard's filter behaves
		// differently depending on how the caller typed it.
		{"method is case-insensitive", ext.Filter{Method: "post"}, 2},
		{"no constraint", ext.Filter{}, 2},
		{"since excludes everything", ext.Filter{Since: time.Now().Add(time.Hour)}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, _, err := s.Query(ctx, tc.f)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(recs) != tc.want {
				t.Errorf("got %d records, want %d", len(recs), tc.want)
			}
		})
	}
}

func testUsage(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	mustSave(t, s, Record(201, 12.5, "/api/v1/payments/charge", "acme"))
	mustSave(t, s, Record(500, 99, "/api/v1/orders", "globex"))

	usage, err := s.UsageByLabel(ctx, time.Now().Add(-time.Hour), "tenant")
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	byName := map[string]ext.Usage{}
	for _, u := range usage {
		byName[u.Consumer] = u
	}
	if byName["acme"].Requests != 1 || byName["globex"].Errors != 1 {
		t.Errorf("usage aggregation wrong: %+v", usage)
	}
	if byName["acme"].Meters["tokens"] != 10 {
		t.Errorf("meters must aggregate per consumer: %+v", byName["acme"].Meters)
	}
}

func testRuleMatchCounts(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	for _, rules := range [][]string{
		{"redact-cards", "label-tenant"},
		{"redact-cards"},
		{"label-tenant"},
		nil, // a record that matched nothing must not break the query
	} {
		r := Record(200, 1, "/api/x", "acme")
		r.MatchedRules = rules
		mustSave(t, s, r)
	}
	got, err := s.RuleMatchCounts(ctx, time.Now().Add(-time.Hour),
		[]string{"redact-cards", "label-tenant", "never-fires"})
	if err != nil {
		t.Fatalf("RuleMatchCounts: %v", err)
	}
	counts := map[string]int64{}
	for _, m := range got {
		counts[m.Rule] = m.Count
	}
	for rule, want := range map[string]int64{
		"redact-cards": 2, "label-tenant": 2, "never-fires": 0,
	} {
		if counts[rule] != want {
			t.Errorf("%s = %d, want %d (all: %+v)", rule, counts[rule], want, counts)
		}
	}
	// A rule that never fired must still be reported — a zero is the
	// interesting answer for a rule someone expected to be matching.
	if len(got) != 3 {
		t.Errorf("every requested rule should be reported, got %d", len(got))
	}
}

// testLabelFilter covers the multi-tenant question: one endpoint, many
// tenants, show me only one of them. The labels-ONLY case matters most —
// a driver that builds its WHERE clause in the wrong order can return every
// record when labels are the sole constraint, which shows a user another
// tenant's traffic rather than erroring.
func testLabelFilter(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	for _, tc := range []struct{ tenant, tier string }{
		{"acme", "premium"}, {"acme", "premium"}, {"acme", "standard"},
		{"globex", "standard"}, {"initech", "premium"},
	} {
		r := Record(200, 1, "/api/orders", tc.tenant)
		r.Labels = map[string]string{"tenant": tc.tenant, "tier": tc.tier}
		mustSave(t, s, r)
	}

	for _, tc := range []struct {
		name   string
		labels map[string]string
		want   int
	}{
		{"single label", map[string]string{"tenant": "acme"}, 3},
		{"other tenant", map[string]string{"tenant": "globex"}, 1},
		{"by tier across tenants", map[string]string{"tier": "premium"}, 3},
		// Multiple labels are an AND.
		{"two labels", map[string]string{"tenant": "acme", "tier": "premium"}, 2},
		{"no match", map[string]string{"tenant": "nobody"}, 0},
		{"contradictory", map[string]string{"tenant": "globex", "tier": "premium"}, 0},
		{"unknown label name", map[string]string{"nosuch": "x"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs, total, err := s.Query(ctx, ext.Filter{Labels: tc.labels})
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if int(total) != tc.want || len(recs) != tc.want {
				t.Fatalf("total=%d len=%d, want %d", total, len(recs), tc.want)
			}
			// Every returned record must actually carry the filter values.
			for _, r := range recs {
				for k, v := range tc.labels {
					if r.Labels[k] != v {
						t.Errorf("returned a record with %s=%q, wanted %q", k, r.Labels[k], v)
					}
				}
			}
		})
	}

	t.Run("combines with other constraints", func(t *testing.T) {
		_, total, err := s.Query(ctx, ext.Filter{
			Labels: map[string]string{"tenant": "acme"}, Method: "post",
		})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if total != 3 {
			t.Errorf("total = %d, want 3", total)
		}
	})

	// Matched literally, never as a pattern — the mistake that once let purge
	// destroy a neighbouring tenant's data, and just as wrong when it widens
	// what someone is shown.
	t.Run("values match literally", func(t *testing.T) {
		s2 := open(t)
		for _, tenant := range []string{"acme_1", "acmeX1"} {
			r := Record(200, 1, "/api/x", tenant)
			r.Labels = map[string]string{"tenant": tenant}
			mustSave(t, s2, r)
		}
		recs, total, err := s2.Query(ctx, ext.Filter{Labels: map[string]string{"tenant": "acme_1"}})
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if total != 1 {
			t.Fatalf("filtering tenant=acme_1 returned %d records — _ was treated as a wildcard", total)
		}
		if recs[0].Labels["tenant"] != "acme_1" {
			t.Errorf("returned the wrong tenant: %q", recs[0].Labels["tenant"])
		}
	})
}

// testTraceCorrelation covers the question that makes several services worth
// pointing at one store: "what did this request actually do". The ids must
// survive storage and be selectable, or the records stay a flat list.
func testTraceCorrelation(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)

	const traceA, traceB = "4bf92f3577b34da6a3ce929d0e0e4736", "0af7651916cd43dd8448eb211c80319c"
	// One request fanning out across three services, plus an unrelated one.
	hops := []struct{ trace, span, parent, service string }{
		{traceA, "aaaa000000000001", "", "gateway"}, // root
		{traceA, "aaaa000000000002", "aaaa000000000001", "leads"},
		{traceA, "aaaa000000000003", "aaaa000000000002", "scoring"},
		{traceB, "bbbb000000000001", "", "gateway"},
	}
	for _, h := range hops {
		r := Record(200, 5, "/api/x", "acme")
		r.Service, r.TraceID, r.SpanID, r.ParentSpanID = h.service, h.trace, h.span, h.parent
		mustSave(t, s, r)
	}

	recs, total, err := s.Query(ctx, ext.Filter{TraceID: traceA})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 3 || len(recs) != 3 {
		t.Fatalf("trace A returned total=%d len=%d, want 3", total, len(recs))
	}

	// The tree has to be reconstructible, which needs the parent links intact.
	bySpan := map[string]ext.Record{}
	for _, r := range recs {
		if r.TraceID != traceA {
			t.Errorf("returned a record from another trace: %s", r.TraceID)
		}
		bySpan[r.SpanID] = r
	}
	roots := 0
	for _, r := range recs {
		if r.ParentSpanID == "" {
			roots++
			continue
		}
		if _, ok := bySpan[r.ParentSpanID]; !ok {
			t.Errorf("span %s has parent %s, which is not in the trace",
				r.SpanID, r.ParentSpanID)
		}
	}
	if roots != 1 {
		t.Errorf("found %d roots, want exactly 1", roots)
	}

	t.Run("other traces are excluded", func(t *testing.T) {
		_, n, err := s.Query(ctx, ext.Filter{TraceID: traceB})
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("trace B returned %d, want 1", n)
		}
	})
	t.Run("unknown trace returns nothing", func(t *testing.T) {
		_, n, err := s.Query(ctx, ext.Filter{TraceID: "deadbeef"})
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("unknown trace returned %d records", n)
		}
	})
	t.Run("combines with other constraints", func(t *testing.T) {
		_, n, err := s.Query(ctx, ext.Filter{TraceID: traceA, Labels: map[string]string{"tenant": "acme"}})
		if err != nil {
			t.Fatal(err)
		}
		if n != 3 {
			t.Errorf("trace + label returned %d, want 3", n)
		}
	})
}

func testPurge(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	mustSave(t, s, Record(201, 12.5, "/api/v1/payments/charge", "acme"))
	mustSave(t, s, Record(500, 99, "/api/v1/orders", "globex"))

	removed, err := s.Purge(ctx, "tenant", "acme", time.Time{})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 1 {
		t.Errorf("purge removed %d, want 1", removed)
	}
	if _, total, _ := s.Query(ctx, ext.Filter{}); total != 1 {
		t.Errorf("purge should leave the other consumer behind, total=%d", total)
	}
	// Refusing an unscoped purge matters: an empty label with a naive
	// implementation deletes the entire store.
	if _, err := s.Purge(ctx, "", "", time.Time{}); err == nil {
		t.Error("purge without a label/value must error rather than delete everything")
	}
}

// testPurgeIsLiteral guards the one mistake an erasure tool must never make:
// deleting a bystander's data. A driver that matches the label value as a
// pattern rather than a literal fails here — which is exactly how the built-in
// SQLite driver once destroyed a neighbouring tenant.
func testPurgeIsLiteral(t *testing.T, open OpenFunc) {
	for _, tc := range []struct{ name, target, bystander string }{
		{"underscore", "acme_1", "acmeX1"},
		{"percent", "a%", "apex"},
		{"backslash", `acme\1`, `acme\\1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := open(t)
			for _, tenant := range []string{tc.target, tc.bystander} {
				mustSave(t, s, Record(200, 1, "/api/x", tenant))
			}
			removed, err := s.Purge(ctx, "tenant", tc.target, time.Time{})
			if err != nil {
				t.Fatalf("purge: %v", err)
			}
			if removed != 1 {
				t.Errorf("purging %q removed %d rows, want 1", tc.target, removed)
			}
			recs, total, err := s.Query(ctx, ext.Filter{})
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if total != 1 {
				t.Fatalf("purging %q left %d rows — only %q should survive",
					tc.target, total, tc.bystander)
			}
			if got := recs[0].Labels["tenant"]; got != tc.bystander {
				t.Errorf("survivor is %q, want the bystander %q", got, tc.bystander)
			}
		})
	}
}

func testStats(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	for i := 0; i < 100; i++ {
		status := 200
		if i%10 == 0 {
			status = 500
		}
		mustSave(t, s, Record(status, float64(i+1), "/api/x", "acme"))
	}

	st, err := s.Stats(ctx, time.Now().Add(-time.Hour), time.Minute)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.Total != 100 || st.Errors != 10 || st.ErrorRate != 0.1 {
		t.Errorf("totals wrong: %+v", st)
	}
	// Durations are 1..100ms. Drivers compute percentiles differently —
	// ordered OFFSET, percentile_cont, quantileExact — so the assertion is a
	// band. Landing outside it means the driver disagrees with the others.
	if st.P50LatencyMS < 45 || st.P50LatencyMS > 56 {
		t.Errorf("p50 = %v, want ~50", st.P50LatencyMS)
	}
	if st.P95LatencyMS < 90 || st.P95LatencyMS > 100 {
		t.Errorf("p95 = %v, want ~95", st.P95LatencyMS)
	}
	if st.StatusCounts["2xx"] != 90 || st.StatusCounts["5xx"] != 10 {
		t.Errorf("status classes: %v", st.StatusCounts)
	}
	if len(st.Series) == 0 || len(st.TopRoutes) == 0 {
		t.Error("Stats must populate the time series and top routes")
	}

	routes, err := s.RouteStats(ctx, time.Now().Add(-time.Hour))
	if err != nil || len(routes) == 0 {
		t.Fatalf("route stats: %v %v", routes, err)
	}
	if routes[0].Count != 100 || routes[0].P99Latency < 90 {
		t.Errorf("route detail: %+v", routes[0])
	}

	svcs, err := s.ServiceStats(ctx, time.Now().Add(-time.Hour))
	if err != nil || len(svcs) == 0 {
		t.Fatalf("service stats: %v %v", svcs, err)
	}
	if svcs[0].Requests != 100 {
		t.Errorf("service stat: %+v", svcs[0])
	}
}

func testPruneBefore(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	for i := 0; i < 20; i++ {
		mustSave(t, s, Record(200, 1, "/api/x", "acme"))
	}
	// Everything counts as old.
	n, err := s.PruneBefore(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("prune before: %v", err)
	}
	if n != 20 {
		t.Errorf("PruneBefore removed %d, want 20", n)
	}
	if c, _ := s.Count(ctx); c != 0 {
		t.Errorf("store should be empty, count=%d", c)
	}
	// A no-op prune must report zero rather than erroring.
	if n, err := s.PruneBefore(ctx, time.Now().Add(-time.Hour)); err != nil || n != 0 {
		t.Errorf("empty PruneBefore = %d, %v; want 0, nil", n, err)
	}
}

func testPrune(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	for i := 0; i < 50; i++ {
		mustSave(t, s, Record(200, 1, "/x", "acme"))
	}
	removed, err := s.Prune(ctx, 20)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 30 {
		t.Errorf("Prune removed %d, want 30", removed)
	}
	if c, _ := s.Count(ctx); c != 20 {
		t.Errorf("want 20 remaining, got %d", c)
	}
	// Under the cap, nothing should be deleted.
	if n, err := s.Prune(ctx, 100); err != nil || n != 0 {
		t.Errorf("Prune under the cap = %d, %v; want 0, nil", n, err)
	}
}

func testRecentFunc(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	for i := 0; i < 25; i++ {
		mustSave(t, s, Record(200, float64(i), "/api/x", "acme"))
	}
	since := time.Now().Add(-time.Hour)

	var streamed []ext.Record
	if err := s.RecentFunc(ctx, since, 0, func(r *ext.Record) error {
		streamed = append(streamed, *r)
		return nil
	}); err != nil {
		t.Fatalf("RecentFunc: %v", err)
	}
	materialised, err := s.Recent(ctx, since, 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	// The streaming and slice forms must agree, including order — callers
	// switch between them purely for memory reasons.
	if len(streamed) != len(materialised) || len(streamed) != 25 {
		t.Fatalf("streamed %d, materialised %d, want 25", len(streamed), len(materialised))
	}
	for i := range streamed {
		if streamed[i].ID != materialised[i].ID {
			t.Fatalf("order diverges at %d: %d vs %d", i, streamed[i].ID, materialised[i].ID)
		}
	}

	t.Run("limit is honoured", func(t *testing.T) {
		n := 0
		if err := s.RecentFunc(ctx, since, 10, func(*ext.Record) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
		if n != 10 {
			t.Errorf("read %d records with limit 10", n)
		}
	})

	t.Run("callback error stops the walk", func(t *testing.T) {
		stop := errors.New("enough")
		n := 0
		err := s.RecentFunc(ctx, since, 0, func(*ext.Record) error {
			n++
			if n == 3 {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) {
			t.Errorf("error = %v, want the callback's", err)
		}
		if n != 3 {
			t.Errorf("kept walking after the callback stopped: %d", n)
		}
	})
}

// testStreams pins the rule that a streaming response's DurationMS is a
// connection lifetime, not a latency. A driver that includes streams in its
// percentiles lets one long SSE connection define a route's p95 for the whole
// window.
func testStreams(t *testing.T, open OpenFunc) {
	ctx := context.Background()
	s := open(t)
	for i := 0; i < 9; i++ {
		mustSave(t, s, Record(200, 10, "/api/x", "acme"))
	}
	stream := Record(200, 600_000, "/api/x", "acme") // a 10-minute stream
	stream.Stream = true
	mustSave(t, s, stream)

	st, err := s.Stats(ctx, time.Now().Add(-time.Hour), time.Minute)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if st.P95LatencyMS > 100 {
		t.Errorf("p95 = %.0fms — the stream leaked into latency percentiles", st.P95LatencyMS)
	}
	// It is still traffic, and must still be counted as such.
	if st.Total != 10 {
		t.Errorf("total = %d, want 10: streams are still requests", st.Total)
	}

	routes, err := s.RouteStats(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("route stats: %v", err)
	}
	for _, r := range routes {
		if r.P99Latency > 100 {
			t.Errorf("route %s p99 = %.0fms — stream leaked in", r.Route, r.P99Latency)
		}
	}

	// The flag itself must survive storage, or the dashboard cannot show it.
	recs, _, err := s.Query(ctx, ext.Filter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Stream {
			found = true
		}
	}
	if !found {
		t.Error("the Stream flag did not survive a storage round trip")
	}
}

func mustSave(t *testing.T, s ext.Store, r *ext.Record) {
	t.Helper()
	if err := s.Save(context.Background(), r); err != nil {
		t.Fatalf("save: %v", err)
	}
}
