package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Two LogStore drivers means two chances to drift apart. This suite is the
// contract: every driver runs the identical assertions, so a Postgres query
// that quietly returns different results than SQLite fails here rather than
// in someone's dashboard.
//
// Postgres is skipped unless OPTICTRACE_TEST_POSTGRES is set to a DSN:
//
//	docker run -d -e POSTGRES_PASSWORD=optic -e POSTGRES_DB=optictrace -p 15432:5432 postgres:16-alpine
//	OPTICTRACE_TEST_POSTGRES='postgres://postgres:optic@localhost:15432/optictrace?sslmode=disable' go test ./internal/store
//
// ClickHouse likewise, via OPTICTRACE_TEST_CLICKHOUSE:
//
//	docker run -d -e CLICKHOUSE_DB=optic -e CLICKHOUSE_USER=optic -e CLICKHOUSE_PASSWORD=optic -p 19010:9000 clickhouse/clickhouse-server:24.8-alpine
//	OPTICTRACE_TEST_CLICKHOUSE='clickhouse://optic:optic@localhost:19010/optic' go test ./internal/store

type driverFactory struct {
	name string
	open func(t *testing.T) LogStore
}

func drivers(t *testing.T) []driverFactory {
	out := []driverFactory{{
		name: "sqlite",
		open: func(t *testing.T) LogStore {
			s, err := NewSQLite(filepath.Join(t.TempDir(), "conf.db"))
			if err != nil {
				t.Fatalf("open sqlite: %v", err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
	}}
	if dsn := os.Getenv("OPTICTRACE_TEST_POSTGRES"); dsn != "" {
		out = append(out, driverFactory{
			name: "postgres",
			open: func(t *testing.T) LogStore {
				s, err := NewPostgres(dsn)
				if err != nil {
					t.Fatalf("open postgres: %v", err)
				}
				// Each test starts from a clean table.
				if _, err := s.db.Exec(`TRUNCATE logs RESTART IDENTITY`); err != nil {
					t.Fatalf("truncate: %v", err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			},
		})
	}
	if dsn := os.Getenv("OPTICTRACE_TEST_CLICKHOUSE"); dsn != "" {
		out = append(out, driverFactory{
			name: "clickhouse",
			open: func(t *testing.T) LogStore {
				s, err := NewClickHouse(dsn)
				if err != nil {
					t.Fatalf("open clickhouse: %v", err)
				}
				// Each test starts from a clean table. TRUNCATE is synchronous
				// for MergeTree, unlike ALTER ... DELETE.
				if _, err := s.db.Exec(`TRUNCATE TABLE logs`); err != nil {
					t.Fatalf("truncate: %v", err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			},
		})
	}
	return out
}

func confRecord(status int, durMS float64, path, tenant string) *Record {
	return &Record{
		Time: time.Now(), Service: "conf", Method: "POST", Path: path,
		Query: "page=2&api_key=" + "[REDACTED]",
		Route: "/api/**", Status: status, DurationMS: durMS,
		RequestHeaders: map[string]string{"Content-Type": "application/json"},
		RequestBody:    `{"amount":1}`,
		Labels:         map[string]string{"tenant": tenant},
		MatchedRules:   []string{"r1"},
		Meters:         map[string]float64{"tokens": 10},
		ReqBytes:       12, RespBytes: 34,
	}
}

func TestConformance(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			s := d.open(t)

			// --- save + roundtrip ------------------------------------------
			if err := s.Save(ctx, confRecord(201, 12.5, "/api/v1/payments/charge", "acme")); err != nil {
				t.Fatalf("save: %v", err)
			}
			if err := s.Save(ctx, confRecord(500, 99, "/api/v1/orders", "globex")); err != nil {
				t.Fatalf("save: %v", err)
			}
			recs, total, err := s.Query(ctx, Filter{})
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if total != 2 || len(recs) != 2 {
				t.Fatalf("want 2 records, got total=%d len=%d", total, len(recs))
			}
			if recs[0].Path != "/api/v1/orders" {
				t.Errorf("expected newest first, got %s", recs[0].Path)
			}
			r := recs[1]
			if r.RequestHeaders["Content-Type"] != "application/json" ||
				r.Labels["tenant"] != "acme" || r.MatchedRules[0] != "r1" ||
				r.Meters["tokens"] != 10 || r.DurationMS != 12.5 || r.Query == "" {
				t.Errorf("roundtrip mismatch: %+v", r)
			}

			// --- filters ---------------------------------------------------
			if recs, _, _ := s.Query(ctx, Filter{StatusMin: 500}); len(recs) != 1 || recs[0].Status != 500 {
				t.Errorf("status filter: %+v", recs)
			}
			if recs, _, _ := s.Query(ctx, Filter{PathPrefix: "/api/v1/payments"}); len(recs) != 1 {
				t.Errorf("path filter: %+v", recs)
			}
			if recs, _, _ := s.Query(ctx, Filter{Search: "amount"}); len(recs) != 2 {
				t.Errorf("body search: %+v", recs)
			}
			if recs, _, _ := s.Query(ctx, Filter{Method: "post"}); len(recs) != 2 {
				t.Errorf("method filter should be case-insensitive: %+v", recs)
			}

			// --- get by id --------------------------------------------------
			got, err := s.Get(ctx, recs[0].ID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.ID != recs[0].ID {
				t.Errorf("get returned wrong record")
			}

			// --- usage aggregation -------------------------------------------
			usage, err := s.UsageByLabel(ctx, time.Now().Add(-time.Hour), "tenant")
			if err != nil {
				t.Fatalf("usage: %v", err)
			}
			byName := map[string]Usage{}
			for _, u := range usage {
				byName[u.Consumer] = u
			}
			if byName["acme"].Requests != 1 || byName["globex"].Errors != 1 {
				t.Errorf("usage aggregation wrong: %+v", usage)
			}
			if byName["acme"].Meters["tokens"] != 10 {
				t.Errorf("meters should aggregate per consumer: %+v", byName["acme"].Meters)
			}

			// --- rule match counts --------------------------------------------
			matches, err := s.RuleMatchCounts(ctx, time.Now().Add(-time.Hour), []string{"r1", "nope"})
			if err != nil {
				t.Fatalf("rule counts: %v", err)
			}
			counts := map[string]int64{}
			for _, m := range matches {
				counts[m.Rule] = m.Count
			}
			if counts["r1"] != 2 || counts["nope"] != 0 {
				t.Errorf("rule match counts: %+v", counts)
			}

			// --- purge isolates one consumer -----------------------------------
			removed, err := s.Purge(ctx, "tenant", "acme", time.Time{})
			if err != nil {
				t.Fatalf("purge: %v", err)
			}
			if removed != 1 {
				t.Errorf("purge removed %d, want 1", removed)
			}
			_, total, _ = s.Query(ctx, Filter{})
			if total != 1 {
				t.Errorf("purge should leave globex behind, total=%d", total)
			}
			if _, err := s.Purge(ctx, "", "", time.Time{}); err == nil {
				t.Error("purge without label/value must error rather than delete everything")
			}
		})
	}
}

// TestConformancePurgeIsLiteral guards the one mistake an erasure tool must
// never make: deleting a bystander's data. SQLite matches labels with LIKE, so
// a tenant value containing % or _ used to be interpreted as a wildcard —
// purging "acme_1" also destroyed "acmeX1", and "a%" destroyed every tenant
// beginning with "a". Postgres compares exactly and never had the bug, which is
// exactly why this belongs in the shared suite: the drivers must agree.
func TestConformancePurgeIsLiteral(t *testing.T) {
	cases := []struct{ name, target, bystander string }{
		{"underscore", "acme_1", "acmeX1"},
		{"percent", "a%", "apex"},
		{"backslash", `acme\1`, `acme\\1`},
	}
	for _, d := range drivers(t) {
		for _, tc := range cases {
			t.Run(d.name+"/"+tc.name, func(t *testing.T) {
				ctx := context.Background()
				s := d.open(t)
				for _, tenant := range []string{tc.target, tc.bystander} {
					if err := s.Save(ctx, confRecord(200, 1, "/api/x", tenant)); err != nil {
						t.Fatalf("save %q: %v", tenant, err)
					}
				}
				removed, err := s.Purge(ctx, "tenant", tc.target, time.Time{})
				if err != nil {
					t.Fatalf("purge: %v", err)
				}
				if removed != 1 {
					t.Errorf("purge %q removed %d rows, want 1", tc.target, removed)
				}
				recs, total, err := s.Query(ctx, Filter{})
				if err != nil {
					t.Fatalf("query: %v", err)
				}
				if total != 1 {
					t.Fatalf("purging %q left %d rows, want only %q to survive",
						tc.target, total, tc.bystander)
				}
				if got := recs[0].Labels["tenant"]; got != tc.bystander {
					t.Errorf("survivor is %q, want the bystander %q", got, tc.bystander)
				}
			})
		}
	}
}

func TestConformanceStatsAndRetention(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			s := d.open(t)
			for i := 0; i < 100; i++ {
				status := 200
				if i%10 == 0 {
					status = 500
				}
				if err := s.Save(ctx, confRecord(status, float64(i+1), "/api/x", "acme")); err != nil {
					t.Fatal(err)
				}
			}
			st, err := s.Stats(ctx, time.Now().Add(-time.Hour), time.Minute)
			if err != nil {
				t.Fatalf("stats: %v", err)
			}
			if st.Total != 100 || st.Errors != 10 || st.ErrorRate != 0.1 {
				t.Errorf("totals: %+v", st)
			}
			// Durations are 1..100ms. Both drivers must land in the same band
			// even though one uses OFFSET and the other percentile_cont.
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
				t.Errorf("missing series/top routes")
			}

			routes, err := s.RouteStats(ctx, time.Now().Add(-time.Hour))
			if err != nil || len(routes) == 0 {
				t.Fatalf("route stats: %v %v", routes, err)
			}
			if routes[0].Count != 100 || routes[0].P99Latency < 90 {
				t.Errorf("route detail: %+v", routes[0])
			}

			// --- age-based retention -------------------------------------
			n, err := s.PruneBefore(ctx, time.Now().Add(time.Hour)) // everything is "old"
			if err != nil {
				t.Fatalf("prune before: %v", err)
			}
			if n != 100 {
				t.Errorf("PruneBefore removed %d, want 100", n)
			}
			if c, _ := s.Count(ctx); c != 0 {
				t.Errorf("store should be empty, count=%d", c)
			}
		})
	}
}

func TestConformanceRowPrune(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			s := d.open(t)
			for i := 0; i < 50; i++ {
				_ = s.Save(ctx, confRecord(200, 1, "/x", "acme"))
			}
			removed, err := s.Prune(ctx, 20)
			if err != nil {
				t.Fatal(err)
			}
			if removed != 30 {
				t.Errorf("Prune removed %d, want 30", removed)
			}
			if c, _ := s.Count(ctx); c != 20 {
				t.Errorf("want 20 remaining, got %d", c)
			}
		})
	}
}

// RecentFunc is the streaming form of Recent. Both must agree, and RecentFunc
// must stop early when the callback asks it to — the whole point is that a
// caller never has to hold the full window in memory.
func TestConformanceRecentFunc(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			s := d.open(t)
			for i := 0; i < 25; i++ {
				if err := s.Save(ctx, confRecord(200, float64(i), "/api/x", "acme")); err != nil {
					t.Fatalf("save: %v", err)
				}
			}
			since := time.Now().Add(-time.Hour)

			var streamed []Record
			if err := s.RecentFunc(ctx, since, 0, func(r *Record) error {
				streamed = append(streamed, *r)
				return nil
			}); err != nil {
				t.Fatalf("RecentFunc: %v", err)
			}
			materialised, err := s.Recent(ctx, since, 0)
			if err != nil {
				t.Fatalf("Recent: %v", err)
			}
			if len(streamed) != len(materialised) || len(streamed) != 25 {
				t.Fatalf("streamed %d, materialised %d, want 25",
					len(streamed), len(materialised))
			}
			for i := range streamed {
				if streamed[i].ID != materialised[i].ID {
					t.Fatalf("order diverges at %d: %d vs %d",
						i, streamed[i].ID, materialised[i].ID)
				}
			}

			t.Run("limit is honoured", func(t *testing.T) {
				n := 0
				if err := s.RecentFunc(ctx, since, 10, func(*Record) error { n++; return nil }); err != nil {
					t.Fatal(err)
				}
				if n != 10 {
					t.Errorf("read %d records with limit 10", n)
				}
			})

			t.Run("callback error stops the walk", func(t *testing.T) {
				stop := errors.New("enough")
				n := 0
				err := s.RecentFunc(ctx, since, 0, func(*Record) error {
					n++
					if n == 3 {
						return stop
					}
					return nil
				})
				if !errors.Is(err, stop) {
					t.Errorf("error = %v, want it to wrap the callback's", err)
				}
				if n != 3 {
					t.Errorf("kept walking after the callback stopped: %d", n)
				}
			})
		})
	}
}

// RuleMatchCounts must report a zero for a rule that never fired — that is the
// interesting answer for a rule you expected to be matching — and must count
// each rule in a multi-rule record.
func TestConformanceRuleMatchCounts(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			s := d.open(t)
			for _, rules := range [][]string{
				{"redact-cards", "label-tenant"},
				{"redact-cards"},
				{"label-tenant"},
				nil,
			} {
				r := confRecord(200, 1, "/api/x", "acme")
				r.MatchedRules = rules
				if err := s.Save(ctx, r); err != nil {
					t.Fatalf("save: %v", err)
				}
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
			if len(got) != 3 {
				t.Errorf("every requested rule should be reported, got %d", len(got))
			}
		})
	}
}

// Streams carry a connection lifetime in DurationMS, so they must not enter
// latency percentiles — one long SSE connection would otherwise define a
// route's p95 for the whole window.
func TestConformanceStreamsExcludedFromPercentiles(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			ctx := context.Background()
			s := d.open(t)
			for i := 0; i < 9; i++ {
				if err := s.Save(ctx, confRecord(200, 10, "/api/x", "acme")); err != nil {
					t.Fatal(err)
				}
			}
			stream := confRecord(200, 600_000, "/api/x", "acme") // a 10-minute stream
			stream.Stream = true
			if err := s.Save(ctx, stream); err != nil {
				t.Fatal(err)
			}

			st, err := s.Stats(ctx, time.Now().Add(-time.Hour), time.Minute)
			if err != nil {
				t.Fatalf("stats: %v", err)
			}
			if st.P95LatencyMS > 100 {
				t.Errorf("p95 = %.0fms — the stream leaked into latency percentiles", st.P95LatencyMS)
			}
			// It should still be counted as traffic.
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
		})
	}
}
