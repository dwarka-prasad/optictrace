package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// seed builds a store with n records spread over 20 routes and 10 rules.
func seed(tb testing.TB, n int) *SQLiteStore {
	tb.Helper()
	s, err := NewSQLite(filepath.Join(tb.TempDir(), "b.db"))
	if err != nil {
		tb.Fatal(err)
	}
	ctx := context.Background()
	tx, _ := s.db.Begin()
	for i := 0; i < n; i++ {
		r := confRecord(200, float64(i%1000), fmt.Sprintf("/api/r%d", i%20), "acme")
		r.Route = fmt.Sprintf("/api/r%d", i%20)
		r.MatchedRules = []string{fmt.Sprintf("rule-%d", i%10)}
		_ = r
		if err := s.Save(ctx, r); err != nil {
			tb.Fatal(err)
		}
	}
	tx.Commit()
	return s
}

func BenchmarkRuleMatchCounts(b *testing.B) {
	s := seed(b, 50_000)
	names := make([]string, 10)
	for i := range names {
		names[i] = fmt.Sprintf("rule-%d", i)
	}
	since := time.Now().Add(-time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.RuleMatchCounts(context.Background(), since, names); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRouteStats(b *testing.B) {
	s := seed(b, 50_000)
	since := time.Now().Add(-time.Hour)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.RouteStats(context.Background(), since); err != nil {
			b.Fatal(err)
		}
	}
}

// The old rule-stats query, kept only to measure what changed.
func BenchmarkRuleMatchCountsOldLikeScan(b *testing.B) {
	s := seed(b, 50_000)
	since := time.Now().Add(-time.Hour).UnixMilli()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for r := 0; r < 10; r++ {
			var n int64
			err := s.db.QueryRow(
				`SELECT COUNT(*) FROM logs WHERE ts >= ? AND matched_rules LIKE ?`,
				since, fmt.Sprintf(`%%"rule-%d"%%`, r)).Scan(&n)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}
