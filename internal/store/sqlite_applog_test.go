package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

func newAppLogStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLite(filepath.Join(t.TempDir(), "applog.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAppLogsRoundTripAndOrdering(t *testing.T) {
	s := newAppLogStore(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)

	// Inserted out of order on purpose: reading what a request did means
	// reading it in the order it happened, not the order it was written.
	lines := []ext.AppLog{
		{Time: base.Add(2 * time.Second), TraceID: "t1", SpanID: "s1", Level: "error", Message: "third"},
		{Time: base, TraceID: "t1", SpanID: "s1", Level: "info", Message: "first",
			Fields: map[string]string{"order": "42"}},
		{Time: base.Add(time.Second), TraceID: "t1", SpanID: "s1", Level: "warn", Message: "second"},
		{Time: base, TraceID: "t2", SpanID: "s2", Level: "info", Message: "other request"},
	}
	if err := s.SaveAppLogs(ctx, lines); err != nil {
		t.Fatal(err)
	}

	got, total, err := s.QueryAppLogs(ctx, ext.AppLogFilter{SpanID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(got) != 3 {
		t.Fatalf("span s1: got %d/%d lines, want 3", len(got), total)
	}
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Message != want {
			t.Errorf("position %d: got %q want %q (not chronological)", i, got[i].Message, want)
		}
	}
	if got[0].Fields["order"] != "42" {
		t.Errorf("structured fields lost: %v", got[0].Fields)
	}
	if !got[0].Time.Equal(base) {
		t.Errorf("timestamp round-trip: got %s want %s", got[0].Time, base)
	}
}

func TestAppLogLevelFilterIsBySeverityNotAlphabet(t *testing.T) {
	s := newAppLogStore(t)
	ctx := context.Background()
	for _, lvl := range []string{"debug", "info", "warn", "error", "fatal"} {
		if err := s.SaveAppLogs(ctx, []ext.AppLog{{
			Time: time.Now(), SpanID: "s", Level: lvl, Message: lvl,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	// Alphabetically "error" < "warn"; by severity it is the other way round.
	// A lexical comparison would return the wrong set here.
	got, _, err := s.QueryAppLogs(ctx, ext.AppLogFilter{SpanID: "s", LevelMin: "warn"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, l := range got {
		seen[l.Level] = true
	}
	for _, want := range []string{"warn", "error", "fatal"} {
		if !seen[want] {
			t.Errorf("level_min=warn dropped %q", want)
		}
	}
	for _, unwanted := range []string{"debug", "info"} {
		if seen[unwanted] {
			t.Errorf("level_min=warn kept %q", unwanted)
		}
	}
}

// Erasure that deletes a tenant's requests but leaves the log lines those
// requests wrote is not erasure — and a log line is the likelier place for the
// personal data to be sitting, because nobody redacts a log as carefully as a
// payload.
func TestPurgeAlsoErasesAppLogs(t *testing.T) {
	s := newAppLogStore(t)
	ctx := context.Background()

	save := func(trace, tenant string) {
		t.Helper()
		if err := s.Save(ctx, &ext.Record{
			Time: time.Now(), Service: "api", Method: "POST", Path: "/pay",
			Route: "/pay", Status: 200, TraceID: trace,
			Labels: map[string]string{"tenant": tenant},
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveAppLogs(ctx, []ext.AppLog{{
			Time: time.Now(), TraceID: trace, SpanID: trace + "-span",
			Level: "info", Message: "processing for " + tenant,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	save("trace-acme", "acme")
	save("trace-globex", "globex")

	if _, err := s.Purge(ctx, "tenant", "acme", time.Time{}); err != nil {
		t.Fatal(err)
	}

	gone, _, err := s.QueryAppLogs(ctx, ext.AppLogFilter{TraceID: "trace-acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 0 {
		t.Errorf("purge left %d app log line(s) behind: %+v", len(gone), gone)
	}
	// And it must not have taken the neighbour's data with it.
	kept, _, err := s.QueryAppLogs(ctx, ext.AppLogFilter{TraceID: "trace-globex"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 {
		t.Errorf("purge destroyed a bystander's logs: %d line(s) remain, want 1", len(kept))
	}
}

func TestAppLogRetentionIsIndependent(t *testing.T) {
	s := newAppLogStore(t)
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	if err := s.SaveAppLogs(ctx, []ext.AppLog{
		{Time: old, SpanID: "s", Message: "ancient"},
		{Time: time.Now(), SpanID: "s", Message: "recent"},
	}); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneAppLogsBefore(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned %d lines, want 1", n)
	}
	left, _, _ := s.QueryAppLogs(ctx, ext.AppLogFilter{SpanID: "s"})
	if len(left) != 1 || left[0].Message != "recent" {
		t.Errorf("wrong line survived: %+v", left)
	}
}

// A search for "100%" must find the line that says 100%, not every line.
func TestAppLogSearchEscapesWildcards(t *testing.T) {
	s := newAppLogStore(t)
	ctx := context.Background()
	if err := s.SaveAppLogs(ctx, []ext.AppLog{
		{Time: time.Now(), SpanID: "s", Message: "progress 100% complete"},
		{Time: time.Now(), SpanID: "s", Message: "unrelated line"},
	}); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.QueryAppLogs(ctx, ext.AppLogFilter{Search: "100%"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("search for %q matched %d lines, want 1", "100%", len(got))
	}
}
