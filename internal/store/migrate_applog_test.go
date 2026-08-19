package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	_ "modernc.org/sqlite"
)

// An app_logs table created by v0.9.0 has no route column. Opening it must
// migrate rather than fail — someone upgrading in place is the normal case.
func TestAppLogsRouteMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly the v0.9.0 shape: no route column.
	if _, err := old.Exec(`CREATE TABLE app_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
		service TEXT NOT NULL DEFAULT '', trace_id TEXT NOT NULL DEFAULT '',
		span_id TEXT NOT NULL DEFAULT '', level TEXT NOT NULL DEFAULT '',
		message TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '',
		source TEXT NOT NULL DEFAULT '', truncated INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(
		`INSERT INTO app_logs (ts, service, span_id, level, message) VALUES (?,?,?,?,?)`,
		time.Now().UnixMilli(), "api", "span-1", "info", "written by the old version"); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("opening a v0.9.0 store failed instead of migrating: %v", err)
	}
	defer s.Close()

	lines, _, err := s.QueryAppLogs(context.Background(), ext.AppLogFilter{SpanID: "span-1"})
	if err != nil {
		t.Fatalf("query after migration: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("the pre-existing line was lost: %d line(s)", len(lines))
	}
	if lines[0].Message != "written by the old version" {
		t.Errorf("message changed: %q", lines[0].Message)
	}
	if lines[0].Route != "" {
		t.Errorf("a migrated row should have an empty route, got %q", lines[0].Route)
	}
	// And new writes carry a route.
	if err := s.SaveAppLogs(context.Background(), []ext.AppLog{
		{Time: time.Now(), SpanID: "span-2", Route: "/api/v1/payments/**", Level: "info", Message: "new"},
	}); err != nil {
		t.Fatal(err)
	}
	fresh, _, _ := s.QueryAppLogs(context.Background(), ext.AppLogFilter{SpanID: "span-2"})
	if len(fresh) != 1 || fresh[0].Route != "/api/v1/payments/**" {
		t.Errorf("route not stored after migration: %+v", fresh)
	}
}
