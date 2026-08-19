package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/ext/exttest"
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
				// Each test starts from clean tables. Both of them: the suite
				// makes exact count assertions, and a leftover app log line
				// fails an assertion about records for no obvious reason.
				if _, err := s.db.Exec(`TRUNCATE logs, app_logs RESTART IDENTITY`); err != nil {
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
				// Each test starts from clean tables. TRUNCATE is synchronous
				// for MergeTree, unlike ALTER ... DELETE.
				for _, tbl := range []string{"logs", "app_logs"} {
					if _, err := s.db.Exec(`TRUNCATE TABLE IF EXISTS ` + tbl); err != nil {
						t.Fatalf("truncate %s: %v", tbl, err)
					}
				}
				t.Cleanup(func() { s.Close() })
				return s
			},
		})
	}
	return out
}

// The suite itself lives in ext/exttest so an out-of-tree driver runs the
// identical assertions. Keeping one copy is the point: two copies drift, and a
// driver passing "the conformance tests" would stop meaning anything.
func TestConformance(t *testing.T) {
	for _, d := range drivers(t) {
		t.Run(d.name, func(t *testing.T) {
			exttest.RunStoreSuite(t, func(t *testing.T) ext.Store { return d.open(t) })
		})
	}
}
