package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite: no CGO, single-binary friendly
)

// SQLiteStore is the default embedded LogStore. WAL mode keeps concurrent
// dashboard reads from blocking the single async writer.
type SQLiteStore struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS logs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	ts            INTEGER NOT NULL,   -- unix milliseconds
	service       TEXT NOT NULL DEFAULT '',
	method        TEXT NOT NULL DEFAULT '',
	path          TEXT NOT NULL DEFAULT '',
	query         TEXT NOT NULL DEFAULT '',
	route         TEXT NOT NULL DEFAULT '',
	status        INTEGER NOT NULL DEFAULT 0,
	duration_ms   REAL NOT NULL DEFAULT 0,
	remote        TEXT NOT NULL DEFAULT '',
	source        TEXT NOT NULL DEFAULT 'proxy',
	req_headers   TEXT NOT NULL DEFAULT '',
	resp_headers  TEXT NOT NULL DEFAULT '',
	req_body      TEXT NOT NULL DEFAULT '',
	resp_body     TEXT NOT NULL DEFAULT '',
	req_trunc     INTEGER NOT NULL DEFAULT 0,
	resp_trunc    INTEGER NOT NULL DEFAULT 0,
	req_bytes     INTEGER NOT NULL DEFAULT 0,
	resp_bytes    INTEGER NOT NULL DEFAULT 0,
	labels        TEXT NOT NULL DEFAULT '',
	matched_rules TEXT NOT NULL DEFAULT '',
	meters        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_ts     ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_status ON logs(status);
CREATE INDEX IF NOT EXISTS idx_logs_route  ON logs(route);
`

func NewSQLite(dsn string) (*SQLiteStore, error) {
	// _pragma via DSN: applied to every pooled connection.
	db, err := sql.Open("sqlite",
		dsn+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Migration for databases created before the meters column existed;
	// "duplicate column" from up-to-date schemas is expected and ignored.
	for _, col := range []string{"meters", "query"} {
		_, err := db.Exec(`ALTER TABLE logs ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`)
		if err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("migrate schema (%s): %w", col, err)
		}
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Save(ctx context.Context, r *Record) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO logs (ts, service, method, path, query, route, status, duration_ms,
			remote, source, req_headers, resp_headers, req_body, resp_body,
			req_trunc, resp_trunc, req_bytes, resp_bytes, labels, matched_rules, meters)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Time.UnixMilli(), r.Service, r.Method, r.Path, r.Query, r.Route, r.Status,
		r.DurationMS,
		r.Remote, r.Source,
		mustJSON(r.RequestHeaders), mustJSON(r.ResponseHeaders),
		r.RequestBody, r.ResponseBody,
		boolInt(r.ReqTruncated), boolInt(r.RespTruncated),
		r.ReqBytes, r.RespBytes,
		mustJSON(r.Labels), mustJSON(r.MatchedRules), mustJSON(r.Meters),
	)
	return err
}

func (s *SQLiteStore) Query(ctx context.Context, f Filter) ([]Record, int64, error) {
	where, args := buildWhere(f)

	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM logs"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := "SELECT id, ts, service, method, path, query, route, status, duration_ms, remote, source, " +
		"req_headers, resp_headers, req_body, resp_body, req_trunc, resp_trunc, " +
		"req_bytes, resp_bytes, labels, matched_rules, meters FROM logs" + where +
		" ORDER BY id DESC LIMIT ? OFFSET ?"
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *rec)
	}
	return out, total, rows.Err()
}

func (s *SQLiteStore) Get(ctx context.Context, id int64) (*Record, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, ts, service, method, path, query, route,
		status, duration_ms, remote, source, req_headers, resp_headers, req_body,
		resp_body, req_trunc, resp_trunc, req_bytes, resp_bytes, labels, matched_rules, meters
		FROM logs WHERE id = ?`, id)
	return scanRecord(row)
}

func (s *SQLiteStore) Stats(ctx context.Context, since time.Time, bucket time.Duration) (*Stats, error) {
	sinceMs := since.UnixMilli()
	st := &Stats{StatusCounts: map[string]int64{}}

	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(status >= 500), 0) FROM logs WHERE ts >= ?`,
		sinceMs).Scan(&st.Total, &st.Errors)
	if err != nil {
		return nil, err
	}
	if st.Total > 0 {
		st.ErrorRate = float64(st.Errors) / float64(st.Total)
	}

	// Latency percentiles via ordered OFFSET — exact, and fine at the row
	// counts retention allows (~100k).
	for _, pc := range []struct {
		q   float64
		dst *float64
	}{{0.50, &st.P50LatencyMS}, {0.95, &st.P95LatencyMS}, {0.99, &st.P99LatencyMS}} {
		offset := int64(pc.q * float64(st.Total))
		if offset >= st.Total && st.Total > 0 {
			offset = st.Total - 1
		}
		err := s.db.QueryRowContext(ctx,
			`SELECT duration_ms FROM logs WHERE ts >= ? ORDER BY duration_ms LIMIT 1 OFFSET ?`,
			sinceMs, offset).Scan(pc.dst)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
	}

	// Status class breakdown.
	rows, err := s.db.QueryContext(ctx,
		`SELECT (status/100)*100, COUNT(*) FROM logs WHERE ts >= ? GROUP BY status/100`, sinceMs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var class int
		var n int64
		if err := rows.Scan(&class, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.StatusCounts[fmt.Sprintf("%dxx", class/100)] = n
	}
	rows.Close()

	// Traffic time series.
	bms := bucket.Milliseconds()
	if bms <= 0 {
		bms = 60_000
	}
	rows, err = s.db.QueryContext(ctx,
		`SELECT (ts/?)*?, COUNT(*), COALESCE(SUM(status >= 500), 0), COALESCE(AVG(duration_ms), 0)
		 FROM logs WHERE ts >= ? GROUP BY ts/? ORDER BY 1`,
		bms, bms, sinceMs, bms)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t int64
		var b TimeBucket
		if err := rows.Scan(&t, &b.Count, &b.Errors, &b.AvgLatency); err != nil {
			rows.Close()
			return nil, err
		}
		b.Time = time.UnixMilli(t)
		st.Series = append(st.Series, b)
	}
	rows.Close()

	// Top routes with an approximate per-route p95 (max as cheap stand-in
	// would mislead; use exact subquery per route — route count is small).
	rows, err = s.db.QueryContext(ctx,
		`SELECT route, method, COUNT(*) c, COALESCE(SUM(status >= 500), 0), COALESCE(AVG(duration_ms), 0)
		 FROM logs WHERE ts >= ? GROUP BY route, method ORDER BY c DESC LIMIT 10`, sinceMs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rs RouteStat
		if err := rows.Scan(&rs.Route, &rs.Method, &rs.Count, &rs.Errors, &rs.AvgLatency); err != nil {
			rows.Close()
			return nil, err
		}
		st.TopRoutes = append(st.TopRoutes, rs)
	}
	rows.Close()
	for i := range st.TopRoutes {
		rs := &st.TopRoutes[i]
		offset := int64(0.95 * float64(rs.Count))
		if offset >= rs.Count {
			offset = rs.Count - 1
		}
		err := s.db.QueryRowContext(ctx,
			`SELECT duration_ms FROM logs WHERE ts >= ? AND route = ? AND method = ?
			 ORDER BY duration_ms LIMIT 1 OFFSET ?`,
			sinceMs, rs.Route, rs.Method, offset).Scan(&rs.P95Latency)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
	}
	return st, nil
}

func (s *SQLiteStore) RouteStats(ctx context.Context, since time.Time) ([]RouteDetail, error) {
	sinceMs := since.UnixMilli()
	rows, err := s.db.QueryContext(ctx,
		`SELECT route, method, COUNT(*) c, COALESCE(SUM(status >= 500), 0),
		        COALESCE(AVG(duration_ms), 0),
		        COALESCE(SUM(req_bytes), 0), COALESCE(SUM(resp_bytes), 0)
		 FROM logs WHERE ts >= ? GROUP BY route, method ORDER BY c DESC LIMIT 200`, sinceMs)
	if err != nil {
		return nil, err
	}
	var out []RouteDetail
	for rows.Next() {
		var rd RouteDetail
		if err := rows.Scan(&rd.Route, &rd.Method, &rd.Count, &rd.Errors,
			&rd.AvgLatency, &rd.ReqBytes, &rd.RespBytes); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, rd)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Exact per-route percentiles via ordered OFFSET (route count is small,
	// each subquery hits idx_logs_route).
	for i := range out {
		rd := &out[i]
		for _, pc := range []struct {
			q   float64
			dst *float64
		}{{0.50, &rd.P50Latency}, {0.95, &rd.P95Latency}, {0.99, &rd.P99Latency}} {
			offset := int64(pc.q * float64(rd.Count))
			if offset >= rd.Count {
				offset = rd.Count - 1
			}
			err := s.db.QueryRowContext(ctx,
				`SELECT duration_ms FROM logs WHERE ts >= ? AND route = ? AND method = ?
				 ORDER BY duration_ms LIMIT 1 OFFSET ?`,
				sinceMs, rd.Route, rd.Method, offset).Scan(pc.dst)
			if err != nil && err != sql.ErrNoRows {
				return nil, err
			}
		}
	}
	return out, nil
}

func (s *SQLiteStore) RuleMatchCounts(ctx context.Context, since time.Time, ruleNames []string) ([]RuleMatch, error) {
	sinceMs := since.UnixMilli()
	out := make([]RuleMatch, 0, len(ruleNames))
	for _, name := range ruleNames {
		// matched_rules is a JSON array of strings; match the quoted name.
		needle := `%"` + strings.ReplaceAll(name, `"`, ``) + `"%`
		var n int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM logs WHERE ts >= ? AND matched_rules LIKE ?`,
			sinceMs, needle).Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, RuleMatch{Rule: name, Count: n})
	}
	return out, nil
}

func (s *SQLiteStore) Recent(ctx context.Context, since time.Time, limit int) ([]Record, error) {
	if limit <= 0 || limit > 50_000 {
		limit = 20_000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, service, method, path, query, route, status, duration_ms, remote, source,
		        req_headers, resp_headers, req_body, resp_body, req_trunc, resp_trunc,
		        req_bytes, resp_bytes, labels, matched_rules, meters
		 FROM logs WHERE ts >= ? ORDER BY id DESC LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

// UsageByLabel aggregates in Go rather than SQL: labels/meters are stored
// as JSON text, and the window is bounded by retention (~100k rows), so a
// single narrow scan is simpler and fast enough.
func (s *SQLiteStore) UsageByLabel(ctx context.Context, since time.Time, label string) ([]Usage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT status, duration_ms, req_bytes, resp_bytes, labels, meters
		 FROM logs WHERE ts >= ?`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byConsumer := map[string]*Usage{}
	for rows.Next() {
		var status int
		var durMS float64
		var reqB, respB int64
		var labelsJSON, metersJSON string
		if err := rows.Scan(&status, &durMS, &reqB, &respB, &labelsJSON, &metersJSON); err != nil {
			return nil, err
		}
		var labels map[string]string
		fromJSON(labelsJSON, &labels)
		consumer := labels[label]
		if consumer == "" {
			consumer = "(unattributed)"
		}
		u := byConsumer[consumer]
		if u == nil {
			u = &Usage{Consumer: consumer}
			byConsumer[consumer] = u
		}
		u.Requests++
		if status >= 500 {
			u.Errors++
		}
		u.ReqBytes += reqB
		u.RespBytes += respB
		u.DurationMS += durMS
		if metersJSON != "" {
			var m map[string]float64
			fromJSON(metersJSON, &m)
			for name, v := range m {
				if u.Meters == nil {
					u.Meters = map[string]float64{}
				}
				u.Meters[name] += v
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Usage, 0, len(byConsumer))
	for _, u := range byConsumer {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out, nil
}

func (s *SQLiteStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logs`).Scan(&n)
	return n, err
}

func (s *SQLiteStore) Prune(ctx context.Context, maxRows int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM logs WHERE id <= (SELECT COALESCE(MAX(id), 0) - ? FROM logs)`, maxRows)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLiteStore) PruneBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM logs WHERE ts < ?`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Purge implements erasure requests. Labels are stored as a JSON object, so
// the match is on the exact `"label":"value"` pair — substring matching on
// the value alone would delete another tenant's data, which is the one
// mistake an erasure tool must never make.
func (s *SQLiteStore) Purge(ctx context.Context, label, value string, before time.Time) (int64, error) {
	if label == "" || value == "" {
		return 0, fmt.Errorf("purge requires both a label and a value")
	}
	pair, err := json.Marshal(map[string]string{label: value})
	if err != nil {
		return 0, err
	}
	// {"tenant":"acme"} -> "tenant":"acme"
	needle := "%" + strings.TrimSuffix(strings.TrimPrefix(string(pair), "{"), "}") + "%"

	query := `DELETE FROM logs WHERE labels LIKE ?`
	args := []any{needle}
	if !before.IsZero() {
		query += ` AND ts < ?`
		args = append(args, before.UnixMilli())
	}
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// --- helpers ----------------------------------------------------------------

func buildWhere(f Filter) (string, []any) {
	var conds []string
	var args []any
	if f.Method != "" {
		conds, args = append(conds, "method = ?"), append(args, strings.ToUpper(f.Method))
	}
	if f.PathPrefix != "" {
		conds, args = append(conds, "path LIKE ?"), append(args, f.PathPrefix+"%")
	}
	if f.Search != "" {
		like := "%" + f.Search + "%"
		conds = append(conds, "(path LIKE ? OR query LIKE ? OR req_body LIKE ? OR resp_body LIKE ?)")
		args = append(args, like, like, like, like)
	}
	if f.StatusMin > 0 {
		conds, args = append(conds, "status >= ?"), append(args, f.StatusMin)
	}
	if f.StatusMax > 0 {
		conds, args = append(conds, "status <= ?"), append(args, f.StatusMax)
	}
	if !f.Since.IsZero() {
		conds, args = append(conds, "ts >= ?"), append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		conds, args = append(conds, "ts <= ?"), append(args, f.Until.UnixMilli())
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

type scannable interface{ Scan(dest ...any) error }

func scanRecord(row scannable) (*Record, error) {
	var r Record
	var ts int64
	var reqH, respH, labels, rules, meters string
	var reqT, respT int
	err := row.Scan(&r.ID, &ts, &r.Service, &r.Method, &r.Path, &r.Query, &r.Route,
		&r.Status, &r.DurationMS, &r.Remote, &r.Source, &reqH, &respH,
		&r.RequestBody, &r.ResponseBody, &reqT, &respT,
		&r.ReqBytes, &r.RespBytes, &labels, &rules, &meters)
	if err != nil {
		return nil, err
	}
	r.Time = time.UnixMilli(ts)
	r.ReqTruncated, r.RespTruncated = reqT != 0, respT != 0
	fromJSON(reqH, &r.RequestHeaders)
	fromJSON(respH, &r.ResponseHeaders)
	fromJSON(labels, &r.Labels)
	fromJSON(rules, &r.MatchedRules)
	fromJSON(meters, &r.Meters)
	return &r, nil
}

func mustJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func fromJSON[T any](s string, dst *T) {
	if s != "" && s != "null" {
		_ = json.Unmarshal([]byte(s), dst)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
