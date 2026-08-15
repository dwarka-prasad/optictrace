package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pure-Go Postgres driver, no CGO
)

// PostgresStore is the multi-node LogStore. SQLite is perfect for a sidecar
// with one writer; the moment several agents (or several replicas of one
// agent) need to share history, they need a server they can all reach.
//
// Notes on the schema choice:
//   - JSONB rather than TEXT for headers/labels/meters, so usage aggregation
//     and label filtering happen in the database instead of in Go.
//   - Timestamps stay as bigint milliseconds, matching the SQLite driver, so
//     records are portable between the two without conversion surprises.
type PostgresStore struct {
	db *sql.DB
}

const pgSchema = `
CREATE TABLE IF NOT EXISTS logs (
	id            BIGSERIAL PRIMARY KEY,
	ts            BIGINT NOT NULL,
	service       TEXT NOT NULL DEFAULT '',
	method        TEXT NOT NULL DEFAULT '',
	path          TEXT NOT NULL DEFAULT '',
	query         TEXT NOT NULL DEFAULT '',
	route         TEXT NOT NULL DEFAULT '',
	status        INTEGER NOT NULL DEFAULT 0,
	duration_ms   DOUBLE PRECISION NOT NULL DEFAULT 0,
	remote        TEXT NOT NULL DEFAULT '',
	source        TEXT NOT NULL DEFAULT 'proxy',
	req_headers   JSONB NOT NULL DEFAULT '{}'::jsonb,
	resp_headers  JSONB NOT NULL DEFAULT '{}'::jsonb,
	req_body      TEXT NOT NULL DEFAULT '',
	resp_body     TEXT NOT NULL DEFAULT '',
	req_trunc     BOOLEAN NOT NULL DEFAULT false,
	resp_trunc    BOOLEAN NOT NULL DEFAULT false,
	req_bytes     BIGINT NOT NULL DEFAULT 0,
	resp_bytes    BIGINT NOT NULL DEFAULT 0,
	labels        JSONB NOT NULL DEFAULT '{}'::jsonb,
	matched_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
	meters        JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_logs_ts      ON logs(ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_status  ON logs(status);
CREATE INDEX IF NOT EXISTS idx_logs_route   ON logs(route, method);
CREATE INDEX IF NOT EXISTS idx_logs_service ON logs(service);
CREATE INDEX IF NOT EXISTS idx_logs_labels  ON logs USING gin(labels);
`

// NewPostgres opens (and migrates) a Postgres-backed store. dsn is a standard
// libpq/pgx URL: postgres://user:pass@host:5432/db?sslmode=disable
func NewPostgres(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	// Bounded pool: the agent's write path is a single async worker, and
	// dashboard reads are light. An unbounded pool would be a footgun on a
	// shared database.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if _, err := db.ExecContext(ctx, pgSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply postgres schema: %w", err)
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Save(ctx context.Context, r *Record) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO logs (ts, service, method, path, query, route, status, duration_ms,
			remote, source, req_headers, resp_headers, req_body, resp_body,
			req_trunc, resp_trunc, req_bytes, resp_bytes, labels, matched_rules, meters)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		r.Time.UnixMilli(), r.Service, r.Method, r.Path, r.Query, r.Route, r.Status,
		r.DurationMS, r.Remote, r.Source,
		jsonbOr(r.RequestHeaders, "{}"), jsonbOr(r.ResponseHeaders, "{}"),
		r.RequestBody, r.ResponseBody, r.ReqTruncated, r.RespTruncated,
		r.ReqBytes, r.RespBytes,
		jsonbOr(r.Labels, "{}"), jsonbOr(r.MatchedRules, "[]"), jsonbOr(r.Meters, "{}"),
	)
	return err
}

const pgColumns = `id, ts, service, method, path, query, route, status, duration_ms,
	remote, source, req_headers, resp_headers, req_body, resp_body,
	req_trunc, resp_trunc, req_bytes, resp_bytes, labels, matched_rules, meters`

func (s *PostgresStore) Query(ctx context.Context, f Filter) ([]Record, int64, error) {
	where, args := pgBuildWhere(f)

	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM logs"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := fmt.Sprintf("SELECT %s FROM logs%s ORDER BY id DESC LIMIT $%d OFFSET $%d",
		pgColumns, where, len(args)+1, len(args)+2)
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		rec, err := pgScan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *rec)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) Get(ctx context.Context, id int64) (*Record, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+pgColumns+" FROM logs WHERE id = $1", id)
	return pgScan(row)
}

func (s *PostgresStore) Stats(ctx context.Context, since time.Time, bucket time.Duration) (*Stats, error) {
	sinceMs := since.UnixMilli()
	st := &Stats{StatusCounts: map[string]int64{}}

	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0)
		 FROM logs WHERE ts >= $1`, sinceMs).Scan(&st.Total, &st.Errors)
	if err != nil {
		return nil, err
	}
	if st.Total > 0 {
		st.ErrorRate = float64(st.Errors) / float64(st.Total)
	}

	// percentile_cont does in one query what SQLite needs three OFFSET scans
	// for — the main reason this driver exists at scale.
	err = s.db.QueryRowContext(ctx,
		`SELECT COALESCE(percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms), 0),
		        COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), 0),
		        COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms), 0)
		 FROM logs WHERE ts >= $1`, sinceMs).
		Scan(&st.P50LatencyMS, &st.P95LatencyMS, &st.P99LatencyMS)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT (status/100)*100 AS class, COUNT(*) FROM logs WHERE ts >= $1 GROUP BY class`, sinceMs)
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

	bms := bucket.Milliseconds()
	if bms <= 0 {
		bms = 60_000
	}
	rows, err = s.db.QueryContext(ctx,
		`SELECT (ts/$1)*$1 AS b, COUNT(*),
		        COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0),
		        COALESCE(AVG(duration_ms), 0)
		 FROM logs WHERE ts >= $2 GROUP BY b ORDER BY b`, bms, sinceMs)
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

	rows, err = s.db.QueryContext(ctx,
		`SELECT route, method, COUNT(*) c,
		        COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0),
		        COALESCE(AVG(duration_ms), 0),
		        COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), 0)
		 FROM logs WHERE ts >= $1 GROUP BY route, method ORDER BY c DESC LIMIT 10`, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rs RouteStat
		if err := rows.Scan(&rs.Route, &rs.Method, &rs.Count, &rs.Errors, &rs.AvgLatency, &rs.P95Latency); err != nil {
			return nil, err
		}
		st.TopRoutes = append(st.TopRoutes, rs)
	}
	return st, rows.Err()
}

func (s *PostgresStore) RouteStats(ctx context.Context, since time.Time) ([]RouteDetail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT route, method, COUNT(*) c,
		        COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0),
		        COALESCE(AVG(duration_ms), 0),
		        COALESCE(SUM(req_bytes), 0), COALESCE(SUM(resp_bytes), 0),
		        COALESCE(percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms), 0),
		        COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), 0),
		        COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms), 0)
		 FROM logs WHERE ts >= $1 GROUP BY route, method ORDER BY c DESC LIMIT 200`,
		since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouteDetail
	for rows.Next() {
		var rd RouteDetail
		if err := rows.Scan(&rd.Route, &rd.Method, &rd.Count, &rd.Errors, &rd.AvgLatency,
			&rd.ReqBytes, &rd.RespBytes, &rd.P50Latency, &rd.P95Latency, &rd.P99Latency); err != nil {
			return nil, err
		}
		out = append(out, rd)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RuleMatchCounts(ctx context.Context, since time.Time, ruleNames []string) ([]RuleMatch, error) {
	out := make([]RuleMatch, 0, len(ruleNames))
	for _, name := range ruleNames {
		var n int64
		// JSONB containment against a real array beats the SQLite LIKE scan.
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM logs WHERE ts >= $1 AND matched_rules @> $2::jsonb`,
			since.UnixMilli(), fmt.Sprintf("[%q]", name)).Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, RuleMatch{Rule: name, Count: n})
	}
	return out, nil
}

func (s *PostgresStore) ServiceStats(ctx context.Context, since time.Time) ([]ServiceStat, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(service, ''), '(unnamed)') AS svc,
		        COUNT(*),
		        COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0),
		        COALESCE(AVG(duration_ms), 0),
		        COUNT(DISTINCT route),
		        string_agg(DISTINCT source, ', '),
		        MAX(ts),
		        COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms), 0)
		 FROM logs WHERE ts >= $1 GROUP BY svc ORDER BY 2 DESC`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceStat
	for rows.Next() {
		var st ServiceStat
		var lastMs int64
		if err := rows.Scan(&st.Service, &st.Requests, &st.Errors, &st.AvgLatency,
			&st.Routes, &st.Sources, &lastMs, &st.P95Latency); err != nil {
			return nil, err
		}
		st.LastSeen = time.UnixMilli(lastMs)
		if st.Requests > 0 {
			st.ErrorRate = float64(st.Errors) / float64(st.Requests)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logs`).Scan(&n)
	return n, err
}

func (s *PostgresStore) Recent(ctx context.Context, since time.Time, limit int) ([]Record, error) {
	if limit <= 0 || limit > 50_000 {
		limit = 20_000
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+pgColumns+" FROM logs WHERE ts >= $1 ORDER BY id DESC LIMIT $2",
		since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		rec, err := pgScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UsageByLabel(ctx context.Context, since time.Time, label string) ([]Usage, error) {
	// Grouping happens in the database via JSONB extraction; the SQLite
	// driver has to scan and aggregate in Go.
	rows, err := s.db.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(labels->>$1, ''), '(unattributed)') AS consumer,
		        COUNT(*),
		        COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(req_bytes), 0), COALESCE(SUM(resp_bytes), 0),
		        COALESCE(SUM(duration_ms), 0)
		 FROM logs WHERE ts >= $2 GROUP BY consumer ORDER BY 2 DESC`,
		label, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.Consumer, &u.Requests, &u.Errors, &u.ReqBytes, &u.RespBytes, &u.DurationMS); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Index AFTER the slice stops growing: pointers taken during append go
	// stale the moment the backing array is reallocated.
	byConsumer := make(map[string]*Usage, len(out))
	for i := range out {
		byConsumer[out[i].Consumer] = &out[i]
	}

	// Meters are a dynamic key space, so sum them in a second pass.
	mrows, err := s.db.QueryContext(ctx,
		`SELECT COALESCE(NULLIF(labels->>$1, ''), '(unattributed)') AS consumer,
		        m.key, SUM((m.value)::text::double precision)
		 FROM logs, jsonb_each(meters) m
		 WHERE ts >= $2 GROUP BY consumer, m.key`,
		label, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var consumer, key string
		var val float64
		if err := mrows.Scan(&consumer, &key, &val); err != nil {
			return nil, err
		}
		if u := byConsumer[consumer]; u != nil {
			if u.Meters == nil {
				u.Meters = map[string]float64{}
			}
			u.Meters[key] = val
		}
	}
	return out, mrows.Err()
}

func (s *PostgresStore) Prune(ctx context.Context, maxRows int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM logs WHERE id <= (SELECT COALESCE(MAX(id), 0) - $1 FROM logs)`, maxRows)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) PruneBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM logs WHERE ts < $1`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) Purge(ctx context.Context, label, value string, before time.Time) (int64, error) {
	if label == "" || value == "" {
		return 0, fmt.Errorf("purge requires both a label and a value")
	}
	// Exact key/value match via JSONB, not a substring — deleting a
	// neighbouring tenant's data is the one unacceptable failure here.
	query := `DELETE FROM logs WHERE labels->>$1 = $2`
	args := []any{label, value}
	if !before.IsZero() {
		query += ` AND ts < $3`
		args = append(args, before.UnixMilli())
	}
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStore) Close() error { return s.db.Close() }

// --- helpers ----------------------------------------------------------------

// pgBuildWhere assembles a filter clause using $N placeholders. bind appends
// a value and returns its placeholder, so ordering can never drift out of
// sync with the argument slice.
func pgBuildWhere(f Filter) (string, []any) {
	var conds []string
	var args []any
	bind := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.Method != "" {
		conds = append(conds, "method = "+bind(strings.ToUpper(f.Method)))
	}
	if f.PathPrefix != "" {
		conds = append(conds, "path LIKE "+bind(f.PathPrefix+"%"))
	}
	if f.Search != "" {
		like := "%" + f.Search + "%"
		conds = append(conds, fmt.Sprintf("(path LIKE %s OR query LIKE %s OR req_body LIKE %s OR resp_body LIKE %s)",
			bind(like), bind(like), bind(like), bind(like)))
	}
	if f.StatusMin > 0 {
		conds = append(conds, "status >= "+bind(f.StatusMin))
	}
	if f.StatusMax > 0 {
		conds = append(conds, "status <= "+bind(f.StatusMax))
	}
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= "+bind(f.Since.UnixMilli()))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "ts <= "+bind(f.Until.UnixMilli()))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func pgScan(row scannable) (*Record, error) {
	var r Record
	var ts int64
	var reqH, respH, labels, rules, meters []byte
	err := row.Scan(&r.ID, &ts, &r.Service, &r.Method, &r.Path, &r.Query, &r.Route,
		&r.Status, &r.DurationMS, &r.Remote, &r.Source, &reqH, &respH,
		&r.RequestBody, &r.ResponseBody, &r.ReqTruncated, &r.RespTruncated,
		&r.ReqBytes, &r.RespBytes, &labels, &rules, &meters)
	if err != nil {
		return nil, err
	}
	r.Time = time.UnixMilli(ts)
	fromJSON(string(reqH), &r.RequestHeaders)
	fromJSON(string(respH), &r.ResponseHeaders)
	fromJSON(string(labels), &r.Labels)
	fromJSON(string(rules), &r.MatchedRules)
	fromJSON(string(meters), &r.Meters)
	emptyToNil(&r)
	return &r, nil
}

// emptyToNil keeps the two drivers' outputs identical: SQLite stores "" for
// absent maps and returns nil, while Postgres stores {} and would return an
// empty map. Conformance tests compare across both, so normalize here.
func emptyToNil(r *Record) {
	if len(r.RequestHeaders) == 0 {
		r.RequestHeaders = nil
	}
	if len(r.ResponseHeaders) == 0 {
		r.ResponseHeaders = nil
	}
	if len(r.Labels) == 0 {
		r.Labels = nil
	}
	if len(r.MatchedRules) == 0 {
		r.MatchedRules = nil
	}
	if len(r.Meters) == 0 {
		r.Meters = nil
	}
}

// jsonbOr marshals v, falling back to a valid empty JSON literal so the
// column never receives "" (which JSONB rejects).
func jsonbOr(v any, empty string) string {
	s := mustJSON(v)
	if s == "" || s == "null" {
		return empty
	}
	return s
}
