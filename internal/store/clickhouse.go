package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2" // pure Go: keeps CGO_ENABLED=0
)

// ClickHouseStore is the column-oriented LogStore driver.
//
// Why a third driver: every dashboard query here is a time-bucketed
// aggregation over a table that only grows — Stats, RouteStats, ServiceStats,
// UsageByLabel. SQLite and Postgres are row stores answering those with sorts
// and scans; ClickHouse answers them with column reads, and is a common choice
// for teams already keeping API traffic at volume.
//
// Two things work differently here than in the row stores, and both are
// visible in this file rather than hidden:
//
//   - There is no autoincrement. IDs are generated client-side (see nextID)
//     rather than by the database.
//   - DELETE is a mutation, applied asynchronously by default. Every delete
//     path runs with mutations_sync=2 so Purge and the retention functions
//     behave synchronously, as the shared conformance suite requires and as
//     an erasure request demands.
type ClickHouseStore struct {
	db *sql.DB
	// seq disambiguates IDs generated within the same millisecond.
	seq atomic.Int64
}

const chSchema = `
CREATE TABLE IF NOT EXISTS logs (
	id            Int64,
	ts            Int64,
	service       String,
	method        String,
	path          String,
	query         String,
	route         String,
	status        Int32,
	duration_ms   Float64,
	remote        String,
	source        String,
	req_headers   String,
	resp_headers  String,
	req_body      String,
	resp_body     String,
	req_trunc     UInt8,
	resp_trunc    UInt8,
	req_bytes     Int64,
	resp_bytes    Int64,
	labels        String,
	matched_rules String,
	meters        String,
	stream        UInt8,
	trace_id      String,
	span_id       String,
	parent_span   String
)
ENGINE = MergeTree
-- ts leads because every dashboard query is windowed by time; id breaks ties
-- and gives Query a stable newest-first order.
ORDER BY (ts, id)
SETTINGS index_granularity = 8192`

// chAppLogSchema is a separate table, not more columns on logs: many lines per
// exchange is a different cardinality entirely, and app logs want their own
// retention horizon.
const chAppLogSchema = `
CREATE TABLE IF NOT EXISTS app_logs (
	id        Int64,
	ts        Int64,
	service   String,
	trace_id  String,
	span_id   String,
	route     String,
	level     String,
	message   String,
	fields    String,
	source    String,
	truncated UInt8
)
ENGINE = MergeTree
-- span_id leads: "what did this request log" is the point, and it is the only
-- lookup that has to be fast on the fastest-growing table in the store.
ORDER BY (span_id, ts, id)
SETTINGS index_granularity = 8192`

// One statement per const, executed on its own: this driver's Exec takes a
// single statement, which is why the app-log schema is already separate.
const chSpanSchema = `
CREATE TABLE IF NOT EXISTS spans (
	id          Int64,
	ts          Int64,
	service     String,
	trace_id    String,
	span_id     String,
	parent_span String,
	name        String,
	kind        String,
	duration_ms Float64,
	error       String,
	attrs       String,
	route       String,
	source      String,
	truncated   UInt8
)
ENGINE = MergeTree
-- parent_span leads: "what ran inside this hop" is the waterfall's query and
-- the only lookup that has to be fast on a table growing faster than logs.
ORDER BY (parent_span, ts, id)
SETTINGS index_granularity = 8192`

// NewClickHouse opens (and migrates) a ClickHouse-backed store. dsn is a
// clickhouse-go URL: clickhouse://user:pass@host:9000/database
func NewClickHouse(dsn string) (*ClickHouseStore, error) {
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, fmt.Errorf("open clickhouse: %w", err)
	}
	// Same posture as the Postgres driver: the write path is one async worker
	// and dashboard reads are light, so an unbounded pool is a footgun on a
	// cluster shared with other workloads.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect clickhouse: %w", err)
	}
	if _, err := db.ExecContext(ctx, chSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if _, err := db.ExecContext(ctx, chAppLogSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply app-log schema: %w", err)
	}
	if _, err := db.ExecContext(ctx, chSpanSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply span schema: %w", err)
	}
	// Columns added after the initial release. ClickHouse has IF NOT EXISTS
	// for this, so no error-string matching is needed.
	for _, decl := range []string{
		`ALTER TABLE logs ADD COLUMN IF NOT EXISTS stream UInt8 DEFAULT 0`,
		`ALTER TABLE logs ADD COLUMN IF NOT EXISTS trace_id String DEFAULT ''`,
		`ALTER TABLE logs ADD COLUMN IF NOT EXISTS span_id String DEFAULT ''`,
		`ALTER TABLE logs ADD COLUMN IF NOT EXISTS parent_span String DEFAULT ''`,
		// app_logs shipped in v0.9.0 without route.
		`ALTER TABLE app_logs ADD COLUMN IF NOT EXISTS route String DEFAULT ''`,
	} {
		if _, err := db.ExecContext(ctx, decl); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate schema: %w", err)
		}
	}

	s := &ClickHouseStore{db: db}
	// Continue after whatever is already stored so IDs stay unique across
	// restarts even inside the same millisecond.
	var maxID int64
	_ = db.QueryRowContext(ctx, `SELECT max(id) FROM logs`).Scan(&maxID)
	s.seq.Store(maxID & idSeqMask)
	return s, nil
}

// ClickHouse has no autoincrement, so IDs are built here: milliseconds in the
// high bits keep them roughly ordered (which is what the dashboard's
// newest-first listing relies on), a per-process counter in the low bits makes
// records written in the same millisecond distinct.
const (
	idSeqBits = 20
	idSeqMask = (1 << idSeqBits) - 1
)

func (s *ClickHouseStore) nextID(t time.Time) int64 {
	return t.UnixMilli()<<idSeqBits | (s.seq.Add(1) & idSeqMask)
}

// syncMutations makes ALTER ... DELETE synchronous. Without it a delete
// returns before the data is gone, which would make `purge` — an erasure
// request — report success while the records were still readable.
const syncMutations = ` SETTINGS mutations_sync = 2`

func (s *ClickHouseStore) Save(ctx context.Context, r *Record) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO logs (id, ts, service, method, path, query, route, status, duration_ms,
			remote, source, req_headers, resp_headers, req_body, resp_body,
			req_trunc, resp_trunc, req_bytes, resp_bytes, labels, matched_rules, meters, stream, trace_id, span_id, parent_span)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.nextID(r.Time), r.Time.UnixMilli(), r.Service, r.Method, r.Path, r.Query,
		r.Route, int32(r.Status), r.DurationMS, r.Remote, r.Source,
		mustJSON(r.RequestHeaders), mustJSON(r.ResponseHeaders),
		r.RequestBody, r.ResponseBody,
		uint8(boolInt(r.ReqTruncated)), uint8(boolInt(r.RespTruncated)),
		r.ReqBytes, r.RespBytes,
		mustJSON(r.Labels), mustJSON(r.MatchedRules), mustJSON(r.Meters),
		uint8(boolInt(r.Stream)), r.TraceID, r.SpanID, r.ParentSpanID,
	)
	return err
}

const chColumns = `id, ts, service, method, path, query, route, status, duration_ms,
	remote, source, req_headers, resp_headers, req_body, resp_body,
	req_trunc, resp_trunc, req_bytes, resp_bytes, labels, matched_rules, meters, stream, trace_id, span_id, parent_span`

// chBuildWhere mirrors buildWhere for ClickHouse's ? placeholders.
func chBuildWhere(f Filter) (string, []any) {
	var conds []string
	var args []any
	if f.Method != "" {
		conds = append(conds, "upper(method) = ?")
		args = append(args, strings.ToUpper(f.Method))
	}
	if f.PathPrefix != "" {
		conds = append(conds, "startsWith(path, ?)")
		args = append(args, f.PathPrefix)
	}
	if f.Search != "" {
		// position() is ClickHouse's substring search; LIKE would need the
		// value escaping for % and _, which is the bug class that bit Purge.
		conds = append(conds, "(position(path, ?) > 0 OR position(req_body, ?) > 0 OR position(resp_body, ?) > 0)")
		args = append(args, f.Search, f.Search, f.Search)
	}
	if f.StatusMin > 0 {
		conds = append(conds, "status >= ?")
		args = append(args, int32(f.StatusMin))
	}
	if f.StatusMax > 0 {
		conds = append(conds, "status <= ?")
		args = append(args, int32(f.StatusMax))
	}
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		conds = append(conds, "ts <= ?")
		args = append(args, f.Until.UnixMilli())
	}
	if f.TraceID != "" {
		conds = append(conds, "trace_id = ?")
		args = append(args, f.TraceID)
	}
	for _, k := range sortedKeys(f.Labels) {
		conds = append(conds, "JSONExtractString(assumeNotNull(labels), ?) = ?")
		args = append(args, k, f.Labels[k])
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func (s *ClickHouseStore) Query(ctx context.Context, f Filter) ([]Record, int64, error) {
	where, args := chBuildWhere(f)

	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT count() FROM logs"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+chColumns+" FROM logs"+where+" ORDER BY id DESC LIMIT ? OFFSET ?",
		append(args, int64(limit), int64(f.Offset))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		rec, err := chScan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *rec)
	}
	return out, total, rows.Err()
}

func (s *ClickHouseStore) Get(ctx context.Context, id int64) (*Record, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+chColumns+" FROM logs WHERE id = ?", id)
	return chScan(row)
}

func chScan(row scannable) (*Record, error) {
	var r Record
	var ts int64
	var status int32
	var reqH, respH, labels, rules, meters string
	var reqT, respT, stream uint8
	err := row.Scan(&r.ID, &ts, &r.Service, &r.Method, &r.Path, &r.Query, &r.Route,
		&status, &r.DurationMS, &r.Remote, &r.Source, &reqH, &respH,
		&r.RequestBody, &r.ResponseBody, &reqT, &respT,
		&r.ReqBytes, &r.RespBytes, &labels, &rules, &meters, &stream,
		&r.TraceID, &r.SpanID, &r.ParentSpanID)
	if err != nil {
		return nil, err
	}
	r.Time = time.UnixMilli(ts)
	r.Status = int(status)
	r.ReqTruncated, r.RespTruncated, r.Stream = reqT != 0, respT != 0, stream != 0
	fromJSON(reqH, &r.RequestHeaders)
	fromJSON(respH, &r.ResponseHeaders)
	fromJSON(labels, &r.Labels)
	fromJSON(rules, &r.MatchedRules)
	fromJSON(meters, &r.Meters)
	emptyToNil(&r)
	return &r, nil
}

func (s *ClickHouseStore) Stats(ctx context.Context, since time.Time, bucket time.Duration) (*Stats, error) {
	sinceMs := since.UnixMilli()
	st := &Stats{StatusCounts: map[string]int64{}}

	// One pass for totals and all three percentiles. quantileExactIf excludes
	// streams: their duration is a connection lifetime, not a latency, and one
	// long stream would otherwise define the window's p95.
	err := s.db.QueryRowContext(ctx, `
		SELECT count(),
		       countIf(status >= 500),
		       quantileExactIf(0.50)(duration_ms, stream = 0),
		       quantileExactIf(0.95)(duration_ms, stream = 0),
		       quantileExactIf(0.99)(duration_ms, stream = 0)
		FROM logs WHERE ts >= ?`, sinceMs).
		Scan(&st.Total, &st.Errors, &st.P50LatencyMS, &st.P95LatencyMS, &st.P99LatencyMS)
	if err != nil {
		return nil, err
	}
	if st.Total > 0 {
		st.ErrorRate = float64(st.Errors) / float64(st.Total)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT intDiv(status, 100) * 100 AS class, count() FROM logs WHERE ts >= ? GROUP BY class`, sinceMs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var class int32
		var n int64
		if err := rows.Scan(&class, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.StatusCounts[fmt.Sprintf("%dxx", class/100)] = n
	}
	rows.Close()

	// What governance did to the window: see the note on Stats.BodiesKept.
	if err := s.db.QueryRowContext(ctx, `
		SELECT countIf(req_body <> '' OR resp_body <> ''), sum(req_bytes + resp_bytes)
		FROM logs WHERE ts >= ?`, sinceMs).Scan(&st.BodiesKept, &st.BytesSeen); err != nil {
		return nil, err
	}

	bms := bucket.Milliseconds()
	if bms <= 0 {
		bms = 60_000
	}
	rows, err = s.db.QueryContext(ctx, `
		SELECT intDiv(ts, ?) * ? AS b, count(), countIf(status >= 500),
		       countIf(status >= 400 AND status < 500), avg(duration_ms),
		       quantileExactIf(0.95)(duration_ms, stream = 0)
		FROM logs WHERE ts >= ? GROUP BY b ORDER BY b`, bms, bms, sinceMs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t int64
		var b TimeBucket
		if err := rows.Scan(&t, &b.Count, &b.Errors, &b.ClientErrors, &b.AvgLatency, &b.P95Latency); err != nil {
			rows.Close()
			return nil, err
		}
		b.Time = time.UnixMilli(t)
		st.Series = append(st.Series, b)
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `
		SELECT route, method, count() AS c, countIf(status >= 500), avg(duration_ms),
		       quantileExactIf(0.95)(duration_ms, stream = 0)
		FROM logs WHERE ts >= ? GROUP BY route, method ORDER BY c DESC LIMIT 10`, sinceMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r RouteStat
		if err := rows.Scan(&r.Route, &r.Method, &r.Count, &r.Errors, &r.AvgLatency, &r.P95Latency); err != nil {
			return nil, err
		}
		st.TopRoutes = append(st.TopRoutes, r)
	}
	return st, rows.Err()
}

func (s *ClickHouseStore) RouteStats(ctx context.Context, since time.Time) ([]RouteDetail, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT route, method, count() AS c, countIf(status >= 500), avg(duration_ms),
		       quantileExactIf(0.50)(duration_ms, stream = 0),
		       quantileExactIf(0.95)(duration_ms, stream = 0),
		       quantileExactIf(0.99)(duration_ms, stream = 0),
		       sum(req_bytes), sum(resp_bytes)
		FROM logs WHERE ts >= ? GROUP BY route, method ORDER BY c DESC LIMIT 200`,
		since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouteDetail
	for rows.Next() {
		var d RouteDetail
		if err := rows.Scan(&d.Route, &d.Method, &d.Count, &d.Errors, &d.AvgLatency,
			&d.P50Latency, &d.P95Latency, &d.P99Latency, &d.ReqBytes, &d.RespBytes); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *ClickHouseStore) ServiceStats(ctx context.Context, since time.Time) ([]ServiceStat, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT if(service = '', '(unnamed)', service) AS svc,
		       count(), countIf(status >= 500), avg(duration_ms),
		       quantileExactIf(0.95)(duration_ms, stream = 0),
		       uniqExact(route),
		       arrayStringConcat(arraySort(groupUniqArray(source)), ', '),
		       max(ts)
		FROM logs WHERE ts >= ? GROUP BY svc ORDER BY 2 DESC`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceStat
	for rows.Next() {
		var s2 ServiceStat
		var lastMs int64
		if err := rows.Scan(&s2.Service, &s2.Requests, &s2.Errors, &s2.AvgLatency,
			&s2.P95Latency, &s2.Routes, &s2.Sources, &lastMs); err != nil {
			return nil, err
		}
		if s2.Requests > 0 {
			s2.ErrorRate = float64(s2.Errors) / float64(s2.Requests)
		}
		s2.LastSeen = time.UnixMilli(lastMs)
		out = append(out, s2)
	}
	return out, rows.Err()
}

// RuleMatchCounts counts rule firings in a single pass. matched_rules is a
// JSON array of strings; arrayJoin over JSONExtract expands it so the counting
// happens in the database rather than in N round trips.
func (s *ClickHouseStore) RuleMatchCounts(ctx context.Context, since time.Time, ruleNames []string) ([]RuleMatch, error) {
	counts := make(map[string]int64, len(ruleNames))
	rows, err := s.db.QueryContext(ctx, `
		SELECT rule, count() FROM (
			SELECT arrayJoin(JSONExtract(assumeNotNull(matched_rules), 'Array(String)')) AS rule
			FROM logs WHERE ts >= ? AND matched_rules != '' AND matched_rules != 'null'
		) GROUP BY rule`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var n int64
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		counts[name] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Report every requested rule, including those that never fired — a zero
	// is the interesting answer for a rule you expected to be matching.
	out := make([]RuleMatch, 0, len(ruleNames))
	for _, name := range ruleNames {
		out = append(out, RuleMatch{Rule: name, Count: counts[name]})
	}
	return out, nil
}

func (s *ClickHouseStore) Count(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT count() FROM logs`).Scan(&n)
	return n, err
}

func (s *ClickHouseStore) RecentFunc(ctx context.Context, since time.Time, limit int, fn func(*Record) error) error {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+chColumns+" FROM logs WHERE ts >= ? ORDER BY id DESC LIMIT ?",
		since.UnixMilli(), int64(AnalysisLimit(limit)))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		rec, err := chScan(rows)
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *ClickHouseStore) Recent(ctx context.Context, since time.Time, limit int) ([]Record, error) {
	var out []Record
	err := s.RecentFunc(ctx, since, limit, func(r *Record) error {
		out = append(out, *r)
		return nil
	})
	return out, err
}

// UsageByLabel aggregates in Go for the same reason the other drivers do:
// labels and meters are stored as JSON documents whose keys are not known in
// advance, so grouping in SQL would need a per-key query.
func (s *ClickHouseStore) UsageByLabel(ctx context.Context, since time.Time, label string) ([]Usage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT status, duration_ms, req_bytes, resp_bytes, labels, meters
		FROM logs WHERE ts >= ?`, since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agg := map[string]*Usage{}
	for rows.Next() {
		var status int32
		var dur float64
		var reqB, respB int64
		var labelsJSON, metersJSON string
		if err := rows.Scan(&status, &dur, &reqB, &respB, &labelsJSON, &metersJSON); err != nil {
			return nil, err
		}
		var labels map[string]string
		fromJSON(labelsJSON, &labels)
		consumer := labels[label]
		if consumer == "" {
			consumer = "(unattributed)"
		}
		u := agg[consumer]
		if u == nil {
			u = &Usage{Consumer: consumer}
			agg[consumer] = u
		}
		u.Requests++
		if status >= 500 {
			u.Errors++
		}
		u.ReqBytes += reqB
		u.RespBytes += respB
		u.DurationMS += dur

		var meters map[string]float64
		fromJSON(metersJSON, &meters)
		for k, v := range meters {
			if u.Meters == nil {
				u.Meters = map[string]float64{}
			}
			u.Meters[k] += v
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Index after the map stops growing: taking pointers into a slice while
	// it is still being appended to was a real bug in the Postgres driver.
	out := make([]Usage, 0, len(agg))
	for _, u := range agg {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out, nil
}

func (s *ClickHouseStore) Prune(ctx context.Context, maxRows int64) (int64, error) {
	if maxRows <= 0 {
		return 0, nil
	}
	total, err := s.Count(ctx)
	if err != nil {
		return 0, err
	}
	if total <= maxRows {
		return 0, nil
	}
	// Find the id boundary of the newest maxRows records, then delete
	// everything at or below it. Done by id rather than ts because two records
	// can share a millisecond, and a ts cutoff would delete an unpredictable
	// number of them.
	var cutoff int64
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET ?`, maxRows-1).Scan(&cutoff)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE logs DELETE WHERE id < ?`+syncMutations, cutoff); err != nil {
		return 0, err
	}
	return total - maxRows, nil
}

func (s *ClickHouseStore) PruneBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, nil
	}
	ms := cutoff.UnixMilli()
	// Counted first: an ALTER ... DELETE mutation reports no row count, and
	// silently returning 0 would read as "there was nothing to prune".
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT count() FROM logs WHERE ts < ?`, ms).Scan(&n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE logs DELETE WHERE ts < ?`+syncMutations, ms); err != nil {
		return 0, err
	}
	return n, nil
}

// Purge implements erasure requests. The label match is on the exact
// `"label":"value"` pair extracted from the JSON document, not a substring or
// a LIKE pattern — deleting a neighbouring tenant's data is the one mistake an
// erasure tool must never make, and a LIKE with unescaped metacharacters is
// exactly how the SQLite driver once made it.
func (s *ClickHouseStore) Purge(ctx context.Context, label, value string, before time.Time) (int64, error) {
	if label == "" || value == "" {
		return 0, fmt.Errorf("purge requires both a label and a value")
	}
	where := `JSONExtractString(assumeNotNull(labels), ?) = ?`
	args := []any{label, value}
	if !before.IsZero() {
		where += ` AND ts < ?`
		args = append(args, before.UnixMilli())
	}
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count() FROM logs WHERE `+where, args...).Scan(&n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	// Erasure has to take the application log lines with it. A tenant's
	// requests deleted while the lines those requests wrote survive is not
	// erasure, and a log is the likelier place for the personal data to be.
	//
	// ClickHouse has no transactions across these two mutations, so the log
	// lines go FIRST: if the second delete fails, the caller sees an error and
	// retries, and a retry is safe. The other order could report failure while
	// having already removed the records, leaving orphaned lines nothing will
	// ever match again.
	var traceIDs []string
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT trace_id FROM logs WHERE `+where+` AND trace_id != ''`, args...)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		traceIDs = append(traceIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	if len(traceIDs) > 0 {
		ids := make([]any, len(traceIDs))
		placeholders := make([]string, len(traceIDs))
		for i, id := range traceIDs {
			ids[i] = id
			placeholders[i] = "?"
		}
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE app_logs DELETE WHERE trace_id IN (`+
				strings.Join(placeholders, ",")+`)`+syncMutations, ids...); err != nil {
			return 0, fmt.Errorf("purge app logs: %w", err)
		}
		// And the inner spans: a statement's attributes can hold the
		// customer's email as surely as a log line can.
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE spans DELETE WHERE trace_id IN (`+
				strings.Join(placeholders, ",")+`)`+syncMutations, ids...); err != nil {
			return 0, fmt.Errorf("purge spans: %w", err)
		}
	}

	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE logs DELETE WHERE `+where+syncMutations, args...); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *ClickHouseStore) Close() error { return s.db.Close() }
