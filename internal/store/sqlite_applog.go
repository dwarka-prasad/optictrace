package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// SQLiteStore implements ext.AppLogStore. The assertion is compile-time on
// purpose: this file existing but not satisfying the interface would show up
// as a runtime "app logs unsupported" that looks like a config problem.
var _ ext.AppLogStore = (*SQLiteStore)(nil)

// SaveAppLogs writes a batch in one transaction. Batching is the point —
// application logs arrive at many lines per request, and a transaction per
// line makes the store the slowest part of the system.
func (s *SQLiteStore) SaveAppLogs(ctx context.Context, lines []ext.AppLog) error {
	if len(lines) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO app_logs (ts, service, trace_id, span_id, route, level, message, fields, source, truncated)
		VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range lines {
		l := &lines[i]
		fields := ""
		if len(l.Fields) > 0 {
			b, err := json.Marshal(l.Fields)
			if err != nil {
				return fmt.Errorf("marshal fields: %w", err)
			}
			fields = string(b)
		}
		if l.Time.IsZero() {
			l.Time = time.Now()
		}
		if _, err := stmt.ExecContext(ctx, l.Time.UnixMilli(), l.Service, l.TraceID,
			l.SpanID, l.Route, l.Level, l.Message, fields, l.Source, boolInt(l.Truncated)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryAppLogs returns matching lines oldest-first: reading what a request did
// means reading it in the order it happened.
func (s *SQLiteStore) QueryAppLogs(ctx context.Context, f ext.AppLogFilter) ([]ext.AppLog, int64, error) {
	var where []string
	var args []any

	if f.SpanID != "" {
		where = append(where, "span_id = ?")
		args = append(args, f.SpanID)
	}
	if f.TraceID != "" {
		where = append(where, "trace_id = ?")
		args = append(args, f.TraceID)
	}
	if f.Service != "" {
		where = append(where, "service = ?")
		args = append(args, f.Service)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= ?")
		args = append(args, f.Until.UnixMilli())
	}
	if f.Search != "" {
		// Escaped: a search for "100%" must not become a wildcard that
		// matches every line.
		where = append(where, `message LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(f.Search)+"%")
	}
	// Level is compared by rank, not lexically — "error" > "warn" is true by
	// severity and false alphabetically. SQLite has no ordering for our
	// severity names, so expand the minimum into the set at or above it.
	if f.LevelMin != "" {
		min := ext.LevelRank(f.LevelMin)
		var keep []string
		for _, name := range []string{"trace", "debug", "info", "warn", "error", "fatal"} {
			if ext.LevelRank(name) >= min {
				keep = append(keep, name)
			}
		}
		// An unrecognised level ranks above every known one and is always
		// kept: a filter must never be the reason a custom "panic" vanishes.
		clause := "level NOT IN ('trace','debug','info','warn','error','fatal')"
		if len(keep) > 0 {
			clause = "level IN (" + strings.TrimSuffix(strings.Repeat("?,", len(keep)), ",") + ") OR " + clause
			for _, k := range keep {
				args = append(args, k)
			}
		}
		where = append(where, "("+clause+")")
	}

	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}

	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_logs`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT id, ts, service, trace_id, span_id, route, level, message, fields, source, truncated
		FROM app_logs` + clause + ` ORDER BY ts ASC, id ASC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.AppLog
	for rows.Next() {
		l, err := scanAppLog(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *l)
	}
	return out, total, rows.Err()
}

func (s *SQLiteStore) CountAppLogs(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_logs`).Scan(&n)
	return n, err
}

// PruneAppLogsBefore enforces the app-log retention horizon, which is separate
// from the record horizon because the volumes differ by orders of magnitude.
func (s *SQLiteStore) PruneAppLogsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM app_logs WHERE ts < ?`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanAppLog(sc scannable) (*ext.AppLog, error) {
	var (
		l         ext.AppLog
		ts        int64
		fields    string
		truncated int
	)
	if err := sc.Scan(&l.ID, &ts, &l.Service, &l.TraceID, &l.SpanID, &l.Route,
		&l.Level, &l.Message, &fields, &l.Source, &truncated); err != nil {
		return nil, err
	}
	l.Time = time.UnixMilli(ts).UTC()
	l.Truncated = truncated != 0
	if fields != "" {
		if err := json.Unmarshal([]byte(fields), &l.Fields); err != nil {
			// A row that will not unmarshal is a bug worth seeing, but it must
			// not make the whole query fail: the message is still readable and
			// is usually what someone came for.
			l.Fields = map[string]string{"_unparsable_fields": fields}
		}
	}
	return &l, nil
}

// AppLogStats aggregates stored lines. Three cheap grouped counts rather than
// one walk: the point of asking the database is not having to carry the rows.
func (s *SQLiteStore) AppLogStats(ctx context.Context, since time.Time) (*ext.AppLogSummary, error) {
	out := &ext.AppLogSummary{ByLevel: map[string]int64{}, ByService: map[string]int64{}}
	cutoff := since.UnixMilli()

	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COUNT(DISTINCT span_id) FROM app_logs WHERE ts >= ?`, cutoff,
	).Scan(&out.Total, &out.SpansWithLogs); err != nil {
		return nil, err
	}

	for _, q := range []struct {
		col  string
		into map[string]int64
	}{
		{"level", out.ByLevel},
		{"service", out.ByService},
	} {
		rows, err := s.db.QueryContext(ctx,
			`SELECT `+q.col+`, COUNT(*) FROM app_logs WHERE ts >= ? GROUP BY `+q.col, cutoff)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var key string
			var n int64
			if err := rows.Scan(&key, &n); err != nil {
				rows.Close()
				return nil, err
			}
			q.into[key] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
