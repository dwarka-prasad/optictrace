package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// PostgresStore implements ext.AppLogStore. Compile-time, because this file
// existing but not satisfying the interface would surface at runtime as
// "app logs unsupported", which looks like a config mistake.
var _ ext.AppLogStore = (*PostgresStore)(nil)

// SaveAppLogs writes a batch in one round trip.
//
// Batching is the point: application logs arrive at many lines per request,
// and a statement per line makes the store the slowest part of the system.
func (s *PostgresStore) SaveAppLogs(ctx context.Context, lines []ext.AppLog) error {
	if len(lines) == 0 {
		return nil
	}

	// One multi-row INSERT rather than a prepared statement in a loop: the
	// round trips dominate, not the parsing.
	var b strings.Builder
	b.WriteString(`INSERT INTO app_logs (ts, service, trace_id, span_id, route, level, message, fields, source, truncated) VALUES `)
	args := make([]any, 0, len(lines)*10)
	for i := range lines {
		l := &lines[i]
		if l.Time.IsZero() {
			l.Time = time.Now()
		}
		fields := "{}"
		if len(l.Fields) > 0 {
			raw, err := json.Marshal(l.Fields)
			if err != nil {
				return fmt.Errorf("marshal fields: %w", err)
			}
			fields = string(raw)
		}
		if i > 0 {
			b.WriteByte(',')
		}
		n := i * 10
		b.WriteString("($" + strconv.Itoa(n+1) + ",$" + strconv.Itoa(n+2) + ",$" + strconv.Itoa(n+3) +
			",$" + strconv.Itoa(n+4) + ",$" + strconv.Itoa(n+5) + ",$" + strconv.Itoa(n+6) +
			",$" + strconv.Itoa(n+7) + ",$" + strconv.Itoa(n+8) + "::jsonb,$" + strconv.Itoa(n+9) +
			",$" + strconv.Itoa(n+10) + ")")
		args = append(args, l.Time.UnixMilli(), l.Service, l.TraceID, l.SpanID, l.Route,
			l.Level, l.Message, fields, l.Source, l.Truncated)
	}
	_, err := s.db.ExecContext(ctx, b.String(), args...)
	return err
}

// QueryAppLogs returns matching lines oldest-first: reading what a request did
// means reading it in the order it happened.
func (s *PostgresStore) QueryAppLogs(ctx context.Context, f ext.AppLogFilter) ([]ext.AppLog, int64, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}

	if f.SpanID != "" {
		where = append(where, "span_id = "+arg(f.SpanID))
	}
	if f.TraceID != "" {
		where = append(where, "trace_id = "+arg(f.TraceID))
	}
	if f.Service != "" {
		where = append(where, "service = "+arg(f.Service))
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= "+arg(f.Since.UnixMilli()))
	}
	if !f.Until.IsZero() {
		where = append(where, "ts <= "+arg(f.Until.UnixMilli()))
	}
	if f.Search != "" {
		// position() rather than LIKE: no metacharacters to escape, so a
		// search for "100%" cannot become a wildcard matching every line.
		where = append(where, "position("+arg(f.Search)+" in message) > 0")
	}
	// Level is compared by RANK, not lexically — "error" sorts before "warn"
	// as text and after it as severity. Expanding the minimum into its set
	// keeps the two drivers agreeing on what "at least warn" means.
	if f.LevelMin != "" {
		min := ext.LevelRank(f.LevelMin)
		var keep []string
		for _, name := range []string{"trace", "debug", "info", "warn", "error", "fatal"} {
			if ext.LevelRank(name) >= min {
				keep = append(keep, arg(name))
			}
		}
		// An unrecognised level outranks every known one and is always kept: a
		// filter must never be the reason a custom "panic" vanishes.
		clause := "level NOT IN ('trace','debug','info','warn','error','fatal')"
		if len(keep) > 0 {
			clause = "level IN (" + strings.Join(keep, ",") + ") OR " + clause
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
		FROM app_logs` + clause + ` ORDER BY ts ASC, id ASC LIMIT ` + arg(limit) + ` OFFSET ` + arg(f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.AppLog
	for rows.Next() {
		var (
			l      ext.AppLog
			ts     int64
			fields []byte
		)
		if err := rows.Scan(&l.ID, &ts, &l.Service, &l.TraceID, &l.SpanID, &l.Route,
			&l.Level, &l.Message, &fields, &l.Source, &l.Truncated); err != nil {
			return nil, 0, err
		}
		l.Time = time.UnixMilli(ts).UTC()
		if len(fields) > 0 {
			if err := json.Unmarshal(fields, &l.Fields); err != nil {
				// A row that will not unmarshal is worth seeing, but it must
				// not fail the whole query: the message is still readable and
				// is usually what someone came for.
				l.Fields = map[string]string{"_unparsable_fields": string(fields)}
			}
			if len(l.Fields) == 0 {
				l.Fields = nil
			}
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

func (s *PostgresStore) CountAppLogs(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_logs`).Scan(&n)
	return n, err
}

// AppLogStats aggregates in the database rather than by counting rows in the
// caller: a dashboard that summarises the first page and calls it a total is
// quietly lying at exactly the volumes where the summary starts to matter.
func (s *PostgresStore) AppLogStats(ctx context.Context, since time.Time) (*ext.AppLogSummary, error) {
	out := &ext.AppLogSummary{ByLevel: map[string]int64{}, ByService: map[string]int64{}}
	cutoff := since.UnixMilli()

	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COUNT(DISTINCT span_id) FROM app_logs WHERE ts >= $1`, cutoff,
	).Scan(&out.Total, &out.SpansWithLogs); err != nil {
		return nil, err
	}

	for _, g := range []struct {
		col  string
		into map[string]int64
	}{
		{"level", out.ByLevel},
		{"service", out.ByService},
	} {
		rows, err := s.db.QueryContext(ctx,
			`SELECT `+g.col+`, COUNT(*) FROM app_logs WHERE ts >= $1 GROUP BY `+g.col, cutoff)
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
			g.into[key] = n
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// PruneAppLogsBefore enforces the app-log retention horizon, which is separate
// from the record horizon because the volumes differ by orders of magnitude.
func (s *PostgresStore) PruneAppLogsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM app_logs WHERE ts < $1`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
