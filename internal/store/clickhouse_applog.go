package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// ClickHouseStore implements ext.AppLogStore.
var _ ext.AppLogStore = (*ClickHouseStore)(nil)

// SaveAppLogs writes a batch.
//
// ClickHouse has no autoincrement, so ids come from the same timestamp+sequence
// generator the record path uses — monotonic enough to order lines written in
// the same millisecond, which is exactly when a request logs several times.
func (s *ClickHouseStore) SaveAppLogs(ctx context.Context, lines []ext.AppLog) error {
	if len(lines) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO app_logs (id, ts, service, trace_id, span_id, level, message, fields, source, truncated)
		VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for i := range lines {
		l := &lines[i]
		if l.Time.IsZero() {
			l.Time = time.Now()
		}
		fields := ""
		if len(l.Fields) > 0 {
			raw, err := json.Marshal(l.Fields)
			if err != nil {
				tx.Rollback()
				return err
			}
			fields = string(raw)
		}
		if _, err := stmt.ExecContext(ctx, s.nextID(l.Time), l.Time.UnixMilli(), l.Service,
			l.TraceID, l.SpanID, l.Level, l.Message, fields, l.Source,
			uint8(boolInt(l.Truncated))); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// QueryAppLogs returns matching lines oldest-first.
func (s *ClickHouseStore) QueryAppLogs(ctx context.Context, f ext.AppLogFilter) ([]ext.AppLog, int64, error) {
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
		// position() rather than LIKE: nothing to escape, so a search for
		// "100%" cannot become a wildcard that matches every line.
		where = append(where, "position(message, ?) > 0")
		args = append(args, f.Search)
	}
	// By severity rank, not lexically: "error" sorts before "warn" as text and
	// after it as severity, so a lexical comparison returns the wrong set.
	if f.LevelMin != "" {
		min := ext.LevelRank(f.LevelMin)
		var keep []string
		for _, name := range []string{"trace", "debug", "info", "warn", "error", "fatal"} {
			if ext.LevelRank(name) >= min {
				keep = append(keep, "?")
				args = append(args, name)
			}
		}
		// An unrecognised level outranks every known one and is always kept.
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
	if err := s.db.QueryRowContext(ctx, `SELECT count() FROM app_logs`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, service, trace_id, span_id, level, message, fields, source, truncated
		 FROM app_logs`+clause+` ORDER BY ts ASC, id ASC LIMIT ? OFFSET ?`,
		append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.AppLog
	for rows.Next() {
		var (
			l         ext.AppLog
			ts        int64
			fields    string
			truncated uint8
		)
		if err := rows.Scan(&l.ID, &ts, &l.Service, &l.TraceID, &l.SpanID,
			&l.Level, &l.Message, &fields, &l.Source, &truncated); err != nil {
			return nil, 0, err
		}
		l.Time = time.UnixMilli(ts).UTC()
		l.Truncated = truncated != 0
		if fields != "" {
			if err := json.Unmarshal([]byte(fields), &l.Fields); err != nil {
				l.Fields = map[string]string{"_unparsable_fields": fields}
			}
		}
		out = append(out, l)
	}
	return out, total, rows.Err()
}

func (s *ClickHouseStore) CountAppLogs(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT count() FROM app_logs`).Scan(&n)
	return n, err
}

// AppLogStats aggregates in the database rather than by counting rows in the
// caller — a summary of the first page is wrong at exactly the volumes where a
// summary starts to matter.
func (s *ClickHouseStore) AppLogStats(ctx context.Context, since time.Time) (*ext.AppLogSummary, error) {
	out := &ext.AppLogSummary{ByLevel: map[string]int64{}, ByService: map[string]int64{}}
	cutoff := since.UnixMilli()

	if err := s.db.QueryRowContext(ctx,
		`SELECT count(), uniqExact(span_id) FROM app_logs WHERE ts >= ?`, cutoff,
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
			`SELECT `+g.col+`, count() FROM app_logs WHERE ts >= ? GROUP BY `+g.col, cutoff)
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

// PruneAppLogsBefore enforces the app-log retention horizon.
//
// mutations_sync=2 for the same reason the record path uses it: an unsynchronised
// ALTER ... DELETE returns before the data is gone, so retention would report
// success while the rows were still readable.
func (s *ClickHouseStore) PruneAppLogsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	ms := cutoff.UnixMilli()
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count() FROM app_logs WHERE ts < ?`, ms).Scan(&n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE app_logs DELETE WHERE ts < ?`+syncMutations, ms); err != nil {
		return 0, err
	}
	return n, nil
}
