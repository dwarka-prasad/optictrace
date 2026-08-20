package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

var _ ext.SpanStore = (*SQLiteStore)(nil)

// SaveSpans persists a batch in one transaction. Called from the async writer,
// never from a request path.
func (s *SQLiteStore) SaveSpans(ctx context.Context, list []ext.Span) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO spans
		(ts, service, trace_id, span_id, parent_span, name, kind, duration_ms,
		 error, attrs, route, source, truncated)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range list {
		sp := &list[i]
		if _, err := stmt.ExecContext(ctx,
			sp.Start.UnixMilli(), sp.Service, sp.TraceID, sp.SpanID, sp.ParentSpanID,
			sp.Name, sp.Kind, sp.DurationMS, sp.Error, mustJSON(sp.Attrs),
			sp.Route, sp.Source, sp.Truncated); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// spanWhere builds the filter shared by QuerySpans and its count.
func spanWhere(f ext.SpanFilter) (string, []any) {
	var conds []string
	var args []any
	add := func(c string, v ...any) {
		conds = append(conds, c)
		args = append(args, v...)
	}
	if f.TraceID != "" {
		add("trace_id = ?", f.TraceID)
	}
	if f.SpanID != "" {
		add("span_id = ?", f.SpanID)
	}
	if f.ParentSpanID != "" {
		add("parent_span = ?", f.ParentSpanID)
	}
	if f.Service != "" {
		add("service = ?", f.Service)
	}
	if f.Kind != "" {
		add("kind = ?", strings.ToLower(f.Kind))
	}
	if f.MinDurationMS > 0 {
		add("duration_ms >= ?", f.MinDurationMS)
	}
	if f.ErrorsOnly {
		add("error <> ''")
	}
	if !f.Since.IsZero() {
		add("ts >= ?", f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		add("ts <= ?", f.Until.UnixMilli())
	}
	if f.Search != "" {
		add("name LIKE ? ESCAPE '\\'", "%"+likeEscape(f.Search)+"%")
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// QuerySpans returns matching spans OLDEST-FIRST: reading a request's work
// means reading it in the order it happened.
func (s *SQLiteStore) QuerySpans(ctx context.Context, f ext.SpanFilter) ([]ext.Span, int64, error) {
	where, args := spanWhere(f)

	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM spans"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, service, trace_id, span_id, parent_span, name, kind,
		        duration_ms, error, attrs, route, source, truncated
		 FROM spans`+where+` ORDER BY ts ASC, id ASC LIMIT ? OFFSET ?`,
		append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.Span
	for rows.Next() {
		var sp ext.Span
		var ts int64
		var attrs string
		if err := rows.Scan(&sp.ID, &ts, &sp.Service, &sp.TraceID, &sp.SpanID,
			&sp.ParentSpanID, &sp.Name, &sp.Kind, &sp.DurationMS, &sp.Error,
			&attrs, &sp.Route, &sp.Source, &sp.Truncated); err != nil {
			return nil, 0, err
		}
		sp.Start = time.UnixMilli(ts)
		fromJSON(attrs, &sp.Attrs)
		out = append(out, sp)
	}
	return out, total, rows.Err()
}

// SpanBreakdown answers "where did the time go" for a window.
//
// Requests is counted alongside Count on purpose: Count/Requests is the
// per-request multiplier, and a multiplier of 40 on a query named once in the
// source is the shape an N+1 makes. A total alone hides it — 4,000 calls looks
// like busy traffic until you know it was 100 requests.
func (s *SQLiteStore) SpanBreakdown(ctx context.Context, since time.Time, route string, limit int) ([]ext.SpanBreakdown, error) {
	if limit <= 0 {
		limit = 20
	}
	args := []any{since.UnixMilli()}
	routeCond := ""
	if route != "" {
		// The route lives on the enclosing RECORD, not on the span, so this
		// joins rather than filtering a column the span does not have. A span
		// carries a producer-supplied route hint, which is fine for policy —
		// it can only tighten — but not for a figure someone reads as fact.
		routeCond = ` AND s.parent_span IN (SELECT span_id FROM logs WHERE route = ? AND ts >= ?)`
		args = append(args, route, since.UnixMilli())
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.name, MIN(s.kind), COUNT(*), COUNT(DISTINCT s.parent_span),
		       COALESCE(SUM(s.error <> ''), 0),
		       COALESCE(SUM(s.duration_ms), 0), COALESCE(AVG(s.duration_ms), 0),
		       COALESCE(MAX(s.duration_ms), 0)
		FROM spans s WHERE s.ts >= ?`+routeCond+`
		GROUP BY s.name ORDER BY SUM(s.duration_ms) DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ext.SpanBreakdown
	for rows.Next() {
		var b ext.SpanBreakdown
		if err := rows.Scan(&b.Name, &b.Kind, &b.Count, &b.Requests, &b.Errors,
			&b.TotalMS, &b.AvgMS, &b.MaxMS); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The p95 per name needs its own ordered pass. Done per row rather than in
	// the group-by above because SQLite has no percentile aggregate, and the
	// row count here is bounded by limit.
	for i := range out {
		b := &out[i]
		offset := int64(0.95 * float64(b.Count))
		if offset >= b.Count {
			offset = b.Count - 1
		}
		q := `SELECT duration_ms FROM spans s WHERE s.ts >= ? AND s.name = ?`
		qa := []any{since.UnixMilli(), b.Name}
		if route != "" {
			q += ` AND s.parent_span IN (SELECT span_id FROM logs WHERE route = ? AND ts >= ?)`
			qa = append(qa, route, since.UnixMilli())
		}
		q += ` ORDER BY duration_ms LIMIT 1 OFFSET ?`
		qa = append(qa, offset)
		if err := s.db.QueryRowContext(ctx, q, qa...).Scan(&b.P95MS); err != nil && err != sql.ErrNoRows {
			return nil, err
		}
	}
	return out, nil
}

func (s *SQLiteStore) SpanStats(ctx context.Context, since time.Time) (*ext.SpanSummary, error) {
	sum := &ext.SpanSummary{ByKind: map[string]int64{}, ByService: map[string]int64{}}
	sinceMs := since.UnixMilli()

	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(error <> ''), 0), COUNT(DISTINCT parent_span)
		 FROM spans WHERE ts >= ?`, sinceMs).
		Scan(&sum.Total, &sum.Errors, &sum.RequestsWithSpans); err != nil {
		return nil, err
	}
	for _, g := range []struct {
		col string
		dst map[string]int64
	}{{"kind", sum.ByKind}, {"service", sum.ByService}} {
		rows, err := s.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT %s, COUNT(*) FROM spans WHERE ts >= ? GROUP BY %s`, g.col, g.col), sinceMs)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k string
			var n int64
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return nil, err
			}
			if k == "" {
				k = "unspecified"
			}
			g.dst[k] = n
		}
		rows.Close()
	}
	return sum, nil
}

func (s *SQLiteStore) CountSpans(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM spans`).Scan(&n)
	return n, err
}

func (s *SQLiteStore) PruneSpansBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM spans WHERE ts < ?`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
