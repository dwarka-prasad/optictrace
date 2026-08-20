package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

var _ ext.SpanStore = (*PostgresStore)(nil)

func (s *PostgresStore) SaveSpans(ctx context.Context, list []ext.Span) error {
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
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range list {
		sp := &list[i]
		if _, err := stmt.ExecContext(ctx,
			sp.Start.UnixMilli(), sp.Service, sp.TraceID, sp.SpanID, sp.ParentSpanID,
			sp.Name, sp.Kind, sp.DurationMS, sp.Error, jsonbOr(sp.Attrs, "{}"),
			sp.Route, sp.Source, sp.Truncated); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// pgSpanWhere mirrors the SQLite filter with numbered placeholders. Postgres
// compares LIKE exactly and needs no ESCAPE clause.
func pgSpanWhere(f ext.SpanFilter, bind func(any) string) (string, []any) {
	var conds []string
	if f.TraceID != "" {
		conds = append(conds, "trace_id = "+bind(f.TraceID))
	}
	if f.SpanID != "" {
		conds = append(conds, "span_id = "+bind(f.SpanID))
	}
	if f.ParentSpanID != "" {
		conds = append(conds, "parent_span = "+bind(f.ParentSpanID))
	}
	if f.Service != "" {
		conds = append(conds, "service = "+bind(f.Service))
	}
	if f.Kind != "" {
		conds = append(conds, "kind = "+bind(strings.ToLower(f.Kind)))
	}
	if f.MinDurationMS > 0 {
		conds = append(conds, "duration_ms >= "+bind(f.MinDurationMS))
	}
	if f.ErrorsOnly {
		conds = append(conds, "error <> ''")
	}
	if !f.Since.IsZero() {
		conds = append(conds, "ts >= "+bind(f.Since.UnixMilli()))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "ts <= "+bind(f.Until.UnixMilli()))
	}
	if f.Search != "" {
		conds = append(conds, "name LIKE "+bind("%"+f.Search+"%"))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), nil
}

func (s *PostgresStore) QuerySpans(ctx context.Context, f ext.SpanFilter) ([]ext.Span, int64, error) {
	var args []any
	bind := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	where, _ := pgSpanWhere(f, bind)

	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM spans"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT id, ts, service, trace_id, span_id, parent_span, name, kind,
	             duration_ms, error, attrs, route, source, truncated
	      FROM spans` + where + ` ORDER BY ts ASC, id ASC LIMIT ` + bind(limit) + ` OFFSET ` + bind(f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.Span
	for rows.Next() {
		var sp ext.Span
		var ts int64
		var attrs []byte
		if err := rows.Scan(&sp.ID, &ts, &sp.Service, &sp.TraceID, &sp.SpanID,
			&sp.ParentSpanID, &sp.Name, &sp.Kind, &sp.DurationMS, &sp.Error,
			&attrs, &sp.Route, &sp.Source, &sp.Truncated); err != nil {
			return nil, 0, err
		}
		sp.Start = time.UnixMilli(ts)
		fromJSON(string(attrs), &sp.Attrs)
		out = append(out, sp)
	}
	return out, total, rows.Err()
}

// SpanBreakdown uses percentile_cont, so the p95 comes from the same pass
// rather than one ordered subquery per operation name.
func (s *PostgresStore) SpanBreakdown(ctx context.Context, since time.Time, route string, limit int) ([]ext.SpanBreakdown, error) {
	if limit <= 0 {
		limit = 20
	}
	args := []any{since.UnixMilli()}
	routeCond := ""
	if route != "" {
		// The route lives on the enclosing RECORD, not on the span: a span
		// carries a producer-supplied hint, fine for policy because it can
		// only tighten, but not for a figure someone reads as fact.
		routeCond = ` AND s.parent_span IN (SELECT span_id FROM logs WHERE route = $2 AND ts >= $1)`
		args = append(args, route)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.name, MIN(s.kind), COUNT(*), COUNT(DISTINCT s.parent_span),
		       COALESCE(SUM(CASE WHEN s.error <> '' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(s.duration_ms), 0), COALESCE(AVG(s.duration_ms), 0),
		       COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY s.duration_ms), 0),
		       COALESCE(MAX(s.duration_ms), 0)
		FROM spans s WHERE s.ts >= $1`+routeCond+`
		GROUP BY s.name ORDER BY SUM(s.duration_ms) DESC LIMIT `+fmt.Sprint(limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ext.SpanBreakdown
	for rows.Next() {
		var b ext.SpanBreakdown
		if err := rows.Scan(&b.Name, &b.Kind, &b.Count, &b.Requests, &b.Errors,
			&b.TotalMS, &b.AvgMS, &b.P95MS, &b.MaxMS); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SpanStats(ctx context.Context, since time.Time) (*ext.SpanSummary, error) {
	sum := &ext.SpanSummary{ByKind: map[string]int64{}, ByService: map[string]int64{}}
	sinceMs := since.UnixMilli()

	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN error <> '' THEN 1 ELSE 0 END), 0),
		        COUNT(DISTINCT parent_span)
		 FROM spans WHERE ts >= $1`, sinceMs).
		Scan(&sum.Total, &sum.Errors, &sum.RequestsWithSpans); err != nil {
		return nil, err
	}
	for _, g := range []struct {
		col string
		dst map[string]int64
	}{{"kind", sum.ByKind}, {"service", sum.ByService}} {
		rows, err := s.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT %s, COUNT(*) FROM spans WHERE ts >= $1 GROUP BY %s`, g.col, g.col), sinceMs)
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

func (s *PostgresStore) CountSpans(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM spans`).Scan(&n)
	return n, err
}

func (s *PostgresStore) PruneSpansBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM spans WHERE ts < $1`, cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
