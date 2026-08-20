package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

var _ ext.SpanStore = (*ClickHouseStore)(nil)

func (s *ClickHouseStore) SaveSpans(ctx context.Context, list []ext.Span) error {
	if len(list) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO spans
		(id, ts, service, trace_id, span_id, parent_span, name, kind, duration_ms,
		 error, attrs, route, source, truncated)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for i := range list {
		sp := &list[i]
		if _, err := stmt.ExecContext(ctx,
			s.nextID(sp.Start), sp.Start.UnixMilli(), sp.Service, sp.TraceID, sp.SpanID,
			sp.ParentSpanID, sp.Name, sp.Kind, sp.DurationMS, sp.Error,
			mustJSON(sp.Attrs), sp.Route, sp.Source, uint8(boolInt(sp.Truncated))); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func chSpanWhere(f ext.SpanFilter) (string, []any) {
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
		add("error != ''")
	}
	if !f.Since.IsZero() {
		add("ts >= ?", f.Since.UnixMilli())
	}
	if !f.Until.IsZero() {
		add("ts <= ?", f.Until.UnixMilli())
	}
	if f.Search != "" {
		// position() rather than LIKE: no metacharacters to escape, so a name
		// containing % cannot widen the match.
		add("position(name, ?) > 0", f.Search)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func (s *ClickHouseStore) QuerySpans(ctx context.Context, f ext.SpanFilter) ([]ext.Span, int64, error) {
	where, args := chSpanWhere(f)

	var total uint64
	if err := s.db.QueryRowContext(ctx, "SELECT count() FROM spans"+where, args...).Scan(&total); err != nil {
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
		var trunc uint8
		if err := rows.Scan(&sp.ID, &ts, &sp.Service, &sp.TraceID, &sp.SpanID,
			&sp.ParentSpanID, &sp.Name, &sp.Kind, &sp.DurationMS, &sp.Error,
			&attrs, &sp.Route, &sp.Source, &trunc); err != nil {
			return nil, 0, err
		}
		sp.Start = time.UnixMilli(ts)
		sp.Truncated = trunc == 1
		fromJSON(attrs, &sp.Attrs)
		out = append(out, sp)
	}
	return out, int64(total), rows.Err()
}

func (s *ClickHouseStore) SpanBreakdown(ctx context.Context, since time.Time, route string, limit int) ([]ext.SpanBreakdown, error) {
	if limit <= 0 {
		limit = 20
	}
	args := []any{since.UnixMilli()}
	routeCond := ""
	if route != "" {
		routeCond = ` AND s.parent_span IN (SELECT span_id FROM logs WHERE route = ? AND ts >= ?)`
		args = append(args, route, since.UnixMilli())
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.name, min(s.kind), count(), uniqExact(s.parent_span),
		       countIf(s.error != ''), sum(s.duration_ms), avg(s.duration_ms),
		       quantileExact(0.95)(s.duration_ms), max(s.duration_ms)
		FROM spans s WHERE s.ts >= ?`+routeCond+`
		GROUP BY s.name ORDER BY sum(s.duration_ms) DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ext.SpanBreakdown
	for rows.Next() {
		var b ext.SpanBreakdown
		var count, requests, errs uint64
		if err := rows.Scan(&b.Name, &b.Kind, &count, &requests, &errs,
			&b.TotalMS, &b.AvgMS, &b.P95MS, &b.MaxMS); err != nil {
			return nil, err
		}
		b.Count, b.Requests, b.Errors = int64(count), int64(requests), int64(errs)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *ClickHouseStore) SpanStats(ctx context.Context, since time.Time) (*ext.SpanSummary, error) {
	sum := &ext.SpanSummary{ByKind: map[string]int64{}, ByService: map[string]int64{}}
	sinceMs := since.UnixMilli()

	var total, errs, reqs uint64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(), countIf(error != ''), uniqExact(parent_span)
		 FROM spans WHERE ts >= ?`, sinceMs).Scan(&total, &errs, &reqs); err != nil {
		return nil, err
	}
	sum.Total, sum.Errors, sum.RequestsWithSpans = int64(total), int64(errs), int64(reqs)

	for _, g := range []struct {
		col string
		dst map[string]int64
	}{{"kind", sum.ByKind}, {"service", sum.ByService}} {
		rows, err := s.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT %s, count() FROM spans WHERE ts >= ? GROUP BY %s`, g.col, g.col), sinceMs)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k string
			var n uint64
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return nil, err
			}
			if k == "" {
				k = "unspecified"
			}
			g.dst[k] = int64(n)
		}
		rows.Close()
	}
	return sum, nil
}

func (s *ClickHouseStore) CountSpans(ctx context.Context) (int64, error) {
	var n uint64
	err := s.db.QueryRowContext(ctx, `SELECT count() FROM spans`).Scan(&n)
	return int64(n), err
}

func (s *ClickHouseStore) PruneSpansBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	// ALTER DELETE is a mutation; the conformance suite requires it to behave
	// synchronously, which syncMutations arranges.
	var before uint64
	if err := s.db.QueryRowContext(ctx,
		`SELECT count() FROM spans WHERE ts < ?`, cutoff.UnixMilli()).Scan(&before); err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE spans DELETE WHERE ts < ?`+syncMutations, cutoff.UnixMilli()); err != nil {
		return 0, err
	}
	return int64(before), nil
}
