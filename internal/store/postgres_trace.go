package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

var _ ext.TraceStore = (*PostgresStore)(nil)

// Traces rolls the recorded hops up into one row per trace. See the SQLite
// implementation for the shape; the difference here is DISTINCT ON, which
// picks the root hop without a correlated subquery per trace.
func (s *PostgresStore) Traces(ctx context.Context, f ext.TraceFilter) ([]ext.TraceSummary, int64, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	var args []any
	bind := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	where := []string{"trace_id <> ''"}
	if !f.Since.IsZero() {
		where = append(where, "ts >= "+bind(f.Since.UnixMilli()))
	}
	if f.Service != "" {
		where = append(where, "service = "+bind(f.Service))
	}
	if f.Search != "" {
		like := "%" + f.Search + "%"
		where = append(where, fmt.Sprintf("(path LIKE %s OR route LIKE %s)", bind(like), bind(like)))
	}
	cond := strings.Join(where, " AND ")

	// parent_span = '' sorts before any real id, so one ORDER BY expresses
	// both "the parentless hop" and "the earliest hop when nothing rooted".
	base := fmt.Sprintf(`
		WITH scoped AS (SELECT * FROM logs WHERE %s),
		     agg AS (
		         SELECT trace_id, COUNT(*) AS spans, COUNT(DISTINCT service) AS services,
		                COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0) AS errors,
		                MIN(ts - duration_ms::bigint) AS started, MAX(ts) AS ended
		         FROM scoped GROUP BY trace_id
		     ),
		     root AS (
		         SELECT DISTINCT ON (trace_id)
		                trace_id, method, route, path, service, status, duration_ms, labels
		         FROM scoped ORDER BY trace_id, (parent_span <> ''), ts
		     )`, cond)

	outer := []string{}
	if f.ErrorsOnly {
		outer = append(outer, "agg.errors > 0")
	}
	for _, k := range sortedKeys(f.Labels) {
		outer = append(outer, fmt.Sprintf("root.labels->>%s = %s", bind(k), bind(f.Labels[k])))
	}
	outerWhere := ""
	if len(outer) > 0 {
		outerWhere = " WHERE " + strings.Join(outer, " AND ")
	}
	joined := " FROM agg JOIN root USING (trace_id)" + outerWhere

	var total int64
	if err := s.db.QueryRowContext(ctx, base+" SELECT COUNT(*)"+joined, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := base + `
		SELECT agg.trace_id, agg.spans, agg.services, agg.errors, agg.started, agg.ended,
		       root.method, root.route, root.path, root.service, root.status,
		       root.duration_ms, root.labels` + joined +
		" ORDER BY agg.started DESC LIMIT " + bind(f.Limit) + " OFFSET " + bind(f.Offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.TraceSummary
	var ids []any
	for rows.Next() {
		var t ext.TraceSummary
		var started, ended int64
		var labels []byte
		if err := rows.Scan(&t.TraceID, &t.Spans, &t.Services, &t.Errors, &started, &ended,
			&t.Method, &t.Route, &t.Path, &t.Service, &t.Status, &t.DurationMS, &labels); err != nil {
			return nil, 0, err
		}
		t.Start, t.End = time.UnixMilli(started), time.UnixMilli(ended)
		fromJSON(string(labels), &t.Labels)
		t.LogLines = -1
		out = append(out, t)
		ids = append(ids, t.TraceID)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(out) == 0 {
		return out, total, nil
	}

	// One query for the page's line counts, not one per row.
	ph := make([]string, len(ids))
	for i := range ids {
		ph[i] = fmt.Sprintf("$%d", i+1)
	}
	lrows, err := s.db.QueryContext(ctx,
		`SELECT trace_id, COUNT(*) FROM app_logs WHERE trace_id IN (`+strings.Join(ph, ",")+`) GROUP BY trace_id`,
		ids...)
	if err != nil {
		return out, total, nil // the list is useful without the badge
	}
	counts := map[string]int64{}
	for lrows.Next() {
		var id string
		var n int64
		if err := lrows.Scan(&id, &n); err == nil {
			counts[id] = n
		}
	}
	lrows.Close()
	for i := range out {
		out[i].LogLines = counts[out[i].TraceID]
	}
	return out, total, nil
}
