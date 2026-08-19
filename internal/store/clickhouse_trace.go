package store

import (
	"context"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

var _ ext.TraceStore = (*ClickHouseStore)(nil)

// Traces rolls the recorded hops up into one row per trace.
//
// ClickHouse has no DISTINCT ON and correlated subqueries are a trap here, so
// the root hop is picked with argMin over a sort key that expresses both
// cases at once: `(parent_span != ”, ts)` puts a parentless hop first and
// falls back to the earliest hop when the entry service was never
// instrumented.
func (s *ClickHouseStore) Traces(ctx context.Context, f ext.TraceFilter) ([]ext.TraceSummary, int64, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	where := []string{"trace_id != ''"}
	var args []any
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.UnixMilli())
	}
	if f.Service != "" {
		where = append(where, "service = ?")
		args = append(args, f.Service)
	}
	if f.Search != "" {
		where = append(where, "(position(path, ?) > 0 OR position(route, ?) > 0)")
		args = append(args, f.Search, f.Search)
	}

	// argMin over a tuple returns the whole root row in one pass.
	agg := `
		SELECT trace_id, count() AS spans, uniqExact(service) AS services,
		       countIf(status >= 500) AS errors,
		       min(ts - toInt64(duration_ms)) AS started, max(ts) AS ended,
		       argMin(method, (parent_span != '', ts))      AS r_method,
		       argMin(route, (parent_span != '', ts))       AS r_route,
		       argMin(path, (parent_span != '', ts))        AS r_path,
		       argMin(service, (parent_span != '', ts))     AS r_service,
		       argMin(status, (parent_span != '', ts))      AS r_status,
		       argMin(duration_ms, (parent_span != '', ts)) AS r_duration,
		       argMin(assumeNotNull(labels), (parent_span != '', ts)) AS r_labels
		FROM logs WHERE ` + strings.Join(where, " AND ") + ` GROUP BY trace_id`

	outer := []string{}
	var outerArgs []any
	if f.ErrorsOnly {
		outer = append(outer, "errors > 0")
	}
	for _, k := range sortedKeys(f.Labels) {
		outer = append(outer, "JSONExtractString(r_labels, ?) = ?")
		outerArgs = append(outerArgs, k, f.Labels[k])
	}
	outerWhere := ""
	if len(outer) > 0 {
		outerWhere = " WHERE " + strings.Join(outer, " AND ")
	}

	countArgs := append(append([]any{}, args...), outerArgs...)
	var total uint64
	if err := s.db.QueryRowContext(ctx,
		"SELECT count() FROM ("+agg+")"+outerWhere, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		"SELECT * FROM ("+agg+")"+outerWhere+" ORDER BY started DESC LIMIT ? OFFSET ?",
		append(countArgs, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.TraceSummary
	var ids []any
	for rows.Next() {
		var (
			t               ext.TraceSummary
			spans, services uint64
			errs            uint64
			started, ended  int64
			status          int32
			labels          string
		)
		if err := rows.Scan(&t.TraceID, &spans, &services, &errs, &started, &ended,
			&t.Method, &t.Route, &t.Path, &t.Service, &status, &t.DurationMS, &labels); err != nil {
			return nil, 0, err
		}
		t.Spans, t.Services, t.Errors, t.Status = int(spans), int(services), int(errs), int(status)
		t.Start, t.End = time.UnixMilli(started), time.UnixMilli(ended)
		fromJSON(labels, &t.Labels)
		t.LogLines = -1
		out = append(out, t)
		ids = append(ids, t.TraceID)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(out) == 0 {
		return out, int64(total), nil
	}

	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	lrows, err := s.db.QueryContext(ctx,
		"SELECT trace_id, count() FROM app_logs WHERE trace_id IN ("+ph+") GROUP BY trace_id", ids...)
	if err != nil {
		return out, int64(total), nil // the list is useful without the badge
	}
	counts := map[string]int64{}
	for lrows.Next() {
		var id string
		var n uint64
		if err := lrows.Scan(&id, &n); err == nil {
			counts[id] = int64(n)
		}
	}
	lrows.Close()
	for i := range out {
		out[i].LogLines = counts[out[i].TraceID]
	}
	return out, int64(total), nil
}
