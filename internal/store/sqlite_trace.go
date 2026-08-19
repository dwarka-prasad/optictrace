package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// Traces rolls the recorded hops up into one row per trace.
//
// The root hop is the one with no parent span. When the entry service is not
// instrumented there is no such row, and the earliest hop stands in: a trace
// that starts halfway through is still evidence, and dropping it would hide
// exactly the services someone has not got round to instrumenting yet.
var _ ext.TraceStore = (*SQLiteStore)(nil)

func (s *SQLiteStore) Traces(ctx context.Context, f ext.TraceFilter) ([]ext.TraceSummary, int64, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	where := []string{"trace_id <> ''"}
	args := []any{}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.UnixMilli())
	}
	if f.Service != "" {
		where = append(where, "service = ?")
		args = append(args, f.Service)
	}
	if f.Search != "" {
		where = append(where, "(path LIKE ? OR route LIKE ?)")
		like := "%" + f.Search + "%"
		args = append(args, like, like)
	}
	cond := strings.Join(where, " AND ")

	// One pass per trace: the aggregate row, and the id of the hop that stands
	// for it. ts is when a hop FINISHED (see ext.Record.Time), so the trace
	// starts at the earliest ts MINUS that hop's duration — using ts directly
	// puts the root, the last hop to finish, after the children it called. MIN(ts) picks the earliest, and parent_span = '' sorts before
	// any real parent id, so ordering by (parent_span <> '', ts) puts a real
	// root first and falls back to the earliest hop when there is none.
	agg := fmt.Sprintf(`
		SELECT trace_id,
		       COUNT(*)                                            AS spans,
		       COUNT(DISTINCT service)                             AS services,
		       COALESCE(SUM(status >= 500), 0)                     AS errors,
		       MIN(ts - CAST(duration_ms AS INTEGER))              AS started,
		       MAX(ts)                                             AS ended
		FROM logs WHERE %s GROUP BY trace_id`, cond)

	// Conditions that can only be judged once a trace has been rolled up and
	// its root hop identified. They must sit in BOTH the count and the page,
	// or the pager reports a total the pages cannot produce.
	outer := []string{}
	outerArgs := []any{}
	if f.ErrorsOnly {
		outer = append(outer, "a.errors > 0")
	}
	// json_extract compares the value literally — deliberately not LIKE, which
	// is how purge once matched a neighbouring tenant.
	for _, k := range sortedKeys(f.Labels) {
		outer = append(outer, "json_extract(r.labels, '$.' || ?) = ?")
		outerArgs = append(outerArgs, k, f.Labels[k])
	}
	outerWhere := ""
	if len(outer) > 0 {
		outerWhere = "WHERE " + strings.Join(outer, " AND ")
	}

	// The root hop: no parent when the entry service is instrumented, the
	// earliest hop otherwise. parent_span = '' sorts before any real id, so
	// one ORDER BY expresses both cases.
	joined := fmt.Sprintf(`
		FROM (%s) a
		JOIN logs r ON r.id = (
		    SELECT id FROM logs
		    WHERE trace_id = a.trace_id
		    ORDER BY parent_span <> '', ts LIMIT 1
		)
		%s`, agg, outerWhere)

	countArgs := append(append([]any{}, args...), outerArgs...)
	var total int64
	if err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) "+joined, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT a.trace_id, a.spans, a.services, a.errors, a.started, a.ended,
		        r.method, r.route, r.path, r.service, r.status, r.duration_ms, r.labels `+
			joined+` ORDER BY a.started DESC LIMIT ? OFFSET ?`,
		append(countArgs, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []ext.TraceSummary
	for rows.Next() {
		var t ext.TraceSummary
		var started, ended int64
		var labels string
		if err := rows.Scan(&t.TraceID, &t.Spans, &t.Services, &t.Errors, &started, &ended,
			&t.Method, &t.Route, &t.Path, &t.Service, &t.Status, &t.DurationMS, &labels); err != nil {
			return nil, 0, err
		}
		t.Start = time.UnixMilli(started)
		t.End = time.UnixMilli(ended)
		fromJSON(labels, &t.Labels)
		t.LogLines = -1 // filled below only when app logs are stored
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	// Line counts in one query for the page, not one per row. A trace list
	// that fires N+1 queries to show a badge is a trace list nobody keeps
	// open.
	if len(out) > 0 {
		ids := make([]any, len(out))
		ph := make([]string, len(out))
		for i, t := range out {
			ids[i] = t.TraceID
			ph[i] = "?"
		}
		counts := map[string]int64{}
		lrows, err := s.db.QueryContext(ctx,
			`SELECT trace_id, COUNT(*) FROM app_logs WHERE trace_id IN (`+
				strings.Join(ph, ",")+`) GROUP BY trace_id`, ids...)
		if err == nil {
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
		}
	}
	return out, total, nil
}
