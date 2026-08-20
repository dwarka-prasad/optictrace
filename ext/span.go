package ext

import (
	"context"
	"time"
)

// Span is one operation inside a request: a database query, a cache lookup, an
// outbound call, a stretch of computation worth naming.
//
// A [Record] covers a whole HTTP exchange as OpticTrace saw it from outside.
// A Span is what happened while that exchange was being served, which is the
// difference between "this request took 300ms" and "this request took 300ms,
// 280 of them in one query".
//
// Correlation is by ParentSpanID, never by timing, for the same reason
// [AppLog] correlates that way: under concurrent traffic, matching on
// timestamps files one tenant's work inside another tenant's request.
//
// ATTRIBUTES ARE THE RISK HERE. A statement reads
// `SELECT * FROM users WHERE email = 'a@b.com'`, a cache key embeds an account
// id, a URL carries a token in its query string. Attributes are therefore
// governed — redacted, capped and filtered — before they are stored, exactly
// like an app log line, and for the same reason: "clean it up later" is after
// the data is already at rest.
type Span struct {
	ID int64 `json:"id"`
	// Start is when the operation BEGAN.
	//
	// Deliberately named differently from [Record.Time], which is when an
	// exchange COMPLETED. The two cannot be reconciled — Record.Time cannot
	// change without making old and new rows indistinguishable — so the field
	// names differ to stop anyone assuming they mean the same thing.
	Start time.Time `json:"start"`
	// Service is the application that ran the operation.
	Service string `json:"service"`
	// TraceID and SpanID place this operation in a trace. SpanID is this
	// operation's own id; ParentSpanID is the span it happened inside, which
	// is normally the HTTP span the SDK recorded, or another internal span
	// when operations nest.
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id"`
	// Name is what ran: "db.query", "redis.get", "GET /rates", "score.model".
	// Kept low-cardinality by convention — the varying part belongs in an
	// attribute, not the name, or every chart built on this becomes useless.
	Name string `json:"name"`
	// Kind classifies the operation so a waterfall can colour it and a
	// breakdown can group by it: db, cache, http, queue, rpc, internal.
	// Anything unrecognised is kept verbatim rather than coerced.
	Kind string `json:"kind,omitempty"`
	// DurationMS is how long it took.
	DurationMS float64 `json:"duration_ms"`
	// Error is non-empty when the operation failed, and is governed like any
	// other free text: a driver error routinely quotes the statement that
	// failed, parameters included.
	Error string `json:"error,omitempty"`
	// Attrs describe the operation. Conventional keys, so the dashboard and a
	// breakdown can rely on them:
	//
	//	db.system     postgres · mysql · sqlite · mongodb
	//	db.statement  the statement — pass the TEMPLATE, not the interpolated one
	//	db.rows       rows returned or affected
	//	cache.key     the key, or better its shape
	//	cache.hit     true · false
	//	http.method   the outbound method
	//	http.url      the outbound URL
	//	http.status   the outbound status
	//	queue.topic   the destination
	Attrs map[string]string `json:"attrs,omitempty"`
	// Route is the rule pattern the enclosing request matched, when the
	// producer knows it. It lets a per-rule `spans:` block apply.
	//
	// Client-supplied and therefore untrusted — safe only because a per-rule
	// block can exclusively TIGHTEN the global policy. A producer that lies
	// about its route, or omits it, gets the global floor and never less.
	Route string `json:"route,omitempty"`
	// Source names the producer: an SDK name, or "ingest" for a direct POST.
	Source string `json:"source,omitempty"`
	// Truncated reports that an attribute or the error was cut to the
	// configured byte cap.
	Truncated bool `json:"truncated,omitempty"`
}

// End returns when the operation finished.
func (s Span) End() time.Time {
	return s.Start.Add(time.Duration(s.DurationMS * float64(time.Millisecond)))
}

// SpanFilter selects stored spans. The zero value matches everything within
// the store's own limits.
type SpanFilter struct {
	TraceID string
	// SpanID matches a span's OWN id.
	SpanID string
	// ParentSpanID selects the operations that ran inside one HTTP hop — the
	// query a trace waterfall actually makes.
	ParentSpanID string
	Service      string
	Kind         string
	// MinDurationMS keeps only spans at least this slow. The point of a
	// breakdown is usually the slow thing.
	MinDurationMS float64
	// ErrorsOnly keeps only failed operations.
	ErrorsOnly bool
	Since      time.Time
	Until      time.Time
	// Search is a substring match over the name.
	Search string
	Limit  int
	Offset int
}

// SpanBreakdown aggregates where a route's time actually goes.
//
// Computed in the store rather than by summing a page in the browser: a
// summary of the first 200 rows is wrong at exactly the volumes where a
// summary starts to matter.
type SpanBreakdown struct {
	Name string `json:"name"`
	Kind string `json:"kind,omitempty"`
	// Count is how many times it ran across the window, which for a query
	// inside a loop is the number worth seeing.
	Count int64 `json:"count"`
	// Requests is how many distinct requests ran it, so Count/Requests is the
	// per-request multiplier — the shape an N+1 query makes.
	Requests int64   `json:"requests"`
	Errors   int64   `json:"errors"`
	TotalMS  float64 `json:"total_ms"`
	AvgMS    float64 `json:"avg_ms"`
	P95MS    float64 `json:"p95_ms"`
	MaxMS    float64 `json:"max_ms"`
}

// SpanSummary aggregates stored spans for a window.
type SpanSummary struct {
	Total int64 `json:"total"`
	// ByKind and ByService are counts keyed by kind and by emitting service.
	ByKind    map[string]int64 `json:"by_kind"`
	ByService map[string]int64 `json:"by_service"`
	// RequestsWithSpans is how many HTTP spans have any inner detail — the
	// denominator for "how much of my traffic can I actually break down".
	RequestsWithSpans int64 `json:"requests_with_spans"`
	Errors            int64 `json:"errors"`
}

// SpanStore is an OPTIONAL companion to Store: a driver may implement it to
// persist inner spans, and is a perfectly good driver if it does not. It is a
// separate interface rather than more methods on Store for the same reason
// [AppLogStore] and [TraceStore] are — Store is published and implemented
// outside this module, so adding a method to it breaks every third-party
// driver at compile time.
//
// Detect support with a type assertion:
//
//	if ss, ok := myStore.(ext.SpanStore); ok { ... }
//
// CONTRACT — if you implement both Store and SpanStore, Store.Purge MUST also
// delete the spans belonging to the records it purges. Erasure that removes a
// tenant's requests but leaves the statements those requests ran is not
// erasure. ext/exttest asserts this.
type SpanStore interface {
	// SaveSpans persists a batch. Called from the async writer, never from a
	// request hot path. Implementations must be safe for concurrent use.
	SaveSpans(ctx context.Context, spans []Span) error
	// QuerySpans returns matching spans oldest-first — reading a request's
	// work means reading it in the order it happened — plus the total
	// matching count, ignoring Limit/Offset.
	QuerySpans(ctx context.Context, f SpanFilter) (spans []Span, total int64, err error)
	// SpanBreakdown groups spans by name for a window, optionally narrowed to
	// one route. This is the "where did the time go" query.
	SpanBreakdown(ctx context.Context, since time.Time, route string, limit int) ([]SpanBreakdown, error)
	// SpanStats aggregates stored spans since a time.
	SpanStats(ctx context.Context, since time.Time) (*SpanSummary, error)
	// CountSpans returns the total stored.
	CountSpans(ctx context.Context) (int64, error)
	// PruneSpansBefore enforces age-based retention. Spans run well above
	// request volume, so they carry their own horizon.
	PruneSpansBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
