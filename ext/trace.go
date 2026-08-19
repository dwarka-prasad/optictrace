package ext

import (
	"context"
	"time"
)

// TraceSummary is one distributed trace rolled up to a single row: what was
// called, how many hops it took, and whether it went wrong.
//
// The fields are deliberately the ones a person scans a list by. Everything
// else about a trace is a query away by ID, and putting it here would mean
// loading every hop's payload to render a table.
type TraceSummary struct {
	TraceID string `json:"trace_id"`
	// Root describes the entry hop — the span with no parent, or failing that
	// the earliest one. A trace whose root was never recorded (the entry
	// service is not instrumented) still lists, named by what WAS seen,
	// because a partial trace is evidence and hiding it helps nobody.
	Method  string `json:"method"`
	Route   string `json:"route"`
	Path    string `json:"path"`
	Service string `json:"service"`
	// Status of the root hop: what the caller was actually told.
	Status int `json:"status"`
	// Spans is the number of recorded hops.
	Spans int `json:"spans"`
	// Services is how many distinct services took part.
	Services int `json:"services"`
	// Errors counts hops that returned 5xx, including inner ones. An inner
	// failure a retry rescued never shows in the root status, and it is
	// exactly what someone opening a trace list is hunting for.
	Errors int `json:"errors"`
	// DurationMS is the root hop's duration when there is a root, which is
	// what the caller waited. Concurrent inner hops make the sum of spans
	// meaningless as a wall-clock figure.
	DurationMS float64 `json:"duration_ms"`
	// Start is the earliest hop's time, End the latest hop's completion.
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	// Labels from the root hop, so a trace list can be read per tenant.
	Labels map[string]string `json:"labels,omitempty"`
	// LogLines is how many application log lines the whole trace produced,
	// or -1 when the store cannot answer cheaply.
	LogLines int64 `json:"log_lines"`
}

// TraceFilter narrows a trace listing.
type TraceFilter struct {
	Since time.Time
	// ErrorsOnly keeps traces with at least one 5xx hop.
	ErrorsOnly bool
	// Service keeps traces any hop of which was served by this service.
	Service string
	// Search matches the root path or route.
	Search string
	// Labels must all match on the root hop.
	Labels map[string]string
	Limit  int
	Offset int
}

// TraceStore is an OPTIONAL companion to Store: a driver may implement it to
// list traces, and is a perfectly good driver if it does not. It is a separate
// interface rather than more methods on Store for the same reason
// [AppLogStore] is — Store is published and implemented outside this module,
// so adding a method to it breaks every third-party driver at compile time.
//
// Detect support with a type assertion:
//
//	if ts, ok := myStore.(ext.TraceStore); ok { ... }
//
// A driver that does not implement it loses the trace list, not correlation:
// every record still carries its trace and span ids, and fetching one trace by
// ID is an ordinary Query.
type TraceStore interface {
	// Traces returns matching traces newest-first, plus the total matching
	// count ignoring Limit/Offset.
	Traces(ctx context.Context, f TraceFilter) (traces []TraceSummary, total int64, err error)
}
