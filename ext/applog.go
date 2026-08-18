package ext

import (
	"context"
	"strings"
	"time"
)

// AppLog is one line your application logged while serving a request.
//
// The name is deliberately not "log": in this codebase a "log" is an HTTP
// exchange (Record, the `logs` table, Store). An AppLog is the other thing —
// what the application itself wrote to its logger during that exchange.
//
// Correlation is by SpanID, never by timing. The proxy already hands the
// application a traceparent carrying this hop's span, so a line the app logs
// under that context belongs to that span as a fact, not as an inference.
// Guessing from timestamps would file one tenant's line under another
// tenant's request whenever two are served concurrently.
type AppLog struct {
	ID   int64     `json:"id"`
	Time time.Time `json:"time"`
	// Service is the application that emitted the line, which need not be the
	// service that recorded the span — a downstream hop logs under the same
	// trace.
	Service string `json:"service"`
	// TraceID and SpanID tie the line to one hop of one request. A line
	// without a SpanID belongs to no request; what happens to it is
	// telemetry.app_logs.drop_orphans.
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id"`
	// Level is normalised lowercase: debug, info, warn, error, fatal.
	// Anything unrecognised is kept verbatim and sorts above fatal, so a
	// custom level is never silently dropped by a level filter.
	Level   string `json:"level,omitempty"`
	Message string `json:"message"`
	// Fields carries structured logger key/values, stringified. Values are
	// redacted under the same policy as the message — a token pasted into a
	// field is exactly as leaked as one in the message text.
	Fields map[string]string `json:"fields,omitempty"`
	// Source names the producer: an SDK name, or "ingest" for a direct POST.
	Source string `json:"source,omitempty"`
	// Truncated reports that Message was cut to the configured byte cap.
	Truncated bool `json:"truncated,omitempty"`
}

// AppLogFilter selects stored lines. The zero value matches everything within
// the store's own limits.
type AppLogFilter struct {
	TraceID string
	SpanID  string
	Service string
	// LevelMin drops anything less severe. Empty means no level filter.
	LevelMin string
	Since    time.Time
	Until    time.Time
	// Search is a substring match over the message.
	Search string
	Limit  int
	Offset int
}

// AppLogSummary aggregates stored lines for a window. Computed in the store
// rather than by counting a page in the browser: a dashboard that summarises
// the first 200 rows and calls it a total is quietly lying at exactly the
// volumes where the summary starts to matter.
type AppLogSummary struct {
	Total int64 `json:"total"`
	// ByLevel and ByService are counts keyed by level and by emitting service.
	ByLevel   map[string]int64 `json:"by_level"`
	ByService map[string]int64 `json:"by_service"`
	// SpansWithLogs is how many distinct requests contributed lines — the
	// denominator for "how much of my traffic is actually explainable".
	SpansWithLogs int64 `json:"spans_with_logs"`
}

// AppLogStore is an OPTIONAL companion to Store: a driver may implement it to
// persist application log lines, and is a perfectly good driver if it does
// not. It is deliberately a separate interface rather than more methods on
// Store, because Store is published and implemented outside this module —
// adding a method to it would break every third-party driver at compile time,
// and drivers here have twice been broken by far smaller changes.
//
// Detect support with a type assertion:
//
//	if als, ok := myStore.(ext.AppLogStore); ok { ... }
//
// CONTRACT — if you implement both Store and AppLogStore, Store.Purge MUST
// also delete the app logs belonging to the records it purges. Erasure that
// removes a tenant's requests but leaves the log lines those requests wrote
// is not erasure, and app logs are the likelier place for the personal data
// to be sitting. ext/exttest asserts this.
type AppLogStore interface {
	// SaveAppLogs persists a batch. Called from the async writer, never from
	// the request hot path. Implementations must be safe for concurrent use.
	SaveAppLogs(ctx context.Context, lines []AppLog) error
	// QueryAppLogs returns matching lines oldest-first — reading a request's
	// logs means reading them in the order they happened — plus the total
	// matching count, ignoring Limit/Offset.
	QueryAppLogs(ctx context.Context, f AppLogFilter) (lines []AppLog, total int64, err error)
	// CountAppLogs returns the total stored.
	CountAppLogs(ctx context.Context) (int64, error)
	// AppLogStats aggregates the lines stored since a time.
	AppLogStats(ctx context.Context, since time.Time) (*AppLogSummary, error)
	// PruneAppLogsBefore enforces age-based retention. App logs run orders of
	// magnitude above request volume, so they usually want a shorter horizon
	// than records do.
	PruneAppLogsBefore(ctx context.Context, cutoff time.Time) (removed int64, err error)
}

// levelRank orders severities for LevelMin comparisons. An unknown level
// returns a rank above every known one: a filter should never be the reason a
// custom "critical" or "panic" line disappears.
func levelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace":
		return 0
	case "debug":
		return 1
	case "info", "information", "notice", "":
		return 2
	case "warn", "warning":
		return 3
	case "error", "err":
		return 4
	case "fatal", "critical", "crit", "panic":
		return 5
	default:
		return 6
	}
}

// LevelRank exposes the severity ordering so drivers and filters agree on
// what "at least warn" means.
func LevelRank(level string) int { return levelRank(level) }

// NormaliseLevel maps a logger's spelling onto the canonical set. It returns
// an unrecognised level unchanged rather than forcing it into a bucket.
func NormaliseLevel(level string) string {
	l := strings.ToLower(strings.TrimSpace(level))
	switch l {
	case "warning":
		return "warn"
	case "err":
		return "error"
	case "information", "notice":
		return "info"
	case "critical", "crit", "panic":
		return "fatal"
	case "":
		return "info"
	}
	return l
}
