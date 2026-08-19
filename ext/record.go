package ext

import "time"

// DefaultAnalysisMaxRows bounds how many records an analysis pass reads when
// no explicit limit is given. These are FULL records including bodies, so at
// the default 64 KiB capture limit this is a memory ceiling, not just a row
// count. Override with telemetry.store.analysis_max_rows.
const DefaultAnalysisMaxRows = 20_000

// MaxAnalysisMaxRows is the hard ceiling on that knob.
const MaxAnalysisMaxRows = 500_000

// AnalysisLimit resolves a requested limit against the defaults.
func AnalysisLimit(limit int) int {
	if limit <= 0 {
		return DefaultAnalysisMaxRows
	}
	if limit > MaxAnalysisMaxRows {
		return MaxAnalysisMaxRows
	}
	return limit
}

// Record is one captured HTTP exchange, post-governance.
type Record struct {
	ID int64 `json:"id"`
	// Time is when the exchange COMPLETED — the record is written once the
	// response is known, and every implementation stamps it there.
	//
	// Anything that needs the start must subtract DurationMS. A trace
	// waterfall built on Time directly draws the parent starting after the
	// children it called, because the parent is the last hop to finish.
	// Stamping the start instead would have been the friendlier choice, but
	// changing it now would make old and new rows indistinguishable and
	// silently corrupt every timeline that spans the change.
	Time    time.Time `json:"time"`
	Service string    `json:"service"`
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	// Query is the sanitized query string (policy-masked, stable ordering).
	Query  string `json:"query,omitempty"`
	Route  string `json:"route"` // low-cardinality route pattern
	Status int    `json:"status"`
	// DurationMS is milliseconds (float) — the natural unit for SDKs in
	// every language to produce and for the dashboard to consume.
	DurationMS float64 `json:"duration_ms"`
	Remote     string  `json:"remote"`
	Source     string  `json:"source"` // "proxy" or an SDK name

	// TraceID ties every hop of one request together across services, so a
	// flat log becomes a tree. Taken from the inbound W3C traceparent when
	// the caller sent one, generated when it did not.
	TraceID string `json:"trace_id,omitempty"`
	// SpanID identifies this hop; ParentSpanID is the caller's span, empty at
	// the root. Together these are what makes the tree reconstructible rather
	// than just a filtered list.
	SpanID       string `json:"span_id,omitempty"`
	ParentSpanID string `json:"parent_span_id,omitempty"`
	// Stream marks a long-lived streaming response (SSE or chunked). Its
	// DurationMS is a connection lifetime, not a latency, so percentile
	// aggregations exclude it — one 10-minute stream would otherwise define
	// a route's p95 for the whole window.
	Stream bool `json:"stream,omitempty"`

	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	ReqTruncated    bool              `json:"req_truncated,omitempty"`
	RespTruncated   bool              `json:"resp_truncated,omitempty"`

	ReqBytes     int64             `json:"req_bytes"`
	RespBytes    int64             `json:"resp_bytes"`
	Labels       map[string]string `json:"labels,omitempty"`
	MatchedRules []string          `json:"matched_rules,omitempty"`
	// Meters holds numeric usage extracted from the response by rule-level
	// meter paths (e.g. LLM token counts) — the raw material for billing.
	Meters map[string]float64 `json:"meters,omitempty"`
}

// Filter narrows a log query. Zero values mean "no constraint".
type Filter struct {
	Method     string
	PathPrefix string
	Search     string // substring across path + bodies
	StatusMin  int
	StatusMax  int
	Since      time.Time
	Until      time.Time
	// TraceID selects every hop of one request — the question "what did this
	// call actually do" once several services report into one store.
	TraceID string
	// Labels selects records carrying ALL of these label values exactly —
	// the multi-tenant question, "show me only this tenant's calls".
	//
	// Matched literally, never as a pattern. A tenant named "acme_1" must not
	// select "acmeX1": the same mistake that once made `purge` destroy a
	// neighbour's data, and just as wrong when it silently widens what someone
	// is shown.
	Labels map[string]string
	Limit  int
	Offset int
}

// TimeBucket is one point in an aggregated traffic series.
type TimeBucket struct {
	Time       time.Time `json:"time"`
	Count      int64     `json:"count"`
	Errors     int64     `json:"errors"` // status >= 500
	AvgLatency float64   `json:"avg_latency_ms"`
	// ClientErrors counts 4xx separately. Folding them into Errors would say
	// the service is failing when a caller is sending bad requests, and the
	// two need opposite responses.
	ClientErrors int64 `json:"client_errors"`
	// P95Latency is the tail within this bucket. An average over a bucket
	// hides exactly the requests worth looking at: a handful of 3s responses
	// inside a minute of 5ms ones move the mean by almost nothing.
	P95Latency float64 `json:"p95_latency_ms"`
}

// RouteStat aggregates one route's traffic.
type RouteStat struct {
	Route      string  `json:"route"`
	Method     string  `json:"method"`
	Count      int64   `json:"count"`
	Errors     int64   `json:"errors"`
	AvgLatency float64 `json:"avg_latency_ms"`
	P95Latency float64 `json:"p95_latency_ms"`
}

// Stats is the dashboard's aggregate view over a time window.
type Stats struct {
	Total        int64            `json:"total"`
	Errors       int64            `json:"errors"`
	ErrorRate    float64          `json:"error_rate"`
	P50LatencyMS float64          `json:"p50_latency_ms"`
	P95LatencyMS float64          `json:"p95_latency_ms"`
	P99LatencyMS float64          `json:"p99_latency_ms"`
	StatusCounts map[string]int64 `json:"status_counts"` // by class: 2xx, 4xx...
	Series       []TimeBucket     `json:"series"`
	TopRoutes    []RouteStat      `json:"top_routes"`

	// BodiesKept is how many records in the window stored a request or
	// response body. Against Total it is the only honest read on what
	// sampling is actually doing — a `sample: 0.05` that quietly matches
	// nothing and a `sample: 1.0` look identical in every other number on the
	// page. Zero from a driver that does not compute it, so treat 0 as
	// "unknown" rather than "nothing was kept".
	BodiesKept int64 `json:"bodies_kept"`
	// BytesSeen is the request and response bytes that passed through, whether
	// or not their bodies were stored. Paired with BodiesKept it answers "what
	// is this costing me to keep".
	BytesSeen int64 `json:"bytes_seen"`
}

// RouteDetail extends RouteStat with the percentiles the Routes dashboard
// shows for every route (not just the top 10).
type RouteDetail struct {
	RouteStat
	P50Latency float64 `json:"p50_latency_ms"`
	P99Latency float64 `json:"p99_latency_ms"`
	ReqBytes   int64   `json:"req_bytes"`
	RespBytes  int64   `json:"resp_bytes"`
}

// RuleMatch is how often one governance rule fired in a window.
type RuleMatch struct {
	Rule  string `json:"rule"`
	Count int64  `json:"count"`
}

// Usage aggregates one consumer's traffic for cost attribution.
type Usage struct {
	Consumer   string             `json:"consumer"` // label value; "" -> "(unattributed)"
	Requests   int64              `json:"requests"`
	Errors     int64              `json:"errors"`
	ReqBytes   int64              `json:"req_bytes"`
	RespBytes  int64              `json:"resp_bytes"`
	DurationMS float64            `json:"duration_ms_total"`
	Meters     map[string]float64 `json:"meters,omitempty"`
}

// ServiceStat summarizes one service in a multi-service deployment. One
// agent proxies one service, but many SDKs can report into a single agent,
// so the store may hold several.
type ServiceStat struct {
	Service    string    `json:"service"`
	Requests   int64     `json:"requests"`
	Errors     int64     `json:"errors"`
	ErrorRate  float64   `json:"error_rate"`
	AvgLatency float64   `json:"avg_latency_ms"`
	P95Latency float64   `json:"p95_latency_ms"`
	Routes     int64     `json:"routes"`
	Sources    string    `json:"sources"` // e.g. "proxy, express"
	LastSeen   time.Time `json:"last_seen"`
}
