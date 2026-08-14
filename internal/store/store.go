// Package store persists governed telemetry records (what optic.yaml allowed
// through) and answers the dashboard's query/analytics needs.
//
// Contract: everything stored here is ALREADY restricted/redacted by the
// engine. The store is deliberately downstream of governance so no driver
// can ever see raw sensitive payloads.
package store

import (
	"context"
	"time"
)

// Record is one captured HTTP exchange, post-governance.
type Record struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Service string    `json:"service"`
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	Route   string    `json:"route"` // low-cardinality route pattern
	Status  int       `json:"status"`
	// DurationMS is milliseconds (float) — the natural unit for SDKs in
	// every language to produce and for the dashboard to consume.
	DurationMS float64 `json:"duration_ms"`
	Remote     string  `json:"remote"`
	Source     string  `json:"source"` // "proxy" or an SDK name

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
	Limit      int
	Offset     int
}

// TimeBucket is one point in an aggregated traffic series.
type TimeBucket struct {
	Time       time.Time `json:"time"`
	Count      int64     `json:"count"`
	Errors     int64     `json:"errors"` // status >= 500
	AvgLatency float64   `json:"avg_latency_ms"`
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

// LogStore is the persistence contract. Implementations must be safe for
// concurrent use. Save is called from the async writer, never from the
// request hot path.
type LogStore interface {
	Save(ctx context.Context, rec *Record) error
	Query(ctx context.Context, f Filter) (records []Record, total int64, err error)
	Get(ctx context.Context, id int64) (*Record, error)
	Stats(ctx context.Context, since time.Time, bucket time.Duration) (*Stats, error)
	// RouteStats aggregates every route seen since the given time.
	RouteStats(ctx context.Context, since time.Time) ([]RouteDetail, error)
	// RuleMatchCounts reports how often each named rule fired since the
	// given time (names come from the loaded config).
	RuleMatchCounts(ctx context.Context, since time.Time, ruleNames []string) ([]RuleMatch, error)
	// Count returns total stored records (for /api/system).
	Count(ctx context.Context) (int64, error)
	// Recent returns up to limit full records since a time (newest first) —
	// the input for spec inference and spec-vs-traffic checks.
	Recent(ctx context.Context, since time.Time, limit int) ([]Record, error)
	// UsageByLabel aggregates traffic per consumer (a label value, e.g.
	// tenant) since the given time — the FinOps view.
	UsageByLabel(ctx context.Context, since time.Time, label string) ([]Usage, error)
	Prune(ctx context.Context, maxRows int64) (removed int64, err error)
	Close() error
}
