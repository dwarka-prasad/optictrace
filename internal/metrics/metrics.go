// Package metrics exposes OpticTrace telemetry to Prometheus.
//
// Design notes:
//   - The collector owns a private Registry (not the global default), so
//     embedding OpticTrace in an app that already uses client_golang can
//     never cause duplicate-registration panics.
//   - Custom labels from optic.yaml become real Prometheus dimensions, taken
//     from engine.LabelKeys(); requests without a value export "" (Prometheus
//     requires stable schemas). A Prometheus metric cannot change its label
//     set, so a config reload that adds a label REBUILDS the affected vectors
//     (see SetLabelKeys) rather than mutating them. Without that, a newly
//     added label would show up in the dashboard but silently never appear in
//     /metrics — a Grafana panel that stays empty with no error anywhere.
//   - The `route` label carries the matched rule's glob (or a normalized
//     path), never the raw path — cardinality stays bounded by design.
//   - P50/P95/P99 are derived by Prometheus from the latency histogram, e.g.:
//     histogram_quantile(0.99, sum by (le, route) (rate(optictrace_request_duration_seconds_bucket[5m])))
package metrics

import (
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Observation is one completed HTTP exchange, as seen by the collector.
type Observation struct {
	// Service names the application the exchange belongs to. Empty means the
	// agent's own service — the sidecar case, where they are the same thing.
	// An SDK reporting into a shared agent sets it, which is what keeps a
	// fleet from collapsing into one series.
	Service   string
	Method    string
	Route     string // low-cardinality route pattern, not the raw path
	Status    int
	Duration  time.Duration
	ReqBytes  int64
	RespBytes int64
	Labels    map[string]string // values for the custom label schema
	// Stream marks a long-lived response (SSE, chunked streaming) rather
	// than a request/response exchange. Its duration is recorded on a
	// separate histogram: a 10-minute stream observed as a 600s request
	// makes the route's p95 meaningless for the whole window.
	Stream bool
}

// OverLimit replaces a custom label's value once that label has already
// contributed maxLabelValues distinct values. Every subsequent unseen value
// collapses into this single series, so cardinality stops growing.
const OverLimit = "__over_limit__"

// Collector aggregates per-request metrics and serves them via Handler().
type Collector struct {
	// Two registries, because client_golang deliberately remembers a metric
	// name's label schema for the lifetime of a Registry — Unregister leaves
	// dimHashesByName intact so exposition stays consistent. A metric whose
	// dimensions come from optic.yaml therefore cannot be re-registered with
	// a new label set; it needs a fresh registry.
	//
	// stable holds everything whose schema is fixed at build time; dynamic
	// holds only the two vectors that carry custom labels, and is replaced
	// wholesale on reload. Handler gathers from both.
	stable  *prometheus.Registry
	dynamic atomic.Pointer[prometheus.Registry]
	// rebuildMu serializes SetLabelKeys against itself; Observe is lock-free
	// via the atomic pointers.
	rebuildMu sync.Mutex

	// Cardinality guard. Label values arrive from arbitrary request headers,
	// so an unbounded value space is a real availability risk for the
	// Prometheus scraping this. seen tracks distinct values per label key.
	maxLabelValues int
	cardMu         sync.Mutex
	seen           map[string]map[string]struct{}

	// dims holds everything whose label schema depends on optic.yaml, so a
	// reload can swap it atomically without locking the hot path.
	dims atomic.Pointer[dimensions]
	// buckets and constLabels are kept so the vectors can be rebuilt.
	buckets     []float64
	constLabels prometheus.Labels
	// service is this agent's own name, used when an observation does not
	// carry one of its own.
	service string

	reqSize  *prometheus.HistogramVec
	respSize *prometheus.HistogramVec
	// Streams are measured separately from requests — different phenomenon,
	// different useful bucket range.
	streams        *prometheus.CounterVec
	streamDuration *prometheus.HistogramVec
	streamsOpen    prometheus.Gauge
	inflight       prometheus.Gauge
	dropped        prometheus.Counter
	ingested       prometheus.Counter
	appLogsStored  prometheus.Counter
	appLogsDropped *prometheus.CounterVec

	exported     *prometheus.CounterVec
	exportFailed *prometheus.CounterVec
	exportDrops  *prometheus.CounterVec

	labelCapped   *prometheus.CounterVec
	labelDistinct *prometheus.GaugeVec
}

// dimensions is the set of metrics whose label schema comes from optic.yaml.
// Replaced wholesale on reload; never mutated in place.
type dimensions struct {
	keys     []string
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// newDimensions builds the config-dependent vectors for one label schema.
//
// `service` is a VARIABLE label here, not a const one, even though the agent
// has a service name of its own. When framework SDKs report into a shared
// agent — the documented fleet deployment — the records carry several service
// names and a const label would collapse them all into the collector's own.
// The store kept them apart while Prometheus did not, so a fleet looked like
// one service on every dashboard.
//
// PromQL cannot tell a const label from a variable one, so existing queries
// and dashboards are unaffected.
func newDimensions(keys []string, buckets []float64, constLabels prometheus.Labels) *dimensions {
	base := []string{"service", "method", "route", "status", "status_class"}
	return &dimensions{
		keys: keys,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "optictrace_requests_total", Help: "Total HTTP requests observed.",
		}, append(append([]string{}, base...), keys...)),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "optictrace_request_duration_seconds", Help: "Request latency.",
			Buckets: buckets,
		}, append([]string{"service", "method", "route"}, keys...)),
	}
}

// New builds a Collector for one service. customKeys is the fixed set of
// optic.yaml label names (from engine.LabelKeys()); maxLabelValues caps the
// distinct values each may contribute (0 disables the guard).
func New(service string, buckets []float64, customKeys []string, maxLabelValues int) *Collector {
	reg := prometheus.NewRegistry()
	constLabels := prometheus.Labels{"service": service}

	sizeBuckets := prometheus.ExponentialBuckets(64, 4, 10) // 64B .. ~16MB

	c := &Collector{
		stable:         reg,
		service:        service,
		maxLabelValues: maxLabelValues,
		buckets:        buckets,
		constLabels:    constLabels,
		seen:           make(map[string]map[string]struct{}, len(customKeys)),
		reqSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "optictrace_request_size_bytes", Help: "Request body size.",
			Buckets: sizeBuckets, ConstLabels: constLabels,
		}, []string{"method", "route"}),
		respSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "optictrace_response_size_bytes", Help: "Response body size.",
			Buckets: sizeBuckets, ConstLabels: constLabels,
		}, []string{"method", "route"}),
		streams: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "optictrace_streams_total", Help: "Long-lived streaming responses observed (SSE or chunked).",
			ConstLabels: constLabels,
		}, []string{"method", "route"}),
		streamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "optictrace_stream_duration_seconds",
			Help: "How long streaming responses stayed open. Separate from request latency on purpose.",
			// 1s .. ~4.5h: streams live on a different timescale than requests,
			// so the request buckets (1ms..10s) would put every stream in +Inf.
			Buckets:     prometheus.ExponentialBuckets(1, 2, 15),
			ConstLabels: constLabels,
		}, []string{"method", "route"}),
		streamsOpen: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "optictrace_streams_open", Help: "Streaming responses currently open.",
			ConstLabels: constLabels,
		}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "optictrace_inflight_requests", Help: "Requests currently being proxied.",
			ConstLabels: constLabels,
		}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "optictrace_store_dropped_total", Help: "Telemetry records dropped because the store queue was full.",
			ConstLabels: constLabels,
		}),
		ingested: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "optictrace_sdk_ingested_total", Help: "Records received from framework SDKs via /api/ingest.",
			ConstLabels: constLabels,
		}),
		appLogsStored: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "optictrace_app_logs_stored_total", Help: "Application log lines stored against a span.",
			ConstLabels: constLabels,
		}),
		// Every discarded line is counted with its reason. A drop you cannot
		// see is indistinguishable from an application that stopped logging,
		// which is the wrong thing to be guessing about at 3am.
		appLogsDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "optictrace_app_logs_dropped_total",
			Help:        "Application log lines discarded, by reason (orphan, level, span_cap, disabled, empty).",
			ConstLabels: constLabels,
		}, []string{"reason"}),
		exported: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "optictrace_exported_total", Help: "Records delivered by output exporters.",
			ConstLabels: constLabels,
		}, []string{"exporter"}),
		exportFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "optictrace_export_failed_total", Help: "Records whose export attempt failed.",
			ConstLabels: constLabels,
		}, []string{"exporter"}),
		exportDrops: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "optictrace_export_dropped_total", Help: "Records dropped because an exporter queue was full.",
			ConstLabels: constLabels,
		}, []string{"exporter"}),
		labelCapped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name:        "optictrace_label_capped_total",
			Help:        "Observations whose custom label value was replaced by __over_limit__ because the cardinality cap was reached.",
			ConstLabels: constLabels,
		}, []string{"label"}),
		labelDistinct: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name:        "optictrace_label_distinct_values",
			Help:        "Distinct values observed per custom label, up to the cardinality cap.",
			ConstLabels: constLabels,
		}, []string{"label"}),
	}
	c.installDimensions(newDimensions(customKeys, buckets, constLabels))
	reg.MustRegister(
		c.reqSize, c.respSize,
		c.streams, c.streamDuration, c.streamsOpen,
		c.inflight, c.dropped, c.ingested,
		c.appLogsStored, c.appLogsDropped,
		c.exported, c.exportFailed, c.exportDrops,
		c.labelCapped, c.labelDistinct,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return c
}

// Observe records one completed exchange. Safe for concurrent use.
func (c *Collector) Observe(o Observation) {
	status := strconv.Itoa(o.Status)
	class := statusClass(o.Status)

	// One load: a concurrent reload must not be able to fill the counter's
	// values from one schema and the histogram's from another.
	d := c.dims.Load()

	svc := o.Service
	if svc == "" {
		svc = c.service
	}
	counterVals := make([]string, 0, 5+len(d.keys))
	counterVals = append(counterVals, svc, o.Method, o.Route, status, class)
	durationVals := make([]string, 0, 3+len(d.keys))
	durationVals = append(durationVals, svc, o.Method, o.Route)
	for _, k := range d.keys {
		v := c.guard(k, o.Labels[k])
		counterVals = append(counterVals, v)
		durationVals = append(durationVals, v)
	}

	d.requests.WithLabelValues(counterVals...).Inc()
	if o.Stream {
		// Deliberately NOT on c.duration. A stream's lifetime is not request
		// latency, and mixing them lets one long connection swamp a route's
		// percentiles for the whole window.
		c.streams.WithLabelValues(o.Method, o.Route).Inc()
		c.streamDuration.WithLabelValues(o.Method, o.Route).Observe(o.Duration.Seconds())
	} else {
		d.duration.WithLabelValues(durationVals...).Observe(o.Duration.Seconds())
	}
	if o.ReqBytes > 0 {
		c.reqSize.WithLabelValues(o.Method, o.Route).Observe(float64(o.ReqBytes))
	}
	if o.RespBytes > 0 {
		c.respSize.WithLabelValues(o.Method, o.Route).Observe(float64(o.RespBytes))
	}
}

// LabelKeys returns the custom label schema currently in effect.
func (c *Collector) LabelKeys() []string { return c.dims.Load().keys }

// SetLabelKeys re-points the config-dependent metrics at a new label schema,
// returning true if anything changed.
//
// A Prometheus metric's label set is immutable — and a Registry refuses to
// re-register a name under a different schema even after Unregister — so this
// swaps in a freshly built registry holding freshly built vectors. Request
// counts and latency buckets therefore restart from zero, and the old series
// go stale.
//
// That is the correct trade. Before this existed, adding a `labels:` key and
// reloading made the label appear in the dashboard while never appearing in
// /metrics: a Grafana panel built on it returned no data, with no error
// anywhere to explain why. Only the two config-dependent vectors are affected;
// every other counter lives in the stable registry and survives.
func (c *Collector) SetLabelKeys(keys []string) bool {
	c.rebuildMu.Lock()
	defer c.rebuildMu.Unlock()

	old := c.dims.Load()
	if slices.Equal(old.keys, keys) {
		return false
	}
	fresh := newDimensions(keys, c.buckets, c.constLabels)

	// Unregister before registering: same metric names, different label sets,
	// which Prometheus rejects as a duplicate if both are present.
	c.installDimensions(fresh)

	// The cardinality guard tracked values for the previous schema; keys that
	// went away should not keep occupying their budget.
	c.cardMu.Lock()
	c.seen = make(map[string]map[string]struct{}, len(keys))
	c.cardMu.Unlock()
	return true
}

// installDimensions registers a dimension set into a private registry and
// publishes both atomically, so a scrape or an Observe never sees the vectors
// and the registry disagree.
func (c *Collector) installDimensions(d *dimensions) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(d.requests, d.duration)
	c.dynamic.Store(reg)
	c.dims.Store(d)
}

// guard enforces the per-label cardinality cap, returning either the original
// value or OverLimit. Empty values are always allowed through: they mean
// "this request had no such header", which is one series, not unbounded.
func (c *Collector) guard(key, value string) string {
	if c.maxLabelValues <= 0 || value == "" {
		return value
	}
	c.cardMu.Lock()
	defer c.cardMu.Unlock()

	vals := c.seen[key]
	if vals == nil {
		vals = make(map[string]struct{}, 8)
		c.seen[key] = vals
	}
	if _, known := vals[value]; known {
		return value
	}
	if len(vals) >= c.maxLabelValues {
		// Cap reached: fold every new value into one bucket so the series
		// count stops growing, and make that visible in metrics.
		c.labelCapped.WithLabelValues(key).Inc()
		return OverLimit
	}
	vals[value] = struct{}{}
	c.labelDistinct.WithLabelValues(key).Set(float64(len(vals)))
	return value
}

// InflightInc/Dec bracket a proxied request.
func (c *Collector) InflightInc() { c.inflight.Inc() }
func (c *Collector) InflightDec() { c.inflight.Dec() }

// StreamOpened/Closed bracket a streaming response, so a live SSE connection
// is visible while it is open rather than only once it ends.
func (c *Collector) StreamOpened() { c.streamsOpen.Inc() }
func (c *Collector) StreamClosed() { c.streamsOpen.Dec() }

// StoreDropped counts a telemetry record lost to backpressure.
func (c *Collector) StoreDropped() { c.dropped.Inc() }

// SDKIngested counts a record received from a framework SDK.
func (c *Collector) SDKIngested() { c.ingested.Inc() }

// AppLogStored counts lines persisted against a span.
func (c *Collector) AppLogStored(n int) {
	if n > 0 {
		c.appLogsStored.Add(float64(n))
	}
}

// AppLogDropped counts a discarded line under the reason it was discarded.
func (c *Collector) AppLogDropped(reason string, n int) {
	if n > 0 {
		c.appLogsDropped.WithLabelValues(reason).Add(float64(n))
	}
}

// Exporter accounting — satisfies export.Metrics.
func (c *Collector) ExportDelivered(exporter string, n int) {
	c.exported.WithLabelValues(exporter).Add(float64(n))
}
func (c *Collector) ExportFailed(exporter string, n int) {
	c.exportFailed.WithLabelValues(exporter).Add(float64(n))
}
func (c *Collector) ExportDropped(exporter string) {
	c.exportDrops.WithLabelValues(exporter).Inc()
}

// Handler serves the /metrics endpoint in Prometheus exposition format.
func (c *Collector) Handler() http.Handler {
	// Resolved per scrape rather than captured once: the dynamic registry is
	// replaced on reload, and a handler built at startup would keep serving
	// the old label schema forever.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g := prometheus.Gatherers{c.stable, c.dynamic.Load()}
		promhttp.HandlerFor(g, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	})
}

func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}
