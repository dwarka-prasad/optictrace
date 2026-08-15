// Package metrics exposes OpticTrace telemetry to Prometheus.
//
// Design notes:
//   - The collector owns a private Registry (not the global default), so
//     embedding OpticTrace in an app that already uses client_golang can
//     never cause duplicate-registration panics.
//   - Custom labels from optic.yaml become real Prometheus dimensions. The
//     label schema is fixed at construction from engine.LabelKeys(); requests
//     without a value export "" (Prometheus requires stable schemas).
//   - The `route` label carries the matched rule's glob (or a normalized
//     path), never the raw path — cardinality stays bounded by design.
//   - P50/P95/P99 are derived by Prometheus from the latency histogram, e.g.:
//     histogram_quantile(0.99, sum by (le, route) (rate(optictrace_request_duration_seconds_bucket[5m])))
package metrics

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Observation is one completed HTTP exchange, as seen by the collector.
type Observation struct {
	Method    string
	Route     string // low-cardinality route pattern, not the raw path
	Status    int
	Duration  time.Duration
	ReqBytes  int64
	RespBytes int64
	Labels    map[string]string // values for the custom label schema
}

// OverLimit replaces a custom label's value once that label has already
// contributed maxLabelValues distinct values. Every subsequent unseen value
// collapses into this single series, so cardinality stops growing.
const OverLimit = "__over_limit__"

// Collector aggregates per-request metrics and serves them via Handler().
type Collector struct {
	registry  *prometheus.Registry
	labelKeys []string

	// Cardinality guard. Label values arrive from arbitrary request headers,
	// so an unbounded value space is a real availability risk for the
	// Prometheus scraping this. seen tracks distinct values per label key.
	maxLabelValues int
	cardMu         sync.Mutex
	seen           map[string]map[string]struct{}

	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	reqSize  *prometheus.HistogramVec
	respSize *prometheus.HistogramVec
	inflight prometheus.Gauge
	dropped  prometheus.Counter
	ingested prometheus.Counter

	exported     *prometheus.CounterVec
	exportFailed *prometheus.CounterVec
	exportDrops  *prometheus.CounterVec

	labelCapped   *prometheus.CounterVec
	labelDistinct *prometheus.GaugeVec
}

// New builds a Collector for one service. customKeys is the fixed set of
// optic.yaml label names (from engine.LabelKeys()); maxLabelValues caps the
// distinct values each may contribute (0 disables the guard).
func New(service string, buckets []float64, customKeys []string, maxLabelValues int) *Collector {
	reg := prometheus.NewRegistry()
	constLabels := prometheus.Labels{"service": service}

	base := []string{"method", "route", "status", "status_class"}
	withCustom := append(append([]string{}, base...), customKeys...)
	durationLabels := append([]string{"method", "route"}, customKeys...)

	sizeBuckets := prometheus.ExponentialBuckets(64, 4, 10) // 64B .. ~16MB

	c := &Collector{
		registry:       reg,
		labelKeys:      customKeys,
		maxLabelValues: maxLabelValues,
		seen:           make(map[string]map[string]struct{}, len(customKeys)),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "optictrace_requests_total", Help: "Total HTTP requests observed.",
			ConstLabels: constLabels,
		}, withCustom),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "optictrace_request_duration_seconds", Help: "Request latency.",
			Buckets: buckets, ConstLabels: constLabels,
		}, durationLabels),
		reqSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "optictrace_request_size_bytes", Help: "Request body size.",
			Buckets: sizeBuckets, ConstLabels: constLabels,
		}, []string{"method", "route"}),
		respSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "optictrace_response_size_bytes", Help: "Response body size.",
			Buckets: sizeBuckets, ConstLabels: constLabels,
		}, []string{"method", "route"}),
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
	reg.MustRegister(
		c.requests, c.duration, c.reqSize, c.respSize,
		c.inflight, c.dropped, c.ingested,
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

	counterVals := make([]string, 0, 4+len(c.labelKeys))
	counterVals = append(counterVals, o.Method, o.Route, status, class)
	durationVals := make([]string, 0, 2+len(c.labelKeys))
	durationVals = append(durationVals, o.Method, o.Route)
	for _, k := range c.labelKeys {
		v := c.guard(k, o.Labels[k])
		counterVals = append(counterVals, v)
		durationVals = append(durationVals, v)
	}

	c.requests.WithLabelValues(counterVals...).Inc()
	c.duration.WithLabelValues(durationVals...).Observe(o.Duration.Seconds())
	if o.ReqBytes > 0 {
		c.reqSize.WithLabelValues(o.Method, o.Route).Observe(float64(o.ReqBytes))
	}
	if o.RespBytes > 0 {
		c.respSize.WithLabelValues(o.Method, o.Route).Observe(float64(o.RespBytes))
	}
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

// StoreDropped counts a telemetry record lost to backpressure.
func (c *Collector) StoreDropped() { c.dropped.Inc() }

// SDKIngested counts a record received from a framework SDK.
func (c *Collector) SDKIngested() { c.ingested.Inc() }

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
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{})
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
