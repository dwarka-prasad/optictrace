package export

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// otlpExporter emits governed records as OpenTelemetry spans over OTLP/HTTP.
//
// Two deliberate choices:
//
//  1. It is an *exporter type*, not a new subsystem. OTLP then inherits the
//     batching, bounded queue, isolation and drop accounting every other
//     exporter already has, instead of duplicating them.
//  2. It speaks OTLP/HTTP with JSON encoding, which the specification defines,
//     rather than pulling in the OpenTelemetry SDK and its protobuf stack. A
//     telemetry sidecar earns its keep by staying small; adding tens of
//     dependencies to emit a well-specified JSON envelope is a poor trade.
//
// Spans carry the governed record only: attributes come from metadata,
// labels and meters. Bodies are never attached — span attributes end up in
// tracing backends with different retention and access rules than the
// payload store, and quietly widening where payloads land would undo the
// governance the rest of the system enforces.
type otlpExporter struct {
	name     string
	endpoint string
	headers  map[string]string
	service  string
	client   *http.Client
}

func newOTLPExporter(c *config.ExporterCfg, serviceName string) *otlpExporter {
	endpoint := strings.TrimRight(c.URL, "/")
	// Accept a collector base URL and append the signal path, matching the
	// convention every OTLP client uses.
	if !strings.HasSuffix(endpoint, "/v1/traces") {
		endpoint += "/v1/traces"
	}
	return &otlpExporter{
		name:     c.Name,
		endpoint: endpoint,
		headers:  c.Headers,
		service:  serviceName,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

func (e *otlpExporter) Name() string { return e.name }
func (e *otlpExporter) Type() string { return "otlp" }

func (e *otlpExporter) Export(ctx context.Context, batch []*store.Record) error {
	spans := make([]map[string]any, 0, len(batch))
	for _, rec := range batch {
		spans = append(spans, e.span(rec))
	}
	payload := map[string]any{
		"resourceSpans": []map[string]any{{
			"resource": map[string]any{
				"attributes": []map[string]any{
					attr("service.name", e.service),
					attr("telemetry.sdk.name", "optictrace"),
					attr("telemetry.sdk.language", "go"),
				},
			},
			"scopeSpans": []map[string]any{{
				"scope": map[string]any{"name": "optictrace"},
				"spans": spans,
			}},
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp collector returned %s", resp.Status)
	}
	return nil
}

func (e *otlpExporter) span(rec *store.Record) map[string]any {
	start := rec.Time.UnixNano()
	end := start + int64(rec.DurationMS*float64(time.Millisecond))

	attrs := []map[string]any{
		attr("http.request.method", rec.Method),
		attr("url.path", rec.Path),
		attr("http.route", rec.Route),
		attrInt("http.response.status_code", int64(rec.Status)),
		attrInt("http.request.body.size", rec.ReqBytes),
		attrInt("http.response.body.size", rec.RespBytes),
		attr("optictrace.source", rec.Source),
	}
	if rec.Query != "" {
		// Already sanitized by the engine; redacted params carry the
		// placeholder rather than their value.
		attrs = append(attrs, attr("url.query", rec.Query))
	}
	if len(rec.MatchedRules) > 0 {
		attrs = append(attrs, attr("optictrace.matched_rules", strings.Join(rec.MatchedRules, ",")))
	}
	for k, v := range rec.Labels {
		attrs = append(attrs, attr("optictrace.label."+k, v))
	}
	for k, v := range rec.Meters {
		attrs = append(attrs, attrFloat("optictrace.meter."+k, v))
	}

	// Join the caller's trace when it sent one, so this span lands inside the
	// application's own trace instead of as an orphan root. Without this every
	// exported span is a separate single-span trace, and you cannot click from
	// a slow OpticTrace span into the request it describes — which is most of
	// the reason to export to OTLP at all.
	traceID, parentID, sampled := traceContext(rec.RequestHeaders)
	span := map[string]any{
		"traceId":           traceID,
		"spanId":            randomHex(8),
		"name":              rec.Method + " " + rec.Route,
		"kind":              2, // SPAN_KIND_SERVER
		"startTimeUnixNano": fmt.Sprint(start),
		"endTimeUnixNano":   fmt.Sprint(end),
		"attributes":        attrs,
	}
	if parentID != "" {
		span["parentSpanId"] = parentID
	}
	if sampled {
		span["flags"] = 1 // W3C sampled bit, propagated from the caller
	}
	if ts := rec.RequestHeaders["tracestate"]; ts != "" {
		span["traceState"] = ts
	}
	// 5xx marks the span as errored so it surfaces in tracing UIs.
	if rec.Status >= 500 {
		span["status"] = map[string]any{"code": 2, "message": http.StatusText(rec.Status)}
	} else {
		span["status"] = map[string]any{"code": 1}
	}
	return span
}

func attr(k, v string) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"stringValue": v}}
}

func attrInt(k string, v int64) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"intValue": fmt.Sprint(v)}}
}

func attrFloat(k string, v float64) map[string]any {
	return map[string]any{"key": k, "value": map[string]any{"doubleValue": v}}
}

// traceContext extracts W3C Trace Context from the captured request headers,
// returning the trace ID to use, the parent span ID (empty if there is none),
// and whether the caller marked the trace sampled.
//
// A malformed or absent header must never cost us the span, so anything
// unparseable falls back to a fresh root trace — the previous behaviour for
// every record.
//
//	traceparent: 00-<32 hex trace id>-<16 hex span id>-<2 hex flags>
func traceContext(headers map[string]string) (traceID, parentID string, sampled bool) {
	raw := headerLookup(headers, "traceparent")
	parts := strings.Split(raw, "-")
	if len(parts) != 4 {
		return randomHex(16), "", false
	}
	version, tid, pid, flags := parts[0], parts[1], parts[2], parts[3]
	// Version ff is forbidden by the spec; anything else may carry extra
	// fields we ignore, but 00 is the only layout defined today.
	if version != "00" ||
		!isHex(tid, 32) || !isHex(pid, 16) || !isHex(flags, 2) ||
		tid == strings.Repeat("0", 32) || pid == strings.Repeat("0", 16) {
		return randomHex(16), "", false
	}
	f, err := strconv.ParseUint(flags, 16, 8)
	return tid, pid, err == nil && f&0x01 != 0
}

// headerLookup finds a header case-insensitively. Captured headers preserve
// whatever casing the client sent, and HTTP header names are case-insensitive.
func headerLookup(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// isHex reports whether s is exactly n lowercase-or-uppercase hex digits.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// randomHex produces trace/span IDs for records that arrived without a usable
// inbound trace context.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not recoverable here, and an all-zero ID is
		// invalid OTLP — fall back to a time-derived value so the batch is
		// still accepted rather than silently dropped.
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i % 8 * 8))
		}
	}
	return hex.EncodeToString(b)
}

func (e *otlpExporter) Close() error { return nil }
