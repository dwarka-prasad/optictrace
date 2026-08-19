// Package admin serves OpticTrace's control-plane HTTP surface, deliberately
// on a separate listener from proxied traffic so it can be firewalled
// independently:
//
//	GET  /metrics              Prometheus exposition
//	GET  /healthz              liveness
//	GET  /api/logs             filtered request log query
//	GET  /api/logs/{id}        single captured exchange
//	GET  /api/stats            aggregates for the dashboard (window/bucket)
//	GET  /api/config           current optic.yaml (raw + summary)
//	POST /api/config/validate  lint a candidate optic.yaml (dashboard editor)
//	POST /api/reload           re-read optic.yaml from disk, hot-swap engine
//	POST /api/ingest           telemetry records from framework SDKs
//	POST /api/applogs/ingest   application log lines, correlated by span id
//	GET  /api/applogs          log lines a request wrote (?trace= / ?span=)
//	GET  /                     embedded developer dashboard
package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/applog"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/export"
	"github.com/dwarka-prasad/optictrace/internal/metrics"
	"github.com/dwarka-prasad/optictrace/internal/scan"
	"github.com/dwarka-prasad/optictrace/internal/spec"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Server wires the admin endpoints to their backing components. Any field
// may be nil; the corresponding endpoints then return 404/501.
type Server struct {
	Logger    *slog.Logger
	Collector *metrics.Collector
	Reader    store.LogStore // queries (may be nil when driver=none)
	// AppLogs governs application log lines; nil or disabled means the ingest
	// endpoint refuses with a clear reason rather than silently accepting and
	// discarding. AppLogStore is the optional store side — a driver without
	// it is a valid driver, so this may be nil while Reader is not.
	AppLogs     *applog.Governor
	AppLogStore store.AppLogStore
	Writer      *store.AsyncWriter // ingest path
	Dispatcher  *export.Dispatcher // output plugins (may be nil)
	ConfigPath  string
	Reload      func() error // hot-reload hook installed by main
	UIDir       string       // static dashboard directory (optional)
	Version     string
	// AuthToken protects every endpoint when non-empty. HealthOpen keeps
	// /healthz reachable for orchestrator probes.
	AuthToken  string
	HealthOpen bool
	// CORSOrigins lists browser origins allowed to call the API
	// cross-origin. Empty means no CORS headers are sent at all.
	CORSOrigins []string
	// AnalysisMaxRows bounds how many records /api/scan and /api/spec read.
	// 0 uses store.DefaultAnalysisMaxRows.
	AnalysisMaxRows int
	// Detectors are org-specific scan patterns from optic.yaml, added to the
	// built-in set.
	Detectors []scan.Detector

	// access holds the resolved authn/authz/audit chain, built by Handler.
	access *accessControl

	startedAt time.Time
}

func (s *Server) Handler() http.Handler {
	s.startedAt = time.Now()
	s.access = &accessControl{
		authns:    ext.Authenticators(),
		authzs:    ext.Authorizers(),
		auds:      ext.Auditors(),
		tokenAuth: s.AuthToken != "",
	}
	mux := http.NewServeMux()

	// Every route declares what it exposes. An extension writes policy against
	// these capabilities rather than against URLs, so it never has to track
	// OpticTrace's routing — and a route cannot be added without classifying
	// it, because there is no unclassified path through this function.
	seen := map[string]bool{}
	route := func(pattern string, capability ext.Capability, h http.Handler) {
		seen[pattern] = true
		mux.Handle(pattern, s.guard(capability, h))
	}
	routeFunc := func(pattern string, capability ext.Capability, h http.HandlerFunc) {
		route(pattern, capability, h)
	}

	if s.Collector != nil {
		route("GET /metrics", ext.CapMetrics, s.Collector.Handler())
	}
	// /healthz is public only when configured to be; HealthOpen=false makes
	// orchestrator probes authenticate like anything else.
	healthCap := ext.CapReadStats
	if s.HealthOpen {
		healthCap = ext.CapPublic
	}
	routeFunc("GET /healthz", healthCap, s.health)

	// Aggregates only — counts, latencies, totals. No captured payloads.
	routeFunc("GET /api/stats", ext.CapReadStats, s.stats)
	routeFunc("GET /api/routes", ext.CapReadStats, s.routes)
	routeFunc("GET /api/rules/stats", ext.CapReadStats, s.ruleStats)
	routeFunc("GET /api/services", ext.CapReadStats, s.services)
	routeFunc("GET /api/system", ext.CapReadStats, s.system)
	routeFunc("GET /api/usage", ext.CapReadStats, s.usage)

	// These return captured request/response bodies to the caller — the
	// capability that lets a person read customer data.
	routeFunc("GET /api/logs", ext.CapReadPayload, s.listLogs)
	routeFunc("GET /api/logs/{id}", ext.CapReadPayload, s.getLog)

	// Bulk egress of the whole store, separated on purpose: "can inspect one
	// request while debugging" and "can download everything" are different
	// grants, and conflating them is how audits go badly.
	routeFunc("GET /api/export", ext.CapExport, s.export)

	// Read payloads server-side, return derived output only.
	routeFunc("GET /api/scan", ext.CapAnalyse, s.scan)
	routeFunc("GET /api/spec", ext.CapAnalyse, s.inferSpec)

	routeFunc("GET /api/config", ext.CapReadConfig, s.getConfig)
	routeFunc("POST /api/config/validate", ext.CapReadConfig, s.validateConfig)
	routeFunc("POST /api/reload", ext.CapAdmin, s.reload)
	routeFunc("POST /api/ingest", ext.CapIngest, s.ingest)
	// Application log lines. Ingest is a machine-to-machine write, so it
	// shares CapIngest with record ingest; reading them returns application
	// payload text, which is CapReadPayload — the same grant as reading a
	// captured body, because that is exactly what a log line can contain.
	routeFunc("POST /api/applogs/ingest", ext.CapIngest, s.ingestAppLogs)
	routeFunc("GET /api/applogs", ext.CapReadPayload, s.queryAppLogs)
	// Counts only — no message text — so it sits behind the stats grant
	// rather than the payload one.
	routeFunc("GET /api/applogs/stats", ext.CapReadStats, s.appLogStats)
	routeFunc("/", ext.CapUI, s.ui)

	// Routes contributed by extensions — a login callback, a role API, an
	// audit viewer. Registered last so a collision with a core route panics
	// here rather than silently shadowing one.
	for _, rt := range ext.AdminRoutes() {
		if seen[rt.Pattern] {
			panic("admin: extension route " + rt.Pattern + " collides with a core route")
		}
		route(rt.Pattern, rt.Capability, rt.Handler)
	}

	return withCORS(s.CORSOrigins, mux)
}

// constantTimeEqual compares credentials without leaking their length
// difference through timing. Used by the built-in bearer check in access.go.
func constantTimeEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// withCORS allows listed browser origins — normally just a dashboard dev
// server — to call the API cross-origin.
//
// This used to send `Access-Control-Allow-Origin: *` unconditionally, outside
// the auth wrapper. Combined with auth being off by default, that let any page
// a developer visited read the entire capture store with one fetch(). Now
// nothing is sent unless an origin is explicitly allowed, so the browser's
// same-origin policy protects the API even when auth is off. The dashboard
// itself is served same-origin and needs no CORS at all.
func withCORS(allowed []string, next http.Handler) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	wildcard := false
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		if o == "*" {
			wildcard = true
		}
		set[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Vary regardless of the outcome: the response body differs by origin,
		// and a cache must not serve one origin's response to another.
		w.Header().Add("Vary", "Origin")
		switch {
		case origin == "":
			// Not a cross-origin request; no headers needed.
		case wildcard:
			w.Header().Set("Access-Control-Allow-Origin", "*")
		case set[origin]:
			// Echo the specific origin rather than the wildcard, so this stays
			// correct if credentials are ever added.
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == http.MethodOptions {
			// A preflight from a disallowed origin gets no CORS headers, which
			// is what makes the browser block the real request.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auditableQuery renders a request's query string for the audit trail with
// credentials removed.
//
// The admin API accepts ?token= so a browser can load the dashboard, which
// means the raw query string can contain the bearer token. An audit trail is
// written to be READ — by auditors, by a SIEM, by whoever investigates an
// incident — so putting a live credential in it hands that credential to
// everyone with access to the log, which is a wider set than those who had the
// token to begin with.
func auditableQuery(r *http.Request) string {
	q := r.URL.Query()
	if len(q) == 0 {
		return ""
	}
	redacted := false
	for key := range q {
		switch strings.ToLower(key) {
		case "token", "access_token", "api_key", "apikey", "password", "secret":
			q.Set(key, "[REDACTED]")
			redacted = true
		}
	}
	if !redacted {
		return r.URL.RawQuery
	}
	return q.Encode()
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled (telemetry.store.driver: none)")
		return
	}
	f := filterFromQuery(r)
	recs, total, err := s.Reader.Query(r.Context(), f)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if recs == nil {
		recs = []store.Record{}
	}
	// The audit trail needs what was reached, not just that /api/logs was
	// called: "listed logs" answers no question an auditor would ask.
	ids := make([]int64, 0, len(recs))
	for i := range recs {
		ids = append(ids, recs[i].ID)
	}
	ext.NoteAccess(r.Context(), ext.Accessed{
		Count: len(recs), RecordIDs: ids, Filter: auditableQuery(r),
	})
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "records": recs})
}

func (s *Server) getLog(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid id")
		return
	}
	rec, err := s.Reader.Get(r.Context(), id)
	if err != nil {
		httpError(w, http.StatusNotFound, "record not found")
		return
	}
	ext.NoteAccess(r.Context(), ext.Accessed{
		Count: 1, RecordIDs: []int64{id}, Consumer: rec.Labels["tenant"],
	})
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	window := parseDurationDefault(r.URL.Query().Get("window"), time.Hour)
	bucket := parseDurationDefault(r.URL.Query().Get("bucket"), time.Minute)
	st, err := s.Reader.Stats(r.Context(), time.Now().Add(-window), bucket)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if st.Series == nil {
		st.Series = []store.TimeBucket{}
	}
	if st.TopRoutes == nil {
		st.TopRoutes = []store.RouteStat{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) routes(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	window := parseDurationDefault(r.URL.Query().Get("window"), time.Hour)
	routes, err := s.Reader.RouteStats(r.Context(), time.Now().Add(-window))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if routes == nil {
		routes = []store.RouteDetail{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": routes})
}

// ruleStats joins the loaded rule definitions with how often each fired —
// the Governance dashboard's data source.
func (s *Server) ruleStats(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		httpError(w, http.StatusUnprocessableEntity, "config invalid: "+err.Error())
		return
	}
	names := make([]string, 0, len(cfg.Rules))
	for i, rule := range cfg.Rules {
		if rule.Name == "" {
			cfg.Rules[i].Name = "#" + strconv.Itoa(i)
		}
		names = append(names, cfg.Rules[i].Name)
	}

	counts := map[string]int64{}
	var windowTotal int64
	if s.Reader != nil {
		window := parseDurationDefault(r.URL.Query().Get("window"), time.Hour)
		since := time.Now().Add(-window)
		matches, err := s.Reader.RuleMatchCounts(r.Context(), since, names)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, m := range matches {
			counts[m.Rule] = m.Count
		}
		if st, err := s.Reader.Stats(r.Context(), since, time.Hour); err == nil {
			windowTotal = st.Total
		}
	}

	type ruleView struct {
		Name       string   `json:"name"`
		Path       string   `json:"path"`
		Methods    []string `json:"methods,omitempty"`
		Restrict   []string `json:"restrict,omitempty"`
		RedactHdrs int      `json:"redact_headers"`
		RedactJSON int      `json:"redact_json_fields"`
		Labels     int      `json:"labels"`
		Sample     *float64 `json:"sample,omitempty"`
		Matches    int64    `json:"matches"`
	}
	rules := make([]ruleView, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		rv := ruleView{
			Name: rule.Name, Path: rule.Match.Path, Methods: rule.Match.Methods,
			Sample: rule.Sample, Labels: len(rule.Labels), Matches: counts[rule.Name],
		}
		for _, f := range rule.Restrict {
			rv.Restrict = append(rv.Restrict, string(f))
		}
		if rule.Redact != nil {
			rv.RedactHdrs = len(rule.Redact.Headers)
			rv.RedactJSON = len(rule.Redact.JSONFields)
		}
		rules = append(rules, rv)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules, "window_total": windowTotal})
}

func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"version":        s.Version,
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
		"config_path":    filepath.Base(s.ConfigPath),
		"store":          map[string]any{"enabled": s.Reader != nil},
		"exporters":      []export.Stat{},
	}
	if raw, err := os.ReadFile(s.ConfigPath); err == nil {
		if cfg, err := config.Parse(raw); err == nil {
			resp["service"] = cfg.Service.Name
			resp["upstream"] = cfg.Service.Upstream
			resp["rules"] = len(cfg.Rules)
		}
	}
	if s.Reader != nil {
		if n, err := s.Reader.Count(r.Context()); err == nil {
			resp["store"] = map[string]any{"enabled": true, "records": n}
		}
	}
	if s.Dispatcher != nil {
		resp["exporters"] = s.Dispatcher.Stats()
	}
	writeJSON(w, http.StatusOK, resp)
}

// usage is the FinOps view: per-consumer traffic aggregates, priced by the
// telemetry.billing model when one is configured.
//
//	GET /api/usage?window=24h[&label=tenant][&format=csv]
func (s *Server) usage(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	var billing *config.Billing
	if raw, err := os.ReadFile(s.ConfigPath); err == nil {
		if cfg, err := config.Parse(raw); err == nil {
			billing = cfg.Telemetry.Billing
		}
	}
	label := r.URL.Query().Get("label")
	if label == "" {
		label = "tenant"
		if billing != nil {
			label = billing.ConsumerLabel
		}
	}
	window := parseDurationDefault(r.URL.Query().Get("window"), 24*time.Hour)
	rows, err := s.Reader.UsageByLabel(r.Context(), time.Now().Add(-window), label)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type consumerUsage struct {
		store.Usage
		Cost map[string]float64 `json:"cost,omitempty"` // component -> amount; "total" included
	}
	currency := "USD"
	out := make([]consumerUsage, 0, len(rows))
	for _, u := range rows {
		cu := consumerUsage{Usage: u}
		if billing != nil {
			currency = billing.Currency
			cost := map[string]float64{}
			total := 0.0
			if p := billing.Prices.PerRequest; p > 0 {
				cost["requests"] = float64(u.Requests) * p
				total += cost["requests"]
			}
			if p := billing.Prices.PerGB; p > 0 {
				cost["data"] = float64(u.ReqBytes+u.RespBytes) / (1 << 30) * p
				total += cost["data"]
			}
			for name, unitPrice := range billing.Prices.PerMeterUnit {
				if v, ok := u.Meters[name]; ok && unitPrice > 0 {
					cost[name] = v * unitPrice
					total += cost[name]
				}
			}
			cost["total"] = total
			cu.Cost = cost
		}
		out = append(out, cu)
	}

	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition",
			`attachment; filename="optictrace-usage-`+time.Now().Format("20060102")+`.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"consumer", "requests", "errors", "req_bytes", "resp_bytes",
			"duration_ms_total", "meters", "cost_total", "currency"})
		for _, u := range out {
			_ = cw.Write([]string{
				u.Consumer, strconv.FormatInt(u.Requests, 10), strconv.FormatInt(u.Errors, 10),
				strconv.FormatInt(u.ReqBytes, 10), strconv.FormatInt(u.RespBytes, 10),
				strconv.FormatFloat(u.DurationMS, 'f', 2, 64), jsonCell(u.Meters),
				strconv.FormatFloat(u.Cost["total"], 'f', 6, 64), currency,
			})
		}
		cw.Flush()
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"label": label, "currency": currency, "billing": billing != nil, "consumers": out,
	})
}

// services is the fleet view: one agent proxies one service, but many SDKs
// can report into the same agent, so the store may hold several.
func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	window := parseDurationDefault(r.URL.Query().Get("window"), time.Hour)
	stats, err := s.Reader.ServiceStats(r.Context(), time.Now().Add(-window))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if stats == nil {
		stats = []store.ServiceStat{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": stats})
}

// scan looks for sensitive values that slipped past the rules — the field
// nobody remembered to redact. Findings carry masked samples only.
//
//	GET /api/scan?window=24h
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	window := parseDurationDefault(r.URL.Query().Get("window"), 24*time.Hour)
	since := time.Now().Add(-window)
	// Streamed, not materialised: these are full records including bodies,
	// and this endpoint is reachable without a token in the default posture.
	sc := scan.NewScannerWith(since, s.Detectors)
	if err := s.Reader.RecentFunc(r.Context(), since, s.AnalysisMaxRows, func(rec *store.Record) error {
		sc.Add(rec)
		return nil
	}); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Application logs are the other half of the surface, and the riskier one:
	// a payload is structured and can be masked by path, a log line is free
	// text. Scanning records but not lines would look where the data is
	// easiest to protect rather than where it escapes.
	if s.AppLogStore != nil {
		offset := 0
		for {
			lines, total, err := s.AppLogStore.QueryAppLogs(r.Context(), store.AppLogFilter{
				Since: since, Limit: 500, Offset: offset,
			})
			if err != nil {
				httpError(w, http.StatusInternalServerError, err.Error())
				return
			}
			for i := range lines {
				sc.AddAppLog(&lines[i])
			}
			offset += len(lines)
			if len(lines) == 0 || int64(offset) >= total || offset >= s.analysisRows() {
				break
			}
		}
	}

	report := sc.Report()
	ext.NoteAccess(r.Context(), ext.Accessed{Count: report.Scanned, Filter: auditableQuery(r)})
	crit, high, med := report.Counts()
	if report.Findings == nil {
		report.Findings = []scan.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records_scanned": report.Scanned,
		// Reported so "0 findings" can be read honestly: none over zero log
		// lines means something very different from none over forty thousand.
		"log_lines_scanned": report.LinesScanned,
		"since":             report.Since,
		"critical":          crit,
		"high":              high,
		"medium":            med,
		"findings":          report.Findings,
	})
}

// inferSpec generates an OpenAPI document from captured traffic on demand:
//
//	GET /api/spec?window=24h&format=yaml|json
func (s *Server) inferSpec(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	window := parseDurationDefault(r.URL.Query().Get("window"), 24*time.Hour)
	service := ""
	if raw, err := os.ReadFile(s.ConfigPath); err == nil {
		if cfg, err := config.Parse(raw); err == nil {
			service = cfg.Service.Name
		}
	}
	// Streamed for the same reason as /api/scan.
	inf := spec.NewInferrer(service)
	seen := 0
	if err := s.Reader.RecentFunc(r.Context(), time.Now().Add(-window), s.AnalysisMaxRows,
		func(rec *store.Record) error {
			seen++
			inf.Add(rec)
			return nil
		}); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if seen == 0 {
		httpError(w, http.StatusNotFound, "no traffic captured in this window")
		return
	}
	ext.NoteAccess(r.Context(), ext.Accessed{Count: seen, Filter: auditableQuery(r)})
	doc := inf.Spec()
	if r.URL.Query().Get("format") == "json" {
		writeJSON(w, http.StatusOK, doc)
		return
	}
	raw, err := doc.YAML()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="openapi-inferred.yaml"`)
	_, _ = w.Write(raw)
}

// export streams matching records as a downloadable JSONL or CSV file —
// the dashboard's "Export" button, also curl-friendly:
//
//	curl -OJ 'localhost:9095/api/export?format=csv&since=1h&path=/api/v1/payments'
func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	if s.Reader == nil {
		httpError(w, http.StatusNotImplemented, "payload store is disabled")
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "csv" {
		httpError(w, http.StatusBadRequest, "format must be jsonl or csv")
		return
	}
	f := filterFromQuery(r)
	f.Limit = 500 // page size; we stream all pages

	filename := "optictrace-export-" + time.Now().Format("20060102-150405") + "." + format
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

	var cw *csv.Writer
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		cw = csv.NewWriter(w)
		_ = cw.Write([]string{"time", "service", "method", "path", "route", "status",
			"duration_ms", "source", "remote", "req_bytes", "resp_bytes",
			"matched_rules", "labels", "request_headers", "response_headers",
			"request_body", "response_body"})
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}

	enc := json.NewEncoder(w)
	for offset := 0; ; offset += f.Limit {
		f.Offset = offset
		recs, _, err := s.Reader.Query(r.Context(), f)
		if err != nil || len(recs) == 0 {
			break
		}
		// Accumulated per page: an export that streams 12,000 records must
		// audit as 12,000, and NoteAccess adds rather than replaces. IDs are
		// deliberately omitted — naming every row of a bulk export would bloat
		// the audit record without telling anyone more than the count does.
		ext.NoteAccess(r.Context(), ext.Accessed{Count: len(recs), Filter: auditableQuery(r)})
		for i := range recs {
			rec := &recs[i]
			if cw != nil {
				_ = cw.Write([]string{
					rec.Time.Format(time.RFC3339Nano), rec.Service, rec.Method,
					rec.Path, rec.Route, strconv.Itoa(rec.Status),
					strconv.FormatFloat(rec.DurationMS, 'f', 3, 64),
					rec.Source, rec.Remote,
					strconv.FormatInt(rec.ReqBytes, 10), strconv.FormatInt(rec.RespBytes, 10),
					strings.Join(rec.MatchedRules, " "), jsonCell(rec.Labels),
					jsonCell(rec.RequestHeaders), jsonCell(rec.ResponseHeaders),
					rec.RequestBody, rec.ResponseBody,
				})
			} else {
				_ = enc.Encode(rec)
			}
		}
		if len(recs) < f.Limit {
			break
		}
	}
	if cw != nil {
		cw.Flush()
	}
}

func jsonCell(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" {
		return ""
	}
	return string(b)
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	raw, err := os.ReadFile(s.ConfigPath)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	cfg, parseErr := config.Parse(raw)
	resp := map[string]any{"path": filepath.Base(s.ConfigPath), "raw": string(raw)}
	if parseErr != nil {
		resp["valid"] = false
		resp["error"] = parseErr.Error()
	} else {
		resp["valid"] = true
		resp["service"] = cfg.Service.Name
		resp["rules"] = len(cfg.Rules)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	cfg, parseErr := config.Parse(raw)
	if parseErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": parseErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true, "service": cfg.Service.Name, "rules": len(cfg.Rules),
	})
}

func (s *Server) reload(w http.ResponseWriter, _ *http.Request) {
	if s.Reload == nil {
		httpError(w, http.StatusNotImplemented, "reload not wired")
		return
	}
	if err := s.Reload(); err != nil {
		httpError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true})
}

// ingest accepts pre-governed records from framework SDKs. The SDK applies
// optic.yaml restriction/redaction in-process (sensitive data never crosses
// a process boundary raw); the agent adds metrics + persistence.
func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	var rec store.Record
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&rec); err != nil {
		httpError(w, http.StatusBadRequest, "invalid record: "+err.Error())
		return
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	if rec.Source == "" || rec.Source == "proxy" {
		rec.Source = "sdk"
	}
	if rec.Route == "" {
		rec.Route = rec.Path
	}
	if s.Collector != nil {
		s.Collector.SDKIngested()
		s.Collector.Observe(metrics.Observation{
			// Carry the RECORD's service, not the agent's: several SDK
			// services report into one agent, and attributing their traffic to
			// the collector would merge a fleet into a single series.
			Service: rec.Service,
			Method:  rec.Method, Route: rec.Route, Status: rec.Status,
			Duration: time.Duration(rec.DurationMS * float64(time.Millisecond)),
			ReqBytes: rec.ReqBytes, RespBytes: rec.RespBytes,
			Labels: rec.Labels,
		})
	}
	if s.Writer != nil {
		s.Writer.Enqueue(&rec)
	}
	if s.Dispatcher != nil {
		s.Dispatcher.Enqueue(&rec)
	}
	w.WriteHeader(http.StatusAccepted)
}

// ui serves the embedded dashboard build when present, falling back to a
// minimal status page so the admin port is never a blank 404.
func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if s.UIDir != "" {
		if _, err := os.Stat(s.UIDir); err == nil {
			serveStatic(s.UIDir, w, r)
			return
		}
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Say WHERE it looked and how to fix it. "Not found" on its own sends
	// people to read the source; the usual cause is simply that the agent was
	// started from a different working directory than the one -ui is relative
	// to, which the path makes obvious at a glance.
	where := s.UIDir
	if where == "" {
		where = "(no -ui directory set)"
	} else if abs, err := filepath.Abs(where); err == nil {
		where = abs
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><title>OpticTrace</title>
<body style="font-family:system-ui;background:#0b1220;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0">
<div style="text-align:center;max-width:44rem;padding:1rem">
<h1 style="letter-spacing:.05em">OpticTrace</h1>
<p>Agent running. The API below works — only the dashboard build is missing.</p>
<p style="color:#7c8cad;font-size:.85rem">Looked in <code style="color:#e2e8f0">`+
		html.EscapeString(where)+`</code></p>
<p style="color:#7c8cad;font-size:.85rem">Build it with <code style="color:#e2e8f0">make ui</code>,
or start the agent with <code style="color:#e2e8f0">-ui /path/to/ui/out</code>.</p>
<p style="margin-top:1.5rem"><a style="color:#7dd3fc" href="/metrics">/metrics</a> ·
<a style="color:#7dd3fc" href="/api/stats">/api/stats</a> ·
<a style="color:#7dd3fc" href="/api/logs">/api/logs</a></p></div></body>`)
}

// serveStatic serves a static-exported SPA: exact file if present, otherwise
// path.html (Next.js export layout), otherwise index.html.
func serveStatic(dir string, w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	full := filepath.Join(dir, p)
	if st, err := os.Stat(full); err == nil && !st.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	if st, err := os.Stat(full + ".html"); err == nil && !st.IsDir() {
		http.ServeFile(w, r, full+".html")
		return
	}
	http.ServeFile(w, r, filepath.Join(dir, "index.html"))
}

// --- helpers ----------------------------------------------------------------

func filterFromQuery(r *http.Request) store.Filter {
	q := r.URL.Query()
	f := store.Filter{
		Method:     q.Get("method"),
		PathPrefix: q.Get("path"),
		Search:     q.Get("q"),
	}
	f.StatusMin, _ = strconv.Atoi(q.Get("status_min"))
	f.StatusMax, _ = strconv.Atoi(q.Get("status_max"))
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil { // "15m", "1h"
			f.Since = time.Now().Add(-d)
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = t
		}
	}
	// trace=<id> selects every hop of one request across services.
	if tid := r.URL.Query().Get("trace"); tid != "" {
		f.TraceID = tid
	}
	// label.<name>=<value> selects by tag: the multi-tenant question, "show me
	// only this tenant's calls". Values are matched literally by every driver.
	for key, vals := range r.URL.Query() {
		name, ok := strings.CutPrefix(key, "label.")
		if !ok || name == "" || len(vals) == 0 || vals[0] == "" {
			continue
		}
		if f.Labels == nil {
			f.Labels = map[string]string{}
		}
		f.Labels[name] = vals[0]
	}
	return f
}

func parseDurationDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return def
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- application logs --------------------------------------------------------

// maxAppLogBatch bounds one ingest call. Log shippers batch aggressively and
// an unbounded body is a trivial way to make the agent the thing that falls
// over, which the telemetry pipeline must never be.
const (
	maxAppLogBatch     = 1000
	maxAppLogBodyBytes = 4 << 20
)

// appLogBatch accepts either a single line or an array, because log shippers
// disagree about which they send and rejecting one of them is a support
// burden with no upside.
type appLogBatch struct {
	lines []store.AppLog
}

func (b *appLogBatch) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &b.lines)
	}
	var one store.AppLog
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return err
	}
	b.lines = []store.AppLog{one}
	return nil
}

// ingestAppLogs accepts application log lines and stores the ones that belong
// to a span. Governance runs here, before persistence: a log line carries
// whatever someone pasted into it, so it is redacted and capped on the way in
// rather than stored raw and cleaned up later.
func (s *Server) ingestAppLogs(w http.ResponseWriter, r *http.Request) {
	if s.AppLogs == nil || !s.AppLogs.Enabled() {
		httpError(w, http.StatusNotImplemented,
			"application logs are off — set telemetry.app_logs.enabled: true")
		return
	}
	if s.AppLogStore == nil {
		// The driver has no app-log support. Say which problem it is: this
		// looks identical to a config mistake from the caller's side.
		httpError(w, http.StatusNotImplemented,
			"the configured store driver does not implement app-log storage")
		return
	}

	var batch appLogBatch
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAppLogBodyBytes)).Decode(&batch); err != nil {
		httpError(w, http.StatusBadRequest, "invalid log batch: "+err.Error())
		return
	}
	if len(batch.lines) > maxAppLogBatch {
		httpError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("batch of %d exceeds the %d-line limit", len(batch.lines), maxAppLogBatch))
		return
	}

	kept := make([]store.AppLog, 0, len(batch.lines))
	dropped := map[string]int{}
	for i := range batch.lines {
		l := &batch.lines[i]
		if l.Time.IsZero() {
			l.Time = time.Now()
		}
		if l.Source == "" {
			l.Source = "ingest"
		}
		if ok, reason := s.AppLogs.Admit(l); ok {
			kept = append(kept, *l)
		} else {
			dropped[string(reason)]++
		}
	}

	if len(kept) > 0 {
		// Storing synchronously here is deliberate: this is not the proxied
		// request's hot path — it is a separate call from a log shipper, and
		// backpressure on it is the correct signal that the store is behind.
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := s.AppLogStore.SaveAppLogs(ctx, kept); err != nil {
			if s.Logger != nil {
				s.Logger.Error("app log save failed", "error", err, "lines", len(kept))
			}
			httpError(w, http.StatusServiceUnavailable, "store unavailable")
			return
		}
	}

	if s.Collector != nil {
		s.Collector.AppLogStored(len(kept))
		for reason, n := range dropped {
			s.Collector.AppLogDropped(reason, n)
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"stored":  len(kept),
		"dropped": dropped,
	})
}

// queryAppLogs returns the lines an application wrote, oldest first — reading
// what a request did means reading it in the order it happened.
func (s *Server) queryAppLogs(w http.ResponseWriter, r *http.Request) {
	if s.AppLogStore == nil {
		httpError(w, http.StatusNotImplemented, "app-log storage is not configured")
		return
	}
	q := r.URL.Query()
	f := store.AppLogFilter{
		TraceID:  q.Get("trace"),
		SpanID:   q.Get("span"),
		Service:  q.Get("service"),
		LevelMin: q.Get("level"),
		Search:   q.Get("q"),
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	if f.Limit <= 0 {
		f.Limit = 200
	}
	if window := q.Get("window"); window != "" {
		f.Since = time.Now().Add(-parseDurationDefault(window, time.Hour))
	}
	lines, total, err := s.AppLogStore.QueryAppLogs(r.Context(), f)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if lines == nil {
		lines = []store.AppLog{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines, "total": total})
}

// analysisRows is the row bound for the analysis endpoints, resolved. App logs
// run orders of magnitude above request volume, so an unbounded scan of them
// would read far more than the equivalent record scan.
func (s *Server) analysisRows() int {
	if s.AnalysisMaxRows > 0 {
		return s.AnalysisMaxRows
	}
	return store.DefaultAnalysisMaxRows
}

// appLogStats returns aggregate counts for the dashboard. It exposes no
// message text, which is why it needs only CapReadStats.
func (s *Server) appLogStats(w http.ResponseWriter, r *http.Request) {
	if s.AppLogStore == nil {
		// Not an error: app logs are optional, and a dashboard asking about a
		// feature nobody turned on should render an empty panel, not a banner.
		writeJSON(w, http.StatusOK, &store.AppLogSummary{
			ByLevel: map[string]int64{}, ByService: map[string]int64{},
		})
		return
	}
	window := parseDurationDefault(r.URL.Query().Get("window"), time.Hour)
	sum, err := s.AppLogStore.AppLogStats(r.Context(), time.Now().Add(-window))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}
