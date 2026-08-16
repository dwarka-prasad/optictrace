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
//	GET  /                     embedded developer dashboard
package admin

import (
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	Logger     *slog.Logger
	Collector  *metrics.Collector
	Reader     store.LogStore     // queries (may be nil when driver=none)
	Writer     *store.AsyncWriter // ingest path
	Dispatcher *export.Dispatcher // output plugins (may be nil)
	ConfigPath string
	Reload     func() error // hot-reload hook installed by main
	UIDir      string       // static dashboard directory (optional)
	Version    string
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

	startedAt time.Time
}

func (s *Server) Handler() http.Handler {
	s.startedAt = time.Now()
	mux := http.NewServeMux()

	if s.Collector != nil {
		mux.Handle("GET /metrics", s.Collector.Handler())
	}
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/logs", s.listLogs)
	mux.HandleFunc("GET /api/logs/{id}", s.getLog)
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/routes", s.routes)
	mux.HandleFunc("GET /api/rules/stats", s.ruleStats)
	mux.HandleFunc("GET /api/system", s.system)
	mux.HandleFunc("GET /api/spec", s.inferSpec)
	mux.HandleFunc("GET /api/usage", s.usage)
	mux.HandleFunc("GET /api/scan", s.scan)
	mux.HandleFunc("GET /api/services", s.services)
	mux.HandleFunc("GET /api/export", s.export)
	mux.HandleFunc("GET /api/config", s.getConfig)
	mux.HandleFunc("POST /api/config/validate", s.validateConfig)
	mux.HandleFunc("POST /api/reload", s.reload)
	mux.HandleFunc("POST /api/ingest", s.ingest)
	mux.HandleFunc("/", s.ui)

	return withCORS(s.CORSOrigins, s.withAuth(mux))
}

// withAuth gates the control plane behind a bearer token. Comparison is
// constant-time so a timing side channel can't be used to guess the token
// byte by byte.
func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.AuthToken == "" {
		return next // disabled: the port is expected to be firewalled
	}
	want := []byte(s.AuthToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.HealthOpen && r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		// Preflight carries no credentials by design.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		got := ""
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			got = strings.TrimPrefix(h, "Bearer ")
		} else if t := r.URL.Query().Get("token"); t != "" {
			// Query fallback exists so a browser can load the dashboard;
			// it is inherently weaker (proxies log URLs), hence documented.
			got = t
		}
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="optictrace"`)
			httpError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
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
	report := sc.Report()
	crit, high, med := report.Counts()
	if report.Findings == nil {
		report.Findings = []scan.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records_scanned": report.Scanned,
		"since":           report.Since,
		"critical":        crit,
		"high":            high,
		"medium":          med,
		"findings":        report.Findings,
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
			Method: rec.Method, Route: rec.Route, Status: rec.Status,
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><title>OpticTrace</title>
<body style="font-family:system-ui;background:#0b1220;color:#e2e8f0;display:grid;place-items:center;height:100vh;margin:0">
<div style="text-align:center"><h1 style="letter-spacing:.05em">OpticTrace</h1>
<p>agent running — dashboard build not found</p>
<p><a style="color:#7dd3fc" href="/metrics">/metrics</a> ·
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
