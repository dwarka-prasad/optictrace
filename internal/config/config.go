// Package config defines the optic.yaml schema, its loader, and validation.
//
// Design notes:
//   - The schema is intentionally declarative and order-sensitive: rules are
//     evaluated top-to-bottom and *merged* (not first-match-wins), so a broad
//     redaction rule and a narrow restriction rule can both apply.
//   - Capture semantics are OPT-OUT: everything is captured unless a rule's
//     `restrict` list disables it.
//   - Validation is strict and happens once at load time so the hot path
//     (per-request rule evaluation) never has to handle malformed input.
package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/scan"
)

// LabelSource describes where a custom label's value comes from.
//
// Compiled once at load time: the hot path does no parsing, and a malformed
// source or regex fails `optictrace validate` rather than at request time.
type LabelSource struct {
	Kind string // "header" | "query" | "path" | "static" | "json" | "json_response"
	Key  string // header/query name, the literal value for static
	Seg  int    // 1-indexed path segment when Kind == "path"
	// JSONPath is the split body path for the json kinds.
	JSONPath []string
	// Extract, when set, pulls a capture group out of the raw value. Exactly
	// one group; a non-match yields "" rather than the whole value, so a
	// mismatched pattern produces a missing label instead of a surprising one.
	Extract *regexp.Regexp
}

// Extract pulls the label value out of a request. Missing values return "".
// Value resolves this source against a request.
func (s LabelSource) Value(r *http.Request) string {
	var raw string
	switch s.Kind {
	case "header":
		raw = r.Header.Get(s.Key)
	case "query":
		raw = r.URL.Query().Get(s.Key)
	case "path":
		segs := pathSegments(r.URL.Path)
		if s.Seg >= 1 && s.Seg <= len(segs) {
			raw = segs[s.Seg-1]
		}
	case "static":
		// Constant: the mechanism for TAGGING a class of traffic. Combined
		// with match criteria and rule merge order, this is how conditional
		// tags are expressed without a second concept.
		return s.Key
	case "json", "json_response":
		// Resolved by ValueFromBody — the body is not on the request struct.
		return ""
	}
	return s.apply(raw)
}

// NeedsBody reports whether this source reads a request or response body.
func (s LabelSource) NeedsBody() bool {
	return s.Kind == "json" || s.Kind == "json_response"
}

// NeedsResponseBody reports whether this source reads the RESPONSE body, which
// is only available after the handler has run.
func (s LabelSource) NeedsResponseBody() bool { return s.Kind == "json_response" }

// ValueFromBody resolves a json source against an already-parsed body.
//
// The body handed here is the GOVERNED one — post-redaction. That is
// deliberate and load-bearing: extracting from the raw payload would let
// `labels: {email: "json:$.customer.email"}` copy a redacted value into a
// Prometheus label and the stored labels map, quietly routing around the
// governance the rule next to it is enforcing. Extracting after redaction
// means such a label reads "[REDACTED]" — visibly wrong rather than silently
// leaking. Validate also refuses the overlap outright.
func (s LabelSource) ValueFromBody(doc any) string {
	if !s.NeedsBody() || doc == nil {
		return ""
	}
	raw, ok := FirstStringFunc(doc, s.JSONPath)
	if !ok {
		return ""
	}
	return s.apply(raw)
}

// FirstStringFunc is wired to engine.FirstString at init to avoid an import
// cycle: config owns the schema, engine owns the JSON walker.
var FirstStringFunc func(node any, path []string) (string, bool) = func(any, []string) (string, bool) {
	return "", false
}

// apply runs the optional capture-group extraction.
func (s LabelSource) apply(raw string) string {
	if s.Extract == nil || raw == "" {
		return raw
	}
	m := s.Extract.FindStringSubmatch(raw)
	if len(m) < 2 {
		return "" // no match, or no capture group: a missing label beats a wrong one
	}
	return m[1]
}

// ParseLabelSource compiles a label source expression:
//
//	header:X-Tenant-ID
//	query:tenant
//	path:4                 1-indexed segment
//	static:premium
//
// optionally followed by |<regex> with exactly one capture group.
//
// Exported so config validation and the engine use the same parser — two
// implementations of a grammar drift, and the drift shows up as a rule that
// validates but does not fire.
func ParseLabelSource(src string) (LabelSource, error) {
	expr, pattern, hasRegex := strings.Cut(src, "|")
	kind, key, ok := strings.Cut(expr, ":")
	if !ok {
		return LabelSource{}, fmt.Errorf("source %q must be "+
			"'header:<Name>', 'query:<name>', 'path:<n>', 'static:<value>', "+
			"'json:$.a.b' or 'json_response:$.a.b'", src)
	}
	ls := LabelSource{Kind: kind, Key: key}
	switch kind {
	case "header", "query":
		if key == "" {
			return LabelSource{}, fmt.Errorf("source %q needs a name after the colon", src)
		}
	case "static":
		if key == "" {
			return LabelSource{}, fmt.Errorf("source %q needs a value after 'static:'", src)
		}
	case "json", "json_response":
		if !strings.HasPrefix(key, "$.") || len(key) <= 2 {
			return LabelSource{}, fmt.Errorf("source %q: %s needs a dotted path "+
				"starting with '$.', e.g. 'json:$.lead.source'", src, kind)
		}
		ls.JSONPath = strings.Split(strings.TrimPrefix(key, "$."), ".")
	case "path":
		n, err := strconv.Atoi(key)
		if err != nil || n < 1 {
			return LabelSource{}, fmt.Errorf("source %q: path segment must be a "+
				"positive 1-indexed integer, e.g. 'path:3'", src)
		}
		ls.Seg = n
	default:
		return LabelSource{}, fmt.Errorf("source %q: unknown kind %q "+
			"(header, query, path, static, json, json_response)", src, kind)
	}
	if hasRegex {
		if kind == "static" {
			return LabelSource{}, fmt.Errorf("source %q: a regex on a static "+
				"value has nothing to extract from", src)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return LabelSource{}, fmt.Errorf("source %q: %w", src, err)
		}
		if re.NumSubexp() != 1 {
			return LabelSource{}, fmt.Errorf("source %q: the extraction regex needs "+
				"exactly one capture group, found %d", src, re.NumSubexp())
		}
		ls.Extract = re
	}
	return ls, nil
}

// pathSegments splits a URL path into its non-empty segments, so `path:2` on
// "/api/v1/x" resolves to "v1".
func pathSegments(p string) []string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	out := parts[:0]
	for _, seg := range parts {
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// CaptureField enumerates the telemetry channels a rule may restrict.
type CaptureField string

const (
	FieldRequestBody  CaptureField = "request_body"
	FieldResponseBody CaptureField = "response_body"
	FieldHeaders      CaptureField = "headers"
	FieldQuery        CaptureField = "query"
)

// Config is the root of an optic.yaml document.
type Config struct {
	Version   int       `yaml:"version"`
	Service   Service   `yaml:"service"`
	Defaults  Defaults  `yaml:"defaults"`
	Telemetry Telemetry `yaml:"telemetry"`
	Scan      ScanCfg   `yaml:"scan"`
	Rules     []Rule    `yaml:"rules"`
}

// ScanCfg configures `optictrace scan`, the leak detector that looks for
// sensitive values which slipped past governance.
type ScanCfg struct {
	// Detectors are org-specific patterns, added to the built-in set rather
	// than replacing it. The built-ins cover credentials and regulated
	// identifiers that look the same everywhere; these cover the ones that
	// do not — internal employee IDs, customer account formats, national
	// identifiers outside the US.
	Detectors []DetectorCfg `yaml:"detectors"`
}

// DetectorCfg is one user-defined sensitive-value pattern.
type DetectorCfg struct {
	Kind     string `yaml:"kind"`     // finding label, e.g. "aadhaar"
	Severity string `yaml:"severity"` // critical | high | medium
	Why      string `yaml:"why"`      // what a reader should understand about the risk
	Pattern  string `yaml:"pattern"`  // Go regexp
	// Verify names a built-in checksum to confirm a regex hit — "luhn",
	// "iban", "us_ssn", "verhoeff". Strongly preferred over a bare pattern:
	// a detector that cries wolf gets switched off, which is worse than not
	// having it. Empty means no checksum.
	Verify string `yaml:"verify"`
}

// Telemetry configures the observability sinks: the admin/metrics endpoint,
// Prometheus exposition, console logging, and the payload store.
type Telemetry struct {
	// AdminListen is the address of the admin server (/metrics, dashboard,
	// query APIs). Kept separate from proxied traffic on purpose: you can
	// firewall it independently.
	//
	// Default "127.0.0.1:9095" — loopback, NOT all interfaces. The admin API
	// can read every captured payload, so exposing it is a deliberate act:
	// set "0.0.0.0:9095" explicitly (and turn on `auth`) when you mean it.
	AdminListen string `yaml:"admin_listen"`
	// CORSOrigins allows listed browser origins to call the admin API
	// cross-origin — normally just a dashboard dev server, e.g.
	// "http://localhost:3001". Empty (the default) sends no CORS headers at
	// all, so the browser same-origin policy protects the API even when auth
	// is off. "*" is accepted but rejected by Validate unless auth is
	// enabled, because a wildcard plus no credentials lets any page a
	// developer visits read the entire capture store.
	CORSOrigins []string      `yaml:"cors_origins"`
	ConsoleLog  *bool         `yaml:"console_log"` // structured stdout telemetry (default true)
	Metrics     Metrics       `yaml:"metrics"`
	Store       StoreCfg      `yaml:"store"`
	Exporters   []ExporterCfg `yaml:"exporters"`
	Billing     *Billing      `yaml:"billing"`
	// AppLogs governs application log lines correlated to spans. Nil means
	// the feature is off and the ingest endpoint refuses politely.
	AppLogs *AppLogsCfg `yaml:"app_logs"`
	Auth    *AdminAuth  `yaml:"auth"`
	TLS     *AdminTLS   `yaml:"tls"`
}

// AdminReachable reports whether AdminListen accepts connections from beyond
// loopback. Used to decide how loudly to warn about an unauthenticated port.
func (t *Telemetry) AdminReachable() bool {
	host, _, err := net.SplitHostPort(t.AdminListen)
	if err != nil {
		return true // unparseable: assume the worst
	}
	if host == "" {
		return true // ":9095" binds every interface
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// AdminAuth protects the control plane. It is off by default because the
// admin port is meant to be firewalled, but "meant to be" is not a control —
// enable this whenever the port could be reachable.
type AdminAuth struct {
	// Token is a bearer token compared in constant time. Prefer TokenEnv:
	// a secret in a config file is a secret in your git history.
	Token string `yaml:"token"`
	// TokenEnv names an environment variable holding the token. It wins
	// over Token when both are set.
	TokenEnv string `yaml:"token_env"`
	// AllowHealth keeps /healthz unauthenticated so orchestrator probes
	// keep working. Default true.
	AllowHealth *bool `yaml:"allow_health"`
}

// AdminTLS serves the control plane over HTTPS.
type AdminTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Resolve returns the effective bearer token, reading TokenEnv if set.
// An empty result means authentication is disabled.
func (a *AdminAuth) Resolve() string {
	if a == nil {
		return ""
	}
	if a.TokenEnv != "" {
		return os.Getenv(a.TokenEnv)
	}
	return a.Token
}

// HealthOpen reports whether /healthz bypasses authentication.
func (a *AdminAuth) HealthOpen() bool {
	return a == nil || a.AllowHealth == nil || *a.AllowHealth
}

// Billing turns telemetry into cost attribution (FinOps): usage is grouped
// by one consumer label (e.g. tenant) and priced by the models below. All
// prices are optional — omitted ones simply contribute zero.
type Billing struct {
	// ConsumerLabel is the optic.yaml label that identifies the consumer
	// (must be declared under some rule's `labels`). Default "tenant".
	ConsumerLabel string `yaml:"consumer_label"`
	Currency      string `yaml:"currency"` // display only; default "USD"
	Prices        Prices `yaml:"prices"`
}

type Prices struct {
	PerRequest float64 `yaml:"per_request"` // e.g. 0.0001
	PerGB      float64 `yaml:"per_gb"`      // request+response bytes
	// PerMeterUnit prices custom meters by name, e.g. tokens: 0.000002.
	PerMeterUnit map[string]float64 `yaml:"per_meter_unit"`
}

// ExporterCfg declares one output plugin. Every exporter receives the SAME
// governed records the store does — post-restriction, post-redaction — so no
// export path can ever see raw sensitive data.
type ExporterCfg struct {
	Name string `yaml:"name"` // unique; becomes the Prometheus `exporter` label
	Type string `yaml:"type"` // "file" | "webhook" | "command" | "otlp"

	// file: JSONL append target, rotated at MaxSizeMB (default 100).
	Path      string `yaml:"path"`
	MaxSizeMB int    `yaml:"max_size_mb"`

	// webhook: POST a JSON array of records to URL with optional headers.
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`

	// command: the custom-plugin hook. OpticTrace spawns this executable and
	// streams one JSON record per line to its stdin — write a plugin in any
	// language to ship data to Kafka, S3, a SIEM, anywhere. The process is
	// restarted with backoff if it exits.
	Command []string `yaml:"command"`

	// Batching (file & webhook): flush when BatchSize records accumulate or
	// FlushInterval elapses, whichever comes first.
	BatchSize     int    `yaml:"batch_size"`     // default 50
	FlushInterval string `yaml:"flush_interval"` // Go duration, default "3s"
	QueueSize     int    `yaml:"queue_size"`     // per-exporter; default 1024

	// Settings carries configuration for an out-of-tree exporter registered
	// via ext.RegisterExporter. The decoder rejects unknown top-level keys on
	// purpose — a typo must fail loudly rather than look like a working rule —
	// so a plugin's own keys need somewhere legitimate to live, and this is it.
	Settings ext.Settings `yaml:"settings"`
}

// Metrics controls the Prometheus exporter.
type Metrics struct {
	Enabled *bool `yaml:"enabled"` // default true
	// Buckets are latency histogram bounds in seconds. Defaults tuned for
	// API traffic (1ms .. 10s).
	Buckets []float64 `yaml:"buckets"`
	// MaxLabelValues caps how many DISTINCT values each custom label may
	// contribute to metrics. Label values come from arbitrary request
	// headers, so one buggy or hostile client can otherwise blow up
	// Prometheus cardinality. Beyond the cap, values collapse into
	// "__over_limit__" and optictrace_label_capped_total increments.
	// Route cardinality is already bounded by design; this closes the same
	// hole for custom labels. Default 500; an explicit 0 disables the guard.
	MaxLabelValues *int `yaml:"max_label_values"`
}

// StoreCfg configures asynchronous payload persistence.
type StoreCfg struct {
	// Driver is "sqlite" (default), "postgres" (multi-node),
	// "clickhouse" (column store, for volume), or "none".
	Driver string `yaml:"driver"`
	// DSN is the SQLite file path, or a postgres:// / clickhouse:// URL.
	// Default "optictrace.db".
	DSN string `yaml:"dsn"`
	// QueueSize bounds the async write queue; writes are dropped (and
	// counted) rather than ever blocking the request path. Default 4096.
	QueueSize int `yaml:"queue_size"`
	// RetentionMaxRows caps the log table; oldest rows are pruned.
	// 0 disables pruning. Default 100000.
	RetentionMaxRows int64 `yaml:"retention_max_rows"`
	// RetentionMaxAge deletes records older than this regardless of row
	// count — the control a data-retention policy is actually written in
	// ("keep 30 days"). Go duration, e.g. "720h". Empty disables it.
	RetentionMaxAge string `yaml:"retention_max_age"`
	// Settings carries configuration for an out-of-tree store registered via
	// ext.RegisterStore. See ExporterCfg.Settings for why this exists.
	Settings ext.Settings `yaml:"settings"`
	// AnalysisMaxRows bounds how many records one analysis pass reads —
	// `scan`, `spec`, `suggest`, `review`, `replay` and the /api/scan and
	// /api/spec endpoints. These read FULL records including bodies, so at
	// the default capture limit this is a memory ceiling rather than just a
	// row count. Default 20000; hard ceiling 500000.
	AnalysisMaxRows int `yaml:"analysis_max_rows"`
}

// Service describes the proxied service (standalone sidecar mode). When
// OpticTrace is embedded as middleware, Listen/Upstream are unused.
type Service struct {
	Name     string `yaml:"name"`
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
	// GraphQLPaths lists path globs served by GraphQL. On these routes the
	// request body is parsed for an operation name, which then becomes part
	// of the route label and can be matched by a rule.
	//
	// Opt-in because it means buffering the request body on those routes.
	// The alternative — every operation collapsing into one `/graphql` route
	// — makes latency percentiles, per-operation rules and spec inference
	// meaningless for a GraphQL service.
	GraphQLPaths []string `yaml:"graphql_paths"`
	// Trace controls W3C Trace Context handling.
	Trace TraceCfg `yaml:"trace"`
	// HTTP2 serves cleartext HTTP/2 (h2c) on the proxy listener in addition
	// to HTTP/1.1. Off by default: it changes protocol negotiation for every
	// client, and HTTP/1.1 is what most upstreams speak.
	//
	// This is what an HTTP/2 client needs in order to connect at all — but it
	// is NOT gRPC support. gRPC bodies are length-prefixed protobuf frames,
	// so without message descriptors the governance engine cannot match
	// fields, redact them, or meter them; you would get method names and byte
	// counts. Use the SDK middleware for gRPC services.
	HTTP2 bool `yaml:"http2"`
}

// TraceCfg controls correlation across services.
//
// OpticTrace always RECORDS trace ids — that costs nothing and is what turns
// records from several services into one request. What is configurable is
// whether it writes a header anywhere, because writing one modifies traffic
// and this product's central promise is that it does not.
type TraceCfg struct {
	// PropagateUpstream sets traceparent on the request FORWARDED to your
	// service, carrying this hop's span id so downstream calls become its
	// children.
	//
	// Default true. This is the one deliberate exception to "live traffic is
	// never modified", and it is narrow: the forwarded copy only — never the
	// response, never what the client sent.
	//
	// It rewrites an inbound traceparent rather than only filling in a
	// missing one. Passing the caller's header through unchanged would make
	// every downstream hop a sibling of this one rather than a child, so the
	// fan-out flattens into a list and the tree is lost. An application doing
	// its own tracing nests under this span, which is correct.
	//
	// Set false to keep the forwarded request byte-identical; correlation
	// then stops at whatever the application itself propagates.
	PropagateUpstream *bool `yaml:"propagate_upstream"`

	// ResponseHeader, when set, returns the trace id to the CALLER under this
	// header name — "X-Trace-Id" is conventional. Off by default because it
	// modifies the response, which nothing else here does. Worth turning on
	// if you want support tickets to arrive with a trace id in them.
	ResponseHeader string `yaml:"response_header"`
}

// Propagate reports whether to add traceparent to the forwarded request.
func (t *TraceCfg) Propagate() bool {
	return t == nil || t.PropagateUpstream == nil || *t.PropagateUpstream
}

// AppLogsCfg governs application log lines — the highest-risk surface in the
// product. An app log routinely contains bearer tokens, email addresses and
// whole payloads inside stack traces, so lines are redacted and capped on the
// way in rather than stored raw and cleaned up later.
type AppLogsCfg struct {
	Enabled bool `yaml:"enabled"`
	// LevelMin drops anything less severe before it is stored. Most of the
	// volume — and almost none of the value — is debug lines.
	LevelMin string `yaml:"level_min"`
	// MaxLinesPerSpan caps one request's contribution. A retry loop logging
	// inside a hot path can otherwise write millions of lines against a
	// single span. 0 uses the default; -1 means no cap.
	MaxLinesPerSpan int `yaml:"max_lines_per_span"`
	// MaxMessageBytes truncates an individual line. Stack traces are large
	// and the first lines are the ones that matter.
	MaxMessageBytes int `yaml:"max_message_bytes"`
	// DropOrphans discards lines that carry no span id — startup, cron jobs,
	// background workers. Default true: they cannot be attributed to a
	// request, and attaching them to whichever request happened to be in
	// flight would cross-attribute tenants.
	//
	// Whatever this is set to, drops are counted in
	// optictrace_app_logs_dropped_total — data thrown away silently is data
	// nobody knows they are missing.
	DropOrphans *bool `yaml:"drop_orphans"`
	// RetentionMaxAge expires lines independently of records. App logs run
	// orders of magnitude above request volume and are rarely wanted for as
	// long.
	RetentionMaxAge time.Duration `yaml:"retention_max_age"`
	// Redact scrubs lines before they are stored. Patterns are regexes
	// applied to the message and to every structured field value; each match
	// is replaced with [REDACTED].
	Redact AppLogRedact `yaml:"redact"`
}

// AppLogRedact is the log-line equivalent of a rule's redact block.
type AppLogRedact struct {
	// Patterns are regexes. A pattern that fails to compile is a config
	// error, not a silently-skipped rule.
	Patterns []string `yaml:"patterns"`
	// Fields are structured-field keys whose values are replaced wholesale.
	Fields []string `yaml:"fields"`
}

// validate checks the app-log block at load time. A redaction pattern that
// does not compile must be a startup failure: the alternative is an agent that
// runs happily while the rule meant to mask credentials never applies.
func (a *AppLogsCfg) validate() error {
	if a == nil {
		return nil
	}
	for i, pat := range a.Redact.Patterns {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("telemetry.app_logs.redact.patterns[%d] (%q): %w", i, pat, err)
		}
	}
	if a.LevelMin != "" && LevelRankKnown(a.LevelMin) < 0 {
		return fmt.Errorf("telemetry.app_logs.level_min %q is not a level "+
			"(debug, info, warn, error, fatal)", a.LevelMin)
	}
	if a.MaxLinesPerSpan < -1 {
		return fmt.Errorf("telemetry.app_logs.max_lines_per_span %d must be >= -1 "+
			"(-1 means no cap)", a.MaxLinesPerSpan)
	}
	if a.MaxMessageBytes < 0 {
		return fmt.Errorf("telemetry.app_logs.max_message_bytes %d must be >= 0", a.MaxMessageBytes)
	}
	if a.RetentionMaxAge < 0 {
		return fmt.Errorf("telemetry.app_logs.retention_max_age %s must not be negative", a.RetentionMaxAge)
	}
	return nil
}

// validate checks a per-rule logs block at load time. A redaction pattern that
// does not compile must fail startup: the alternative is an agent that runs
// happily while the rule meant to mask credentials never applies.
func (l *RuleLogs) validate() error {
	if l == nil {
		return nil
	}
	if l.LevelMin != "" && LevelRankKnown(l.LevelMin) < 0 {
		return fmt.Errorf("logs.level_min %q is not a level (debug, info, warn, error, fatal)", l.LevelMin)
	}
	if l.MaxLinesPerSpan < 0 {
		return fmt.Errorf("logs.max_lines_per_span %d must be >= 0 "+
			"(a per-rule block can only lower the global cap, never remove it)", l.MaxLinesPerSpan)
	}
	for i, pat := range l.Redact.Patterns {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("logs.redact.patterns[%d] (%q): %w", i, pat, err)
		}
	}
	return nil
}

// LevelRankKnown returns the severity rank of a level, or -1 if it is not one
// of the recognised names. Used to reject a typo in level_min at load time —
// "warining" would otherwise silently keep everything.
func LevelRankKnown(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace":
		return 0
	case "debug":
		return 1
	case "info", "information", "notice":
		return 2
	case "warn", "warning":
		return 3
	case "error", "err":
		return 4
	case "fatal", "critical", "crit", "panic":
		return 5
	}
	return -1
}

// DropOrphanLines reports whether uncorrelated lines are discarded.
func (a *AppLogsCfg) DropOrphanLines() bool {
	return a == nil || a.DropOrphans == nil || *a.DropOrphans
}

// Defaults holds the global capture posture applied before any rule.
type Defaults struct {
	Capture           CaptureFlags `yaml:"capture"`
	CaptureLimitBytes int64        `yaml:"capture_limit_bytes"`
}

// CaptureFlags uses *bool so an omitted key ("capture everything") is
// distinguishable from an explicit `false`.
type CaptureFlags struct {
	RequestBody  *bool `yaml:"request_body"`
	ResponseBody *bool `yaml:"response_body"`
	Headers      *bool `yaml:"headers"`
	Query        *bool `yaml:"query"`
}

// Rule couples a traffic matcher with governance actions.
type Rule struct {
	Name     string         `yaml:"name"`
	Match    Match          `yaml:"match"`
	Restrict []CaptureField `yaml:"restrict"`
	Redact   *Redact        `yaml:"redact"`
	// Labels attach dimensions to this request's telemetry: Prometheus label
	// values, stored record fields, and the grouping key for usage and cost
	// attribution. Each value is a source expression:
	//
	//	header:X-Tenant-ID     the request header
	//	query:tenant           a query parameter
	//	path:4                 the 4th path segment, 1-indexed
	//	static:premium         a constant — the way to TAG a class of traffic
	//
	// Any source may be followed by |<regex> to extract part of the value.
	// The regex needs exactly one capture group, and that group becomes the
	// label; a non-match yields an empty label rather than the whole value.
	//
	//	region: "header:X-Region|^([a-z]{2})-"      eu-west-1 -> eu
	//
	// Rules merge top to bottom and later rules win, so conditional tagging
	// needs no separate mechanism: give a broad rule a static default and let
	// a narrower rule with `match.headers` override it.
	//
	// Label values are client-controlled, so they pass through the metrics
	// cardinality guard (telemetry.metrics.max_label_values) before becoming
	// Prometheus dimensions.
	Labels map[string]string `yaml:"labels"`
	// Sample captures bodies for only this fraction of matched requests
	// (0..1]. Metrics and metadata are always recorded in full — sampling
	// only bounds payload volume on hot routes. Later rules override.
	Sample *float64 `yaml:"sample"`
	// KeepErrors and KeepSlowerThan are TAIL-BASED sampling: they rescue
	// interesting requests that uniform `sample` would have thrown away.
	// The decision is made after the response, so a route using either one
	// buffers bodies for every request and discards them at the end.
	KeepErrors     *bool  `yaml:"keep_errors"`      // always capture status >= 500
	KeepSlowerThan string `yaml:"keep_slower_than"` // Go duration, e.g. "500ms"
	// Meter extracts numeric usage figures from RESPONSE bodies by JSON
	// path — e.g. tokens: "$.usage.total_tokens" for LLM APIs. Values are
	// summed per consumer for usage/cost attribution. Metering is
	// independent of capture rules: a restricted route can still meter.
	Meter map[string]string `yaml:"meter"`
	// Logs narrows the application-log policy for requests this rule matches.
	//
	// telemetry.app_logs sets the floor for every route; this tightens it per
	// route, which is the shape the risk actually has. A payments handler
	// deserves a stricter level floor and extra redaction than a health check,
	// and expressing that globally means applying the strictest setting
	// everywhere — which in practice means people set it loosely.
	//
	// Only ever tightens. A rule cannot raise a cap or lower a level floor
	// below the global one: a per-route override that could weaken the global
	// policy would make the global setting a suggestion rather than a
	// guarantee, and reviewing one file would no longer tell you what is
	// enforced.
	Logs *RuleLogs `yaml:"logs"`
}

// RuleLogs is the per-rule application-log policy. Every field is optional;
// an omitted field inherits telemetry.app_logs.
type RuleLogs struct {
	// LevelMin raises the severity floor for this route. Ignored if it would
	// LOWER the global floor.
	LevelMin string `yaml:"level_min"`
	// MaxLinesPerSpan lowers the per-request line cap for this route. Ignored
	// if it would raise the global cap. -1 is not accepted here: removing the
	// cap is a global decision.
	MaxLinesPerSpan int `yaml:"max_lines_per_span"`
	// Redact adds patterns and field names on top of the global set. Additive
	// only — there is no way to remove a global redaction, because a rule that
	// could unmask something would make the global list unreviewable.
	Redact AppLogRedact `yaml:"redact"`
	// Drop discards application log lines for this route entirely. The
	// honest way to say "never store what this handler logs" — a debug
	// endpoint, or a route whose logs are known to carry secrets nothing can
	// pattern-match reliably.
	Drop bool `yaml:"drop"`
}

// Match selects requests by path glob and (optionally) HTTP methods.
type Match struct {
	Path    string   `yaml:"path"`
	Methods []string `yaml:"methods"`
	// GraphQLOperation matches the operation name inside a GraphQL request
	// body, as a glob. Every GraphQL operation POSTs to the same path, so
	// without this a rule cannot target one: you could not redact a field on
	// createPaymentMethod without applying the same rule to every query.
	//
	// Requires service.graphql_paths to include the route, since extracting
	// the name means reading the request body before the response.
	GraphQLOperation string `yaml:"graphql_operation"`

	// Headers matches request headers by regular expression: the rule applies
	// only when EVERY listed header matches its pattern. Header names are
	// case-insensitive, as HTTP requires.
	//
	//	match:
	//	  path: "/api/**"
	//	  headers:
	//	    X-Plan: "^(gold|platinum)$"
	//
	// Patterns are unanchored by default, exactly like Go's regexp — write ^
	// and $ when you mean a whole-value match. `"."` therefore means "the
	// header is present and non-empty", which is a useful idiom.
	Headers map[string]string `yaml:"headers"`

	// Query matches query parameters the same way.
	Query map[string]string `yaml:"query"`

	// Body matches values inside the JSON request body by path, again as
	// regular expressions:
	//
	//	match:
	//	  path: "/api/v1/leads"
	//	  body:
	//	    "$.**.source": "^flipkart$"
	//
	// This is what distinguishes callers that are otherwise identical — the
	// same endpoint, the same tenant, the same product, differing only in a
	// field of the payload.
	//
	// It costs a buffered request body on the matching routes, which is why
	// it is per-rule rather than global: only paths with a body rule pay.
	// Matched against the GOVERNED body, so a redacted field cannot be used
	// as a criterion — see the note on json label sources.
	Body map[string]string `yaml:"body"`
}

// Redact lists what to mask in *captured* telemetry. The proxied traffic
// itself is never modified.
type Redact struct {
	Headers    []string `yaml:"headers"`
	JSONFields []string `yaml:"json_fields"`
	// QueryParams are masked in the captured query string. Credentials in
	// query strings are common (?api_key=…), so capturing queries without
	// a way to mask them would be a governance regression.
	QueryParams []string `yaml:"query_params"`
}

const DefaultCaptureLimitBytes = 64 * 1024

// Detectors compiles the configured detectors. Validate has already proved
// they compile, so an error here means the config was mutated after loading.
func (c *Config) Detectors() ([]scan.Detector, error) {
	out := make([]scan.Detector, 0, len(c.Scan.Detectors))
	for _, d := range c.Scan.Detectors {
		det, err := scan.NewDetector(d.Kind, d.Severity, d.Why, d.Pattern, d.Verify)
		if err != nil {
			return nil, fmt.Errorf("scan.detectors[%s]: %w", d.Kind, err)
		}
		out = append(out, det)
	}
	return out, nil
}

// MaxAnalysisRows mirrors store.MaxAnalysisMaxRows. Duplicated rather than
// imported to keep config free of a dependency on store.
const MaxAnalysisRows = 500_000

// Load reads, parses, and validates an optic.yaml file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse decodes and validates a raw optic.yaml document.
func Parse(raw []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // reject typos like `restirct:` instead of silently ignoring them
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse optic.yaml: %w", err)
	}
	if cfg.Defaults.CaptureLimitBytes == 0 {
		cfg.Defaults.CaptureLimitBytes = DefaultCaptureLimitBytes
	}
	applyTelemetryDefaults(&cfg.Telemetry)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyTelemetryDefaults(t *Telemetry) {
	if t.AdminListen == "" {
		// Loopback by default. The admin API can read every captured payload,
		// so binding all interfaces must be something you asked for.
		t.AdminListen = "127.0.0.1:9095"
	}
	if t.Store.Driver == "" {
		t.Store.Driver = "sqlite"
	}
	if t.Store.DSN == "" && t.Store.Driver == "sqlite" {
		t.Store.DSN = "optictrace.db"
	}
	if t.Store.QueueSize <= 0 {
		t.Store.QueueSize = 4096
	}
	if t.Store.RetentionMaxRows == 0 {
		t.Store.RetentionMaxRows = 100_000
	}
	if t.Billing != nil {
		if t.Billing.ConsumerLabel == "" {
			t.Billing.ConsumerLabel = "tenant"
		}
		if t.Billing.Currency == "" {
			t.Billing.Currency = "USD"
		}
	}
	if t.Metrics.MaxLabelValues == nil {
		def := 500
		t.Metrics.MaxLabelValues = &def
	}
	if len(t.Metrics.Buckets) == 0 {
		t.Metrics.Buckets = []float64{
			0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
			0.25, 0.5, 1, 2.5, 5, 10,
		}
	}
}

// RestartRequired lists the settings that differ between two configs but
// cannot be applied by a hot reload, which only swaps the rule engine and the
// metrics label schema.
//
// Reload used to parse the whole file, validate it, apply the rules, and
// silently discard everything else — reporting success either way. Someone
// changing an exporter and reloading had no way to learn it had not taken
// effect. Naming the fields is most of the fix.
func (c *Config) RestartRequired(next *Config) []string {
	var out []string
	add := func(cond bool, field string) {
		if cond {
			out = append(out, field)
		}
	}
	add(c.Service.Listen != next.Service.Listen, "service.listen")
	add(c.Service.Upstream != next.Service.Upstream, "service.upstream")
	add(c.Service.HTTP2 != next.Service.HTTP2, "service.http2")
	add(c.Telemetry.AdminListen != next.Telemetry.AdminListen, "telemetry.admin_listen")
	add(!slices.Equal(c.Telemetry.CORSOrigins, next.Telemetry.CORSOrigins), "telemetry.cors_origins")
	add(c.Telemetry.Auth.Resolve() != next.Telemetry.Auth.Resolve(), "telemetry.auth")
	add(!reflect.DeepEqual(c.Telemetry.TLS, next.Telemetry.TLS), "telemetry.tls")
	add(!reflect.DeepEqual(c.Telemetry.Store, next.Telemetry.Store), "telemetry.store")
	add(!reflect.DeepEqual(c.Telemetry.Exporters, next.Telemetry.Exporters), "telemetry.exporters")
	add(!slices.Equal(c.Telemetry.Metrics.Buckets, next.Telemetry.Metrics.Buckets), "telemetry.metrics.buckets")
	add(!reflect.DeepEqual(c.Telemetry.Billing, next.Telemetry.Billing), "telemetry.billing")
	return out
}

// RequireProxyAddrs enforces the invariants of sidecar mode, where a listener
// is actually opened. It is separate from Validate because embedded middleware
// and the analysis subcommands legitimately have neither address.
//
// The failure this prevents: an omitted `listen` reaches net/http as Addr:""
// and binds port 80 — either quietly serving where nobody expects it, or
// failing with "listen tcp :80: bind: permission denied", a port number that
// appears nowhere in the user's config and gives them nothing to search for.
func (c *Config) RequireProxyAddrs() error {
	if c.Service.Listen == "" {
		return fmt.Errorf(`service.listen is required to run the proxy ` +
			`(an empty listen address binds port 80); set e.g. listen: ":8080"`)
	}
	if c.Service.Upstream == "" {
		return fmt.Errorf("service.upstream is required to run the proxy: " +
			"there is nowhere to forward requests to")
	}
	return nil
}

// validateHostPort rejects addresses net/http would otherwise accept and then
// bind somewhere surprising. An empty string is Addr:"" — port 80.
func validateHostPort(field, addr string) error {
	if addr == "" {
		return fmt.Errorf("%s must not be empty (an empty address binds port 80)", field)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q must be host:port, e.g. \":9095\" or \"127.0.0.1:9095\"", field, addr)
	}
	if port == "" {
		return fmt.Errorf("%s %q is missing a port", field, addr)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("%s %q: %q is not a valid port", field, addr, port)
	}
	if host != "" && net.ParseIP(host) == nil {
		// A hostname is legal but almost always a mistake in a listen address.
		if _, err := net.LookupHost(host); err != nil {
			return fmt.Errorf("%s %q: host %q does not resolve", field, addr, host)
		}
	}
	return nil
}

var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

// Validate enforces schema invariants so the runtime engine can trust the config.
// redactedJSONPaths collects every path any rule redacts, for the overlap
// check below.
func (c *Config) redactedJSONPaths() map[string]bool {
	out := map[string]bool{}
	for i := range c.Rules {
		if c.Rules[i].Redact == nil {
			continue
		}
		for _, jp := range c.Rules[i].Redact.JSONFields {
			out[jp] = true
		}
	}
	return out
}

func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d (expected 1)", c.Version)
	}
	if c.Service.Upstream != "" {
		u, err := url.Parse(c.Service.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("service.upstream %q is not a valid absolute URL", c.Service.Upstream)
		}
	}
	// Only the *format* is checked here. Whether a listen address is required
	// at all depends on how OpticTrace is being used: embedded middleware and
	// the analysis subcommands never open a listener, and the proxy package's
	// tests drive the interceptor directly with an upstream but no listener.
	// The sidecar's hard requirement lives in RequireProxyAddrs, called by
	// `run`, which is the only path that actually binds a port.
	if c.Service.Listen != "" {
		if err := validateHostPort("service.listen", c.Service.Listen); err != nil {
			return err
		}
	}
	if err := validateHostPort("telemetry.admin_listen", c.Telemetry.AdminListen); err != nil {
		return err
	}
	if err := c.Telemetry.AppLogs.validate(); err != nil {
		return err
	}
	for _, r := range c.Rules {
		if r.Logs != nil && (c.Telemetry.AppLogs == nil || !c.Telemetry.AppLogs.Enabled) {
			return fmt.Errorf("rule %q has a `logs:` block but telemetry.app_logs.enabled is not true — "+
				"the block would be silently ignored", r.Name)
		}
	}
	for _, o := range c.Telemetry.CORSOrigins {
		if o == "*" {
			// A wildcard means any page the operator visits can read the
			// capture store cross-origin. Only defensible when a credential
			// is also required.
			if c.Telemetry.Auth.Resolve() == "" {
				return fmt.Errorf(`telemetry.cors_origins: "*" requires telemetry.auth ` +
					"(a wildcard origin without a token lets any website read captured traffic)")
			}
			continue
		}
		u, err := url.Parse(o)
		if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
			return fmt.Errorf("telemetry.cors_origins: %q must be a scheme://host[:port] origin", o)
		}
	}
	switch c.Telemetry.Store.Driver {
	case "sqlite", "none":
	case "postgres":
		if !strings.HasPrefix(c.Telemetry.Store.DSN, "postgres://") &&
			!strings.HasPrefix(c.Telemetry.Store.DSN, "postgresql://") {
			return fmt.Errorf("telemetry.store.dsn must be a postgres:// URL when driver is postgres")
		}
	case "clickhouse":
		if !strings.HasPrefix(c.Telemetry.Store.DSN, "clickhouse://") {
			return fmt.Errorf("telemetry.store.dsn must be a clickhouse:// URL when driver is clickhouse")
		}
	default:
		// An out-of-tree driver registered via ext.RegisterStore is a valid
		// name; that is what makes a linked-in extension configurable without
		// the core knowing anything about it.
		if _, ok := ext.LookupStore(c.Telemetry.Store.Driver); !ok {
			known := append([]string{"sqlite", "postgres", "clickhouse", "none"},
				ext.RegisteredStores()...)
			return fmt.Errorf("telemetry.store.driver %q is not supported (%s)",
				c.Telemetry.Store.Driver, strings.Join(known, ", "))
		}
	}
	if a := c.Telemetry.Auth; a != nil {
		if a.Token == "" && a.TokenEnv == "" {
			return fmt.Errorf("telemetry.auth: set either token or token_env (token_env is preferred)")
		}
		if a.TokenEnv != "" && os.Getenv(a.TokenEnv) == "" {
			return fmt.Errorf("telemetry.auth.token_env: %s is not set in the environment", a.TokenEnv)
		}
	}
	if t := c.Telemetry.TLS; t != nil {
		if t.CertFile == "" || t.KeyFile == "" {
			return fmt.Errorf("telemetry.tls: both cert_file and key_file are required")
		}
		for _, f := range []string{t.CertFile, t.KeyFile} {
			if _, err := os.Stat(f); err != nil {
				return fmt.Errorf("telemetry.tls: %v", err)
			}
		}
	}
	if n := c.Telemetry.Store.AnalysisMaxRows; n < 0 {
		return fmt.Errorf("telemetry.store.analysis_max_rows must not be negative")
	} else if n > MaxAnalysisRows {
		return fmt.Errorf("telemetry.store.analysis_max_rows %d exceeds the %d ceiling "+
			"(these are full records with bodies — a larger window is a memory ceiling, not a row count)",
			n, MaxAnalysisRows)
	}
	if s := c.Telemetry.Store.RetentionMaxAge; s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("telemetry.store.retention_max_age: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("telemetry.store.retention_max_age %q must be positive", s)
		}
	}
	seen := map[string]bool{}
	for i := range c.Telemetry.Exporters {
		e := &c.Telemetry.Exporters[i]
		if err := e.validate(); err != nil {
			name := e.Name
			if name == "" {
				name = fmt.Sprintf("#%d", i)
			}
			return fmt.Errorf("telemetry.exporters[%s]: %w", name, err)
		}
		if seen[e.Name] {
			return fmt.Errorf("telemetry.exporters: duplicate name %q", e.Name)
		}
		seen[e.Name] = true
	}
	// Compiled here so a bad pattern fails `optictrace validate` — and the
	// CI check that runs it — rather than at scan time in production.
	seenKind := map[string]bool{}
	for i, d := range c.Scan.Detectors {
		if _, err := scan.NewDetector(d.Kind, d.Severity, d.Why, d.Pattern, d.Verify); err != nil {
			name := d.Kind
			if name == "" {
				name = fmt.Sprintf("#%d", i)
			}
			return fmt.Errorf("scan.detectors[%s]: %w", name, err)
		}
		if seenKind[d.Kind] {
			return fmt.Errorf("scan.detectors: duplicate kind %q", d.Kind)
		}
		seenKind[d.Kind] = true
	}
	// Cross-rule check: a json label or body criterion aimed at something
	// another rule redacts.
	redacted := c.redactedJSONPaths()
	for i := range c.Rules {
		r := &c.Rules[i]
		for key, src := range r.Labels {
			ls, err := ParseLabelSource(src)
			if err != nil || !ls.NeedsBody() {
				continue
			}
			jp := "$." + strings.Join(ls.JSONPath, ".")
			if redacted[jp] {
				return fmt.Errorf("rule %s: labels.%s reads %s, which another rule redacts — "+
					"the label would be \"[REDACTED]\", and using redacted data as a "+
					"dimension is what redaction exists to prevent", r.Name, key, jp)
			}
		}
		for jp := range r.Match.Body {
			if redacted[jp] {
				return fmt.Errorf("rule %s: match.body cannot key on %s, which another "+
					"rule redacts — the criterion would only ever see \"[REDACTED]\"",
					r.Name, jp)
			}
		}
	}
	for i := range c.Rules {
		if err := c.Rules[i].validate(); err != nil {
			name := c.Rules[i].Name
			if name == "" {
				name = fmt.Sprintf("#%d", i)
			}
			return fmt.Errorf("rule %s: %w", name, err)
		}
	}
	return nil
}

func (e *ExporterCfg) validate() error {
	if e.Name == "" {
		return fmt.Errorf("name is required")
	}
	switch e.Type {
	case "file":
		if e.Path == "" {
			return fmt.Errorf("type file requires path")
		}
	case "webhook", "otlp":
		u, err := url.Parse(e.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("type %s requires a valid absolute url, got %q", e.Type, e.URL)
		}
	case "command":
		if len(e.Command) == 0 {
			return fmt.Errorf("type command requires command: [executable, args...]")
		}
	default:
		// An out-of-tree exporter registered via ext.RegisterExporter is a
		// valid type. Its own keys live under `settings`, which the core does
		// not validate — the plugin owns that.
		if _, ok := ext.LookupExporter(e.Type); !ok {
			known := append([]string{"file", "webhook", "command", "otlp"},
				ext.RegisteredExporters()...)
			return fmt.Errorf("unknown type %q (%s)", e.Type, strings.Join(known, ", "))
		}
	}
	if e.FlushInterval != "" {
		if _, err := time.ParseDuration(e.FlushInterval); err != nil {
			return fmt.Errorf("flush_interval: %w", err)
		}
	}
	// Apply defaults post-validation so runtime code never re-checks.
	if e.BatchSize <= 0 {
		e.BatchSize = 50
	}
	if e.FlushInterval == "" {
		e.FlushInterval = "3s"
	}
	if e.QueueSize <= 0 {
		e.QueueSize = 1024
	}
	if e.MaxSizeMB <= 0 {
		e.MaxSizeMB = 100
	}
	return nil
}

// FlushEvery returns the parsed flush interval (validated at load time).
func (e *ExporterCfg) FlushEvery() time.Duration {
	d, _ := time.ParseDuration(e.FlushInterval)
	return d
}

func (r *Rule) validate() error {
	if r.Match.Path == "" {
		return fmt.Errorf("match.path is required")
	}
	if !strings.HasPrefix(r.Match.Path, "/") {
		return fmt.Errorf("match.path %q must start with '/'", r.Match.Path)
	}
	for i, m := range r.Match.Methods {
		upper := strings.ToUpper(m)
		if !validMethods[upper] {
			return fmt.Errorf("match.methods[%d]: unknown HTTP method %q", i, m)
		}
		r.Match.Methods[i] = upper // normalize once, at load time
	}
	for _, f := range r.Restrict {
		switch f {
		case FieldRequestBody, FieldResponseBody, FieldHeaders, FieldQuery:
		default:
			return fmt.Errorf("restrict: unknown field %q (valid: request_body, response_body, headers, query)", f)
		}
	}
	if r.Redact != nil {
		for _, p := range r.Redact.JSONFields {
			if !strings.HasPrefix(p, "$.") || len(p) <= 2 {
				return fmt.Errorf("redact.json_fields: %q must be a dotted path starting with '$.'", p)
			}
		}
	}
	for key, src := range r.Labels {
		// Parsed by the engine's own parser so validation and runtime cannot
		// disagree about the grammar — a rule that validates but never fires
		// is the worst failure mode for a config-driven product.
		if _, err := ParseLabelSource(src); err != nil {
			return fmt.Errorf("labels.%s: %w", key, err)
		}
	}
	// A json label reading a field that some rule redacts would copy the value
	// into a Prometheus label and the stored labels map — routing around the
	// very rule protecting it. Extraction happens post-redaction so the label
	// would read "[REDACTED]" rather than leak, but silently producing a
	// useless label is its own bug, so say so at load time.
	for name, pat := range r.Match.Body {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("match.body[%s]: %w", name, err)
		}
		if !strings.HasPrefix(name, "$.") {
			return fmt.Errorf("match.body: key %q must be a dotted path starting with '$.'", name)
		}
	}
	for name, pat := range r.Match.Headers {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("match.headers.%s: %w", name, err)
		}
	}
	for name, pat := range r.Match.Query {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("match.query.%s: %w", name, err)
		}
	}
	if r.Sample != nil && (*r.Sample <= 0 || *r.Sample > 1) {
		return fmt.Errorf("sample %v must be in (0, 1]", *r.Sample)
	}
	if err := r.Logs.validate(); err != nil {
		return err
	}
	for name, path := range r.Meter {
		if !strings.HasPrefix(path, "$.") || len(path) <= 2 {
			return fmt.Errorf("meter.%s: %q must be a dotted path starting with '$.'", name, path)
		}
	}
	if r.KeepSlowerThan != "" {
		d, err := time.ParseDuration(r.KeepSlowerThan)
		if err != nil {
			return fmt.Errorf("keep_slower_than: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("keep_slower_than %q must be positive", r.KeepSlowerThan)
		}
	}
	return nil
}

// SlowerThan returns the parsed tail-sampling latency threshold (0 = unset).
// Validated at load time, so parse errors are impossible here.
func (r *Rule) SlowerThan() time.Duration {
	if r.KeepSlowerThan == "" {
		return 0
	}
	d, _ := time.ParseDuration(r.KeepSlowerThan)
	return d
}

// MaxAge returns the parsed age-based retention window (0 = disabled).
func (s *StoreCfg) MaxAge() time.Duration {
	if s.RetentionMaxAge == "" {
		return 0
	}
	d, _ := time.ParseDuration(s.RetentionMaxAge)
	return d
}

// LabelValueCap resolves the cardinality guard (0 = disabled).
func (m *Metrics) LabelValueCap() int {
	if m.MaxLabelValues == nil {
		return 500
	}
	if *m.MaxLabelValues < 0 {
		return 0
	}
	return *m.MaxLabelValues
}

// Bool resolves an optional flag against the opt-out default (true).
func Bool(v *bool) bool {
	if v == nil {
		return true
	}
	return *v
}
