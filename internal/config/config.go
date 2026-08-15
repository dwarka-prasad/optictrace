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
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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
	Rules     []Rule    `yaml:"rules"`
}

// Telemetry configures the observability sinks: the admin/metrics endpoint,
// Prometheus exposition, console logging, and the payload store.
type Telemetry struct {
	// AdminListen is the address of the admin server (/metrics, dashboard,
	// query APIs). Kept separate from proxied traffic on purpose: you can
	// firewall it independently. Default ":9095".
	AdminListen string        `yaml:"admin_listen"`
	ConsoleLog  *bool         `yaml:"console_log"` // structured stdout telemetry (default true)
	Metrics     Metrics       `yaml:"metrics"`
	Store       StoreCfg      `yaml:"store"`
	Exporters   []ExporterCfg `yaml:"exporters"`
	Billing     *Billing      `yaml:"billing"`
	Auth        *AdminAuth    `yaml:"auth"`
	TLS         *AdminTLS     `yaml:"tls"`
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
	Type string `yaml:"type"` // "file" | "webhook" | "command"

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
	Driver string `yaml:"driver"` // "sqlite" (default) or "none"
	// DSN is the SQLite file path. Default "optictrace.db".
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
}

// Service describes the proxied service (standalone sidecar mode). When
// OpticTrace is embedded as middleware, Listen/Upstream are unused.
type Service struct {
	Name     string `yaml:"name"`
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`
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
	Name     string            `yaml:"name"`
	Match    Match             `yaml:"match"`
	Restrict []CaptureField    `yaml:"restrict"`
	Redact   *Redact           `yaml:"redact"`
	Labels   map[string]string `yaml:"labels"`
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
}

// Match selects requests by path glob and (optionally) HTTP methods.
type Match struct {
	Path    string   `yaml:"path"`
	Methods []string `yaml:"methods"`
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
		t.AdminListen = ":9095"
	}
	if t.Store.Driver == "" {
		t.Store.Driver = "sqlite"
	}
	if t.Store.DSN == "" {
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

var validMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
}

// Validate enforces schema invariants so the runtime engine can trust the config.
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
	switch c.Telemetry.Store.Driver {
	case "sqlite", "none":
	default:
		return fmt.Errorf("telemetry.store.driver %q is not supported (sqlite, none)", c.Telemetry.Store.Driver)
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
	case "webhook":
		u, err := url.Parse(e.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("type webhook requires a valid absolute url, got %q", e.URL)
		}
	case "command":
		if len(e.Command) == 0 {
			return fmt.Errorf("type command requires command: [executable, args...]")
		}
	default:
		return fmt.Errorf("unknown type %q (file, webhook, command)", e.Type)
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
		kind, _, ok := strings.Cut(src, ":")
		if !ok || (kind != "header" && kind != "query") {
			return fmt.Errorf("labels.%s: source %q must be 'header:<Name>' or 'query:<name>'", key, src)
		}
	}
	if r.Sample != nil && (*r.Sample <= 0 || *r.Sample > 1) {
		return fmt.Errorf("sample %v must be in (0, 1]", *r.Sample)
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
