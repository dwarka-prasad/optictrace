package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Finding groups every occurrence of one sensitive-value class at one place
// in the API — a route plus a field path. Grouping is what makes the report
// actionable: "17 hits of credit-card at $.payment.pan on POST
// /api/v1/orders/**" maps to exactly one line of optic.yaml.
type Finding struct {
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Why      string    `json:"why"`
	Method   string    `json:"method"`
	Route    string    `json:"route"`
	Location string    `json:"location"` // request_body | response_body | request_headers | response_headers
	Field    string    `json:"field"`    // JSON path or header name
	Count    int       `json:"count"`
	FirstAt  time.Time `json:"first_seen"`
	LastAt   time.Time `json:"last_seen"`
	Sample   string    `json:"masked_sample"` // never the raw value
	// Suggest is the optic.yaml fragment that would have prevented this.
	Suggest string `json:"suggested_rule"`
}

// Report is a complete scan result.
type Report struct {
	Scanned  int       `json:"records_scanned"`
	Since    time.Time `json:"since"`
	Findings []Finding `json:"findings"`
}

// Counts summarizes findings by severity.
func (r *Report) Counts() (critical, high, medium int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SevCritical:
			critical++
		case SevHigh:
			high++
		case SevMedium:
			medium++
		}
	}
	return
}

// HasAtLeast reports whether any finding meets or exceeds a severity — the
// CI gate. Medium (personal data) is common enough that gating on critical
// or high is the sane default.
func (r *Report) HasAtLeast(sev string) bool {
	rank := map[string]int{SevMedium: 1, SevHigh: 2, SevCritical: 3}
	want := rank[sev]
	for _, f := range r.Findings {
		if rank[f.Severity] >= want {
			return true
		}
	}
	return false
}

type key struct{ kind, method, route, location, field string }

// Records scans stored telemetry for values that look sensitive despite
// having passed governance.
func Records(records []store.Record, since time.Time) *Report {
	agg := map[key]*Finding{}

	record := func(rec *store.Record, location, field string, matches []Match) {
		for _, m := range matches {
			k := key{m.Kind, rec.Method, rec.Route, location, field}
			f := agg[k]
			if f == nil {
				f = &Finding{
					Kind: m.Kind, Severity: m.Severity, Why: m.Why,
					Method: rec.Method, Route: rec.Route,
					Location: location, Field: field,
					Sample: m.Masked, FirstAt: rec.Time,
					Suggest: suggest(location, field),
				}
				agg[k] = f
			}
			f.Count++
			if rec.Time.Before(f.FirstAt) {
				f.FirstAt = rec.Time
			}
			if rec.Time.After(f.LastAt) {
				f.LastAt = rec.Time
			}
		}
	}

	for i := range records {
		rec := &records[i]
		scanBody(rec.RequestBody, func(field, val string) {
			record(rec, "request_body", field, Find(val))
		})
		scanBody(rec.ResponseBody, func(field, val string) {
			record(rec, "response_body", field, Find(val))
		})
		if rec.Query != "" {
			if vals, err := url.ParseQuery(rec.Query); err == nil {
				for name, list := range vals {
					for _, v := range list {
						record(rec, "query", name, Find(v))
					}
				}
			}
		}
		for name, val := range rec.RequestHeaders {
			record(rec, "request_headers", name, Find(val))
		}
		for name, val := range rec.ResponseHeaders {
			record(rec, "response_headers", name, Find(val))
		}
	}

	out := make([]Finding, 0, len(agg))
	for _, f := range agg {
		out = append(out, *f)
	}
	rank := map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Field < out[j].Field
	})
	return &Report{Scanned: len(records), Since: since, Findings: out}
}

// scanBody walks a stored JSON body, calling visit with each leaf's dotted
// path and string form. Non-JSON bodies are scanned whole under "(raw)".
func scanBody(body string, visit func(field, value string)) {
	if body == "" {
		return
	}
	var doc any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		visit("(raw)", body)
		return
	}
	walk(doc, "$", visit, 0)
}

func walk(node any, path string, visit func(string, string), depth int) {
	if depth > 12 {
		return
	}
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			walk(child, path+"."+k, visit, depth+1)
		}
	case []any:
		// Array indices are noise in a report: every element of `items`
		// shares one field path so findings aggregate instead of fragmenting.
		for _, child := range v {
			walk(child, path, visit, depth+1)
		}
	case string:
		visit(path, v)
	case float64:
		// Numeric card numbers are a real pattern in sloppy payloads.
		visit(path, formatNumber(v))
	}
}

func formatNumber(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%v", f)
}

// suggest emits the optic.yaml fragment that would have masked this value,
// so a finding converts into a fix by copy-paste.
func suggest(location, field string) string {
	switch location {
	case "query":
		return fmt.Sprintf("redact:\n  query_params: [%s]", field)
	case "request_headers", "response_headers":
		return fmt.Sprintf("redact:\n  headers: [%s]", field)
	default:
		if field == "(raw)" {
			return "restrict: [" + strings.TrimSuffix(location, "_body") + "_body]"
		}
		return fmt.Sprintf("redact:\n  json_fields: [%q]", field)
	}
}
