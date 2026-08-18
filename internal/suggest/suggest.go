// Package suggest proposes governance rules for traffic that has none.
//
// It is the complement to internal/scan, and the split matters:
//
//	scan     looks at VALUES — "this string is a Luhn-valid card number"
//	suggest  looks at NAMES  — "a field called password should be masked"
//
// Neither subsumes the other. A field named `password` holding "hunter2" trips
// no value detector, and a card number in a field called `ref` trips no name
// heuristic. Running both is what makes the coverage meaningful.
//
// Suggestions are proposals, never applied automatically: governance changes
// belong in a reviewed commit, not in a tool's side effects.
package suggest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Confidence expresses how sure the heuristic is, so a reviewer can triage.
const (
	High   = "high"   // the name is unambiguous (password, ssn, card_number)
	Medium = "medium" // the name is commonly sensitive (email, phone, address)
	Low    = "low"    // worth a look (anything *_id paired with a person)
)

// nameRule maps a field-name pattern to a proposed action.
type nameRule struct {
	match      func(string) bool
	confidence string
	why        string
}

func contains(subs ...string) func(string) bool {
	return func(name string) bool {
		n := strings.ToLower(name)
		for _, s := range subs {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}
}

// exact matches the LAST path segment, which avoids flagging a whole subtree
// because one ancestor happened to be called "account".
func exact(names ...string) func(string) bool {
	return func(name string) bool {
		n := strings.ToLower(name)
		if i := strings.LastIndex(n, "."); i >= 0 {
			n = n[i+1:]
		}
		for _, s := range names {
			if n == s {
				return true
			}
		}
		return false
	}
}

var fieldRules = []nameRule{
	{contains("password", "passwd", "secret", "private_key", "privatekey"), High,
		"credentials must never be stored in telemetry"},
	{contains("api_key", "apikey", "access_token", "refresh_token", "auth_token", "bearer"), High,
		"a token in telemetry is a replayable credential"},
	{contains("card_number", "cardnumber", "card_no"), High,
		"payment card data is PCI-DSS scope"},
	// `pan`, `cvv` and `cvc` are matched EXACTLY, never as substrings:
	// "pan" appears inside ordinary words like "expand", "company" and
	// "panel", and a heuristic that flags those gets muted — at which point
	// it protects nothing.
	{exact("pan", "cvv", "cvc"), High,
		"payment card data is PCI-DSS scope"},
	{contains("ssn", "social_security", "national_id", "aadhaar", "tax_id"), High,
		"national identifiers are regulated personal data"},
	{exact("iban", "account_number", "routing_number", "sort_code"), High,
		"bank account details enable fraud if leaked"},
	{contains("email", "e_mail"), Medium,
		"email addresses are personal data under GDPR and similar regimes"},
	{contains("phone", "mobile", "msisdn"), Medium,
		"phone numbers are personal data"},
	{contains("address", "postcode", "zip_code", "street"), Medium,
		"postal addresses are personal data"},
	{contains("dob", "date_of_birth", "birthdate"), Medium,
		"dates of birth are personal data and aid identity theft"},
	{contains("latitude", "longitude", "geo_"), Medium,
		"precise location is sensitive personal data"},
	{exact("name", "first_name", "last_name", "full_name"), Low,
		"names are personal data; mask if this identifies end users"},
	{contains("session", "cookie"), Medium,
		"session identifiers can be replayed"},
}

var headerRules = []nameRule{
	{contains("authorization", "x-api-key", "x-auth", "token"), High,
		"authentication headers are credentials"},
	{contains("cookie", "set-cookie"), High,
		"cookies carry session credentials"},
	{contains("x-forwarded-for", "x-real-ip"), Low,
		"client IPs are personal data in several jurisdictions"},
}

// Suggestion is one proposed governance change.
type Suggestion struct {
	Route      string   `json:"route"`
	Methods    []string `json:"methods,omitempty"`
	Kind       string   `json:"kind"` // json_field | header | query_param
	Field      string   `json:"field"`
	Confidence string   `json:"confidence"`
	Why        string   `json:"why"`
	Seen       int      `json:"seen"`
	// AlreadyGoverned is true when a rule already covers this field, in which
	// case the suggestion is informational rather than actionable.
	AlreadyGoverned bool `json:"already_governed"`
}

// Report groups suggestions by route so the output maps to rule blocks.
type Report struct {
	Scanned     int          `json:"records_scanned"`
	Suggestions []Suggestion `json:"suggestions"`
}

// Actionable returns only suggestions not already covered by existing rules.
func (r *Report) Actionable() []Suggestion {
	var out []Suggestion
	for _, s := range r.Suggestions {
		if !s.AlreadyGoverned {
			out = append(out, s)
		}
	}
	return out
}

type key struct{ route, kind, field string }

// Records analyses captured traffic and proposes rules. eng is the currently
// loaded engine, used to mark fields that existing rules already handle.
func Records(records []store.Record, eng *engine.Engine) *Report {
	agg := map[key]*Suggestion{}

	note := func(rec *store.Record, kind, field, confidence, why string, governed bool) {
		k := key{rec.Route, kind, field}
		s := agg[k]
		if s == nil {
			s = &Suggestion{
				Route: rec.Route, Kind: kind, Field: field,
				Confidence: confidence, Why: why, AlreadyGoverned: governed,
			}
			agg[k] = s
		}
		s.Seen++
	}

	for i := range records {
		rec := &records[i]
		policy := eng.EvaluateAttrs(attrsOfRecord(rec))

		// --- body fields -------------------------------------------------
		for _, body := range []string{rec.RequestBody, rec.ResponseBody} {
			for _, field := range jsonFieldPaths(body) {
				if r := matchRules(fieldRules, field); r != nil {
					note(rec, "json_field", field, r.confidence, r.why,
						fieldGoverned(&policy, field))
				}
			}
		}
		// --- headers -----------------------------------------------------
		if policy.CaptureHeaders {
			for name := range rec.RequestHeaders {
				if r := matchRules(headerRules, name); r != nil {
					_, masked := policy.RedactHeaders[name]
					note(rec, "header", name, r.confidence, r.why, masked)
				}
			}
		}
		// --- query params --------------------------------------------------
		for _, name := range queryKeys(rec.Query) {
			if r := matchRules(append(fieldRules, headerRules...), name); r != nil {
				_, masked := policy.RedactQuery[strings.ToLower(name)]
				note(rec, "query_param", name, r.confidence, r.why, masked)
			}
		}
	}

	out := make([]Suggestion, 0, len(agg))
	for _, s := range agg {
		out = append(out, *s)
	}
	rank := map[string]int{High: 0, Medium: 1, Low: 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Confidence] != rank[out[j].Confidence] {
			return rank[out[i].Confidence] < rank[out[j].Confidence]
		}
		if out[i].Route != out[j].Route {
			return out[i].Route < out[j].Route
		}
		return out[i].Field < out[j].Field
	})
	return &Report{Scanned: len(records), Suggestions: out}
}

// YAML renders actionable suggestions as optic.yaml rule blocks, ready to
// paste. Grouped per route so the output mirrors how rules are written.
func (r *Report) YAML() string {
	actionable := r.Actionable()
	if len(actionable) == 0 {
		return ""
	}
	byRoute := map[string][]Suggestion{}
	var routes []string
	for _, s := range actionable {
		if _, seen := byRoute[s.Route]; !seen {
			routes = append(routes, s.Route)
		}
		byRoute[s.Route] = append(byRoute[s.Route], s)
	}
	sort.Strings(routes)

	var b strings.Builder
	b.WriteString("# Proposed by `optictrace suggest` — review before committing.\n")
	b.WriteString("# These are NAME-based heuristics; pair them with `optictrace scan`,\n")
	b.WriteString("# which inspects values, for the other half of the coverage.\n")
	for _, route := range routes {
		fields, headers, queries := split(byRoute[route])
		fmt.Fprintf(&b, "\n  - name: govern-%s\n", slug(route))
		fmt.Fprintf(&b, "    match:\n      path: %q\n", route)
		b.WriteString("    redact:\n")
		if len(headers) > 0 {
			fmt.Fprintf(&b, "      headers: [%s]\n", strings.Join(headers, ", "))
		}
		if len(queries) > 0 {
			fmt.Fprintf(&b, "      query_params: [%s]\n", strings.Join(queries, ", "))
		}
		if len(fields) > 0 {
			b.WriteString("      json_fields:\n")
			for _, f := range fields {
				fmt.Fprintf(&b, "        - %q\n", f)
			}
		}
	}
	return b.String()
}

func split(ss []Suggestion) (fields, headers, queries []string) {
	seen := map[string]bool{}
	for _, s := range ss {
		if seen[s.Kind+s.Field] {
			continue
		}
		seen[s.Kind+s.Field] = true
		switch s.Kind {
		case "header":
			headers = append(headers, s.Field)
		case "query_param":
			queries = append(queries, s.Field)
		default:
			fields = append(fields, s.Field)
		}
	}
	sort.Strings(fields)
	sort.Strings(headers)
	sort.Strings(queries)
	return
}

func matchRules(rules []nameRule, name string) *nameRule {
	for i := range rules {
		if rules[i].match(name) {
			return &rules[i]
		}
	}
	return nil
}

// fieldGoverned reports whether an existing redaction path already covers a
// dotted field path, so suggestions don't repeat work already done.
func fieldGoverned(p *engine.Policy, field string) bool {
	target := strings.TrimPrefix(field, "$.")
	for _, path := range p.RedactJSONPaths {
		if pathCovers(path, strings.Split(target, ".")) {
			return true
		}
	}
	return false
}

func pathCovers(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	switch pattern[0] {
	case "**":
		if len(pattern) == 1 {
			return true
		}
		for i := 0; i <= len(segs); i++ {
			if pathCovers(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	case "*":
		if len(segs) == 0 {
			return false
		}
		return pathCovers(pattern[1:], segs[1:])
	default:
		if len(segs) == 0 || pattern[0] != segs[0] {
			return false
		}
		return pathCovers(pattern[1:], segs[1:])
	}
}

// jsonFieldPaths flattens a stored JSON body into dotted paths.
func jsonFieldPaths(body string) []string {
	if body == "" || (body[0] != '{' && body[0] != '[') {
		return nil
	}
	var doc any
	if json.Unmarshal([]byte(body), &doc) != nil {
		return nil
	}
	var out []string
	var walk func(any, string, int)
	walk = func(n any, prefix string, depth int) {
		if depth > 10 {
			return
		}
		switch v := n.(type) {
		case map[string]any:
			for k, child := range v {
				p := prefix + "." + k
				out = append(out, p)
				walk(child, p, depth+1)
			}
		case []any:
			for _, child := range v {
				walk(child, prefix, depth+1)
			}
		}
	}
	walk(doc, "$", 0)
	return out
}

func queryKeys(q string) []string {
	if q == "" {
		return nil
	}
	var out []string
	for _, pair := range strings.Split(q, "&") {
		if k, _, ok := strings.Cut(pair, "="); ok && k != "" {
			out = append(out, k)
		}
	}
	return out
}

func slug(route string) string {
	s := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		if r >= 'A' && r <= 'Z' {
			return r - 'A' + 'a'
		}
		return '-'
	}, route)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if s == "" {
		s = "route"
	}
	return s
}

// attrsOfRecord rebuilds match context from a stored record, so rules using
// match.headers or match.query are evaluated the same way here as they were
// live. Without this the PR bot would report a tagging rule as inert.
func attrsOfRecord(rec *store.Record) engine.Attrs {
	a := engine.Attrs{Method: rec.Method, Path: rec.Path}
	if len(rec.RequestHeaders) > 0 {
		a.Headers = make(http.Header, len(rec.RequestHeaders))
		for k, v := range rec.RequestHeaders {
			a.Headers.Set(k, v)
		}
	}
	if rec.Query != "" {
		if q, err := url.ParseQuery(rec.Query); err == nil {
			a.Query = q
		}
	}
	return a
}
