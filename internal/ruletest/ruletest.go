// Package ruletest runs assertions about optic.yaml against the real rule
// engine, with no server and no network.
//
// Governance rules are security-critical but, until now, verifiable only by
// eyeball or by pushing live traffic through a running agent. That makes them
// frightening to refactor: nobody wants to reorder rules and discover the
// consequence in production logs. A test file turns "I think this still
// redacts" into something CI can prove.
package ruletest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dwarka-prasad/optictrace/internal/engine"
)

// Case is one fixture: a request, and what the policy should do with it.
type Case struct {
	Name    string  `yaml:"name"`
	Request Request `yaml:"request"`
	Expect  Expect  `yaml:"expect"`
}

type Request struct {
	Method   string            `yaml:"method"`
	Path     string            `yaml:"path"`
	Headers  map[string]string `yaml:"headers"`
	Body     any               `yaml:"body"`     // parsed YAML/JSON object
	Response any               `yaml:"response"` // upstream response body
	Status   int               `yaml:"status"`   // response status (tail sampling)
	TookMS   float64           `yaml:"took_ms"`  // elapsed ms (tail sampling)
}

// Expect holds assertions. Every field is optional — a case asserts only
// what it cares about, so tests stay readable and don't break on unrelated
// config changes.
type Expect struct {
	MatchedRules    *[]string          `yaml:"matched_rules"`
	Route           *string            `yaml:"route"`
	CapturesReqBody *bool              `yaml:"captures_request_body"`
	CapturesResBody *bool              `yaml:"captures_response_body"`
	CapturesHeaders *bool              `yaml:"captures_headers"`
	StoredReqBody   *string            `yaml:"stored_request_body"`
	StoredResBody   *string            `yaml:"stored_response_body"`
	RedactedHeaders *[]string          `yaml:"redacted_headers"`
	Labels          map[string]string  `yaml:"labels"`
	Meters          map[string]float64 `yaml:"meters"`
	KeepsBody       *bool              `yaml:"keeps_body"`
	// NotContains asserts that a string appears nowhere in the governed
	// record — the leak assertion, and the one most worth writing.
	NotContains []string `yaml:"not_contains"`
}

// Failure is one unmet assertion.
type Failure struct {
	Case   string
	Assert string
	Want   string
	Got    string
}

// Result summarizes a run.
type Result struct {
	Total    int
	Passed   int
	Failures []Failure
}

// Load reads a test file (a bare list of cases, or {cases: [...]}).
func Load(path string) ([]Case, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cases []Case
	if err := yaml.Unmarshal(raw, &cases); err == nil && len(cases) > 0 {
		return cases, nil
	}
	var wrapper struct {
		Cases []Case `yaml:"cases"`
	}
	if err := yaml.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(wrapper.Cases) == 0 {
		return nil, fmt.Errorf("%s contains no test cases", path)
	}
	return wrapper.Cases, nil
}

// governedDoc marshals a case's body, redacts it under the policy, and parses
// the result — the same order the interceptor uses, so a test asserts what
// production would actually record.
func governedDoc(body any, p *engine.Policy) (any, bool) {
	if body == nil {
		return nil, false
	}
	raw, err := json.Marshal(normalizeYAML(body))
	if err != nil {
		return nil, false
	}
	if red, ok := p.RedactJSONBody(raw); ok {
		raw = red
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false
	}
	return doc, true
}

// Run evaluates every case against the engine.
func Run(eng *engine.Engine, cases []Case) *Result {
	res := &Result{Total: len(cases)}
	for i, c := range cases {
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("case #%d", i+1)
		}
		if fails := runCase(eng, name, c); len(fails) > 0 {
			res.Failures = append(res.Failures, fails...)
		} else {
			res.Passed++
		}
	}
	return res
}

func runCase(eng *engine.Engine, name string, c Case) []Failure {
	var fails []Failure
	fail := func(assert, want, got string) {
		fails = append(fails, Failure{Case: name, Assert: assert, Want: want, Got: got})
	}

	method := strings.ToUpper(c.Request.Method)
	if method == "" {
		method = http.MethodGet
	}
	path := c.Request.Path
	query := ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	hdr := http.Header{}
	for k, v := range c.Request.Headers {
		hdr.Set(k, v)
	}
	// The test case's headers and query are part of the match context, so a
	// `optictrace test` case can assert that a tagging rule fires — which is
	// the whole point of being able to test rules before shipping them.
	q, _ := url.ParseQuery(query)
	attrs := engine.Attrs{Method: method, Path: path, Headers: hdr, Query: q}
	policy := eng.EvaluateAttrs(attrs)

	// Two passes, mirroring the proxy: rules keyed on the body cannot be
	// decided until the body is available, and the body is redacted before
	// anything reads it so a criterion or label can never see a masked field.
	//
	// Without this a rule using match.body or a json: label could not be
	// tested at all — and an untestable governance rule is one nobody can
	// trust, which defeats the point of this file existing.
	reqBody, reqKnown := governedDoc(c.Request.Body, &policy)
	if reqKnown {
		attrs.Body, attrs.BodyKnown = reqBody, true
		policy = eng.EvaluateAttrs(attrs)
	}

	// --- matched rules ---------------------------------------------------
	if c.Expect.MatchedRules != nil {
		want := append([]string{}, *c.Expect.MatchedRules...)
		got := append([]string{}, policy.MatchedRules...)
		sort.Strings(want)
		sort.Strings(got)
		if strings.Join(want, ",") != strings.Join(got, ",") {
			fail("matched_rules", fmt.Sprint(*c.Expect.MatchedRules), fmt.Sprint(policy.MatchedRules))
		}
	}
	if c.Expect.Route != nil {
		got := policy.RoutePattern
		if got == "" {
			got = engine.NormalizeRoute(path)
		}
		if got != *c.Expect.Route {
			fail("route", *c.Expect.Route, got)
		}
	}

	// --- capture flags ----------------------------------------------------
	checkBool := func(label string, want *bool, got bool) {
		if want != nil && *want != got {
			fail(label, fmt.Sprint(*want), fmt.Sprint(got))
		}
	}
	checkBool("captures_request_body", c.Expect.CapturesReqBody, policy.CaptureRequestBody)
	checkBool("captures_response_body", c.Expect.CapturesResBody, policy.CaptureResponseBody)
	checkBool("captures_headers", c.Expect.CapturesHeaders, policy.CaptureHeaders)

	// --- governed bodies ---------------------------------------------------
	reqStored := governBody(&policy, c.Request.Body, policy.CaptureRequestBody)
	resStored := governBody(&policy, c.Request.Response, policy.CaptureResponseBody)

	if c.Expect.StoredReqBody != nil && !jsonEquivalent(*c.Expect.StoredReqBody, reqStored) {
		fail("stored_request_body", *c.Expect.StoredReqBody, reqStored)
	}
	if c.Expect.StoredResBody != nil && !jsonEquivalent(*c.Expect.StoredResBody, resStored) {
		fail("stored_response_body", *c.Expect.StoredResBody, resStored)
	}

	// --- headers -----------------------------------------------------------
	var sanitized map[string]string
	if policy.CaptureHeaders {
		sanitized = policy.SanitizeHeaders(hdr)
	}
	if c.Expect.RedactedHeaders != nil {
		for _, want := range *c.Expect.RedactedHeaders {
			canonical := http.CanonicalHeaderKey(want)
			got, present := sanitized[canonical]
			switch {
			case !policy.CaptureHeaders:
				// headers aren't captured at all, which is stricter than redaction
			case !present:
				fail("redacted_headers", canonical+" present and masked", canonical+" absent from fixture")
			case got != engine.RedactedPlaceholder:
				fail("redacted_headers", canonical+"=[REDACTED]", canonical+"="+got)
			}
		}
	}

	// --- labels -------------------------------------------------------------
	if len(c.Expect.Labels) > 0 {
		req := &http.Request{Header: hdr, URL: &url.URL{Path: path, RawQuery: query}}
		for name, want := range c.Expect.Labels {
			src, ok := policy.Labels[name]
			if !ok {
				fail("labels."+name, want, "(label not defined by any matching rule)")
				continue
			}
			got := src.Value(req)
			// json / json_response sources read a body, not the request line.
			if src.Kind == "json" {
				got = src.ValueFromBody(reqBody)
			} else if src.Kind == "json_response" {
				resDoc, _ := governedDoc(c.Request.Response, &policy)
				got = src.ValueFromBody(resDoc)
			}
			if got != want {
				fail("labels."+name, want, got)
			}
		}
	}

	// --- meters --------------------------------------------------------------
	if len(c.Expect.Meters) > 0 {
		var meters map[string]float64
		if c.Request.Response != nil {
			if raw, err := json.Marshal(c.Request.Response); err == nil {
				meters = policy.ExtractMeters(raw)
			}
		}
		for name, want := range c.Expect.Meters {
			got, ok := meters[name]
			if !ok {
				fail("meters."+name, fmt.Sprint(want), "(not extracted)")
			} else if got != want {
				fail("meters."+name, fmt.Sprint(want), fmt.Sprint(got))
			}
		}
	}

	// --- tail sampling --------------------------------------------------------
	if c.Expect.KeepsBody != nil {
		status := c.Request.Status
		if status == 0 {
			status = http.StatusOK
		}
		elapsed := time.Duration(c.Request.TookMS * float64(time.Millisecond))
		// drew=false asks the sharper question: would tail rules rescue a
		// request that the uniform draw discarded?
		got := policy.KeepBody(false, status, elapsed)
		if got != *c.Expect.KeepsBody {
			fail("keeps_body", fmt.Sprint(*c.Expect.KeepsBody), fmt.Sprint(got))
		}
	}

	// --- leak assertion ---------------------------------------------------------
	if len(c.Expect.NotContains) > 0 {
		haystack := reqStored + "\x00" + resStored
		if sanitized != nil {
			for k, v := range sanitized {
				haystack += "\x00" + k + "=" + v
			}
		}
		for _, needle := range c.Expect.NotContains {
			if needle != "" && strings.Contains(haystack, needle) {
				fail("not_contains", "absent: "+needle, "found in governed record")
			}
		}
	}
	return fails
}

// governBody applies the policy exactly as the proxy would: nothing at all
// when capture is restricted, otherwise the redacted JSON form.
func governBody(p *engine.Policy, body any, captured bool) string {
	if body == nil || !captured {
		return ""
	}
	raw, err := json.Marshal(normalizeYAML(body))
	if err != nil {
		return ""
	}
	redacted, ok := p.RedactJSONBody(raw)
	if !ok {
		return string(raw)
	}
	return string(redacted)
}

// normalizeYAML converts map[any]any (which older YAML shapes produce) into
// map[string]any so encoding/json can handle it.
func normalizeYAML(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprint(k)] = normalizeYAML(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalizeYAML(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalizeYAML(val)
		}
		return out
	default:
		return v
	}
}

// jsonEquivalent compares two JSON strings by structure, so key order and
// whitespace in the fixture don't matter.
func jsonEquivalent(want, got string) bool {
	if strings.TrimSpace(want) == strings.TrimSpace(got) {
		return true
	}
	var a, b any
	if json.Unmarshal([]byte(want), &a) != nil || json.Unmarshal([]byte(got), &b) != nil {
		return false
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
