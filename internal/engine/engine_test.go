package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
)

const testYAML = `
version: 1
service:
  name: test
defaults:
  capture:
    request_body: true
    response_body: true
    headers: true
rules:
  - name: no-capture-on-auth
    match:
      path: "/api/v1/auth/**"
    restrict: [request_body, response_body, headers]
  - name: redact-payments
    match:
      path: "/api/v1/payments/**"
      methods: [POST]
    redact:
      headers: [Authorization]
      json_fields:
        - "$.credit_card.number"
        - "$.*.ssn"
    labels:
      tenant: "header:X-Tenant-ID"
`

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	cfg, err := config.Parse([]byte(testYAML))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return New(cfg)
}

func TestGlobMatching(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/api/v1/payments/**", "/api/v1/payments", true},            // ** matches zero segments
		{"/api/v1/payments/**", "/api/v1/payments/123/refund", true}, // ** matches many
		{"/api/v1/payments/*", "/api/v1/payments/123", true},         // * matches one
		{"/api/v1/payments/*", "/api/v1/payments/123/refund", false}, // * does not span
		{"/api/*/health", "/api/v2/health", true},
		{"/api/v1/user-*", "/api/v1/user-admin", true}, // shell pattern inside segment
		{"/webhooks/*", "/other", false},
	}
	for _, c := range cases {
		got := matchSegments(splitPath(c.pattern), splitPath(c.path))
		if got != c.want {
			t.Errorf("match(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestPolicyRestriction(t *testing.T) {
	e := mustEngine(t)

	p := e.Evaluate("POST", "/api/v1/auth/login")
	if p.CaptureRequestBody || p.CaptureResponseBody || p.CaptureHeaders {
		t.Errorf("auth route should have all capture disabled, got %+v", p)
	}
	if len(p.MatchedRules) != 1 || p.MatchedRules[0] != "no-capture-on-auth" {
		t.Errorf("unexpected matched rules: %v", p.MatchedRules)
	}

	// Unmatched route keeps opt-out defaults (capture everything).
	p = e.Evaluate("GET", "/healthz")
	if !p.CaptureRequestBody || !p.CaptureResponseBody || !p.CaptureHeaders {
		t.Errorf("default route should capture everything, got %+v", p)
	}
}

func TestPolicyMethodFilter(t *testing.T) {
	e := mustEngine(t)
	// Rule only applies to POST; GET on same path should carry no redactions.
	p := e.Evaluate("GET", "/api/v1/payments/charge")
	if len(p.RedactJSONPaths) != 0 {
		t.Errorf("GET should not match POST-only rule, got paths %v", p.RedactJSONPaths)
	}
}

func TestJSONRedaction(t *testing.T) {
	e := mustEngine(t)
	p := e.Evaluate("POST", "/api/v1/payments/charge")

	body := []byte(`{
		"amount": 4200,
		"credit_card": {"number": "4111111111111111", "cvv": "123"},
		"customer": {"ssn": "078-05-1120", "name": "Ada"}
	}`)
	out, ok := p.RedactJSONBody(body)
	if !ok {
		t.Fatal("expected JSON body to be redactable")
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("redacted output is not valid JSON: %v", err)
	}
	cc := doc["credit_card"].(map[string]any)
	if cc["number"] != RedactedPlaceholder {
		t.Errorf("credit_card.number not redacted: %v", cc["number"])
	}
	if cc["cvv"] != "123" {
		t.Errorf("cvv should be untouched (not in rules): %v", cc["cvv"])
	}
	cust := doc["customer"].(map[string]any)
	if cust["ssn"] != RedactedPlaceholder {
		t.Errorf("wildcard $.*.ssn did not redact customer.ssn: %v", cust["ssn"])
	}
	if cust["name"] != "Ada" || doc["amount"].(float64) != 4200 {
		t.Error("non-sensitive fields were modified")
	}
	if strings.Contains(string(out), "4111111111111111") {
		t.Error("raw card number leaked into redacted output")
	}
}

func TestDeepJSONRedaction(t *testing.T) {
	yaml := `
version: 1
rules:
  - match:
      path: "/**"
    redact:
      json_fields: ["$.**.card.number"]
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	p := New(cfg).Evaluate("POST", "/anything")

	body := []byte(`{
		"card": {"number": "1111"},
		"echo": {"nested": {"card": {"number": "2222"}}},
		"items": [{"card": {"number": "3333"}}]
	}`)
	out, ok := p.RedactJSONBody(body)
	if !ok {
		t.Fatal("expected redactable JSON")
	}
	s := string(out)
	for _, leaked := range []string{"1111", "2222", "3333"} {
		if strings.Contains(s, leaked) {
			t.Errorf("recursive descent missed card number %s: %s", leaked, s)
		}
	}
}

func TestHeaderRedaction(t *testing.T) {
	e := mustEngine(t)
	p := e.Evaluate("POST", "/api/v1/payments/charge")
	if _, ok := p.RedactHeaders["Authorization"]; !ok {
		t.Error("Authorization should be in the redaction set")
	}
}

func TestMeterExtraction(t *testing.T) {
	yaml := `
version: 1
rules:
  - match: { path: "/v1/**" }
    meter:
      tokens: "$.usage.total_tokens"
      items:  "$.results.count"
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	p := New(cfg).Evaluate("POST", "/v1/complete")

	body := []byte(`{
		"usage": {"total_tokens": 128, "prompt_tokens": 40},
		"results": [{"count": 3}, {"count": 4}]
	}`)
	m := p.ExtractMeters(body)
	if m["tokens"] != 128 {
		t.Errorf("tokens = %v, want 128", m["tokens"])
	}
	// Arrays traverse implicitly and matches sum.
	if m["items"] != 7 {
		t.Errorf("items = %v, want 7", m["items"])
	}
	// Missing meters are absent, not zero.
	if _, ok := p.ExtractMeters([]byte(`{"other": 1}`))["tokens"]; ok {
		t.Error("absent meter should not be reported")
	}
	// Non-matching route has no meters at all.
	other := New(cfg).Evaluate("GET", "/other")
	if got := other.ExtractMeters(body); got != nil {
		t.Errorf("unmatched route should not meter: %v", got)
	}
}

func TestQueryRedaction(t *testing.T) {
	yaml := `
version: 1
rules:
  - name: mask-query-creds
    match: { path: "/v1/**" }
    redact:
      query_params: [api_key, TOKEN]
  - name: no-query-on-admin
    match: { path: "/admin/**" }
    restrict: [query]
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	e := New(cfg)

	p := e.Evaluate("GET", "/v1/search")
	got := p.SanitizeQuery("q=shoes&api_key=secret123&page=2&token=abc")
	// Sorted for stability; listed params masked; case-insensitive match.
	want := "api_key=" + RedactedPlaceholder + "&page=2&q=shoes&token=" + RedactedPlaceholder
	if got != want {
		t.Errorf("SanitizeQuery:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "secret123") || strings.Contains(got, "abc") {
		t.Error("credential leaked through query sanitization")
	}

	// Restriction beats redaction: the query isn't captured at all.
	admin := e.Evaluate("GET", "/admin/panel")
	if admin.CaptureQuery {
		t.Error("restrict: [query] should disable query capture")
	}

	// Unparseable queries are dropped rather than stored raw.
	if out := p.SanitizeQuery("%zz"); !strings.Contains(out, "omitted") {
		t.Errorf("unparseable query should be omitted, got %q", out)
	}
	// Default posture captures queries.
	if !e.Evaluate("GET", "/other").CaptureQuery {
		t.Error("query capture should be on by default")
	}
}

func TestConfigValidationErrors(t *testing.T) {
	bad := []string{
		"version: 2", // unsupported version
		"version: 1\nrules:\n  - match:\n      path: x",                                         // path without leading /
		"version: 1\nrules:\n  - match:\n      path: /a\n    restrict: [bodyz]",                 // bad restrict enum
		"version: 1\nrules:\n  - match:\n      path: /a\n    redact:\n      json_fields: [foo]", // bad JSON path
		"version: 1\nrules:\n  - match:\n      path: /a\n    labels:\n      t: nope",            // bad label source
	}
	for i, y := range bad {
		if _, err := config.Parse([]byte(y)); err == nil {
			t.Errorf("case %d: expected validation error, got none", i)
		}
	}
}
