package ruletest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
)

const cfgYAML = `
version: 1
service: { name: test }
rules:
  - name: no-capture-on-auth
    match: { path: "/auth/**" }
    restrict: [request_body, response_body, headers]
  - name: redact-payments
    match: { path: "/payments/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.card.number"]
    labels:
      tenant: "header:X-Tenant-ID"
  - name: meter-ai
    match: { path: "/ai/**" }
    restrict: [response_body]
    meter: { tokens: "$.usage.total_tokens" }
    keep_errors: true
    keep_slower_than: 500ms
`

func mustEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg, err := config.Parse([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	return engine.New(cfg)
}

func runYAML(t *testing.T, tests string) *Result {
	t.Helper()
	p := filepath.Join(t.TempDir(), "optic.test.yaml")
	if err := os.WriteFile(p, []byte(tests), 0o644); err != nil {
		t.Fatal(err)
	}
	cases, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return Run(mustEngine(t), cases)
}

func TestPassingAssertions(t *testing.T) {
	res := runYAML(t, `
- name: auth captures nothing
  request:
    method: POST
    path: /auth/login
    body: { password: hunter2 }
  expect:
    matched_rules: [no-capture-on-auth]
    captures_request_body: false
    captures_headers: false
    stored_request_body: ""
    not_contains: ["hunter2"]

- name: payments redacts card at any depth
  request:
    method: POST
    path: /payments/charge
    headers: { Authorization: "Bearer tok", X-Tenant-ID: acme }
    body: { amount: 5, card: { number: "4111111111111111" } }
    response: { echo: { card: { number: "4111111111111111" } } }
  expect:
    matched_rules: [redact-payments]
    redacted_headers: [Authorization]
    labels: { tenant: acme }
    stored_request_body: '{"amount":5,"card":{"number":"[REDACTED]"}}'
    stored_response_body: '{"echo":{"card":{"number":"[REDACTED]"}}}'
    not_contains: ["4111111111111111", "Bearer tok"]

- name: ai route meters without storing
  request:
    method: POST
    path: /ai/complete
    response: { completion: "secret text", usage: { total_tokens: 128 } }
  expect:
    captures_response_body: false
    stored_response_body: ""
    meters: { tokens: 128 }
    not_contains: ["secret text"]

- name: tail sampling rescues a server error
  request: { method: POST, path: /ai/complete, status: 500 }
  expect: { keeps_body: true }

- name: tail sampling rescues a slow request
  request: { method: POST, path: /ai/complete, status: 200, took_ms: 900 }
  expect: { keeps_body: true }

- name: a fast success is not rescued
  request: { method: POST, path: /ai/complete, status: 200, took_ms: 5 }
  expect: { keeps_body: false }
`)
	if len(res.Failures) != 0 {
		for _, f := range res.Failures {
			t.Errorf("unexpected failure: %s / %s want=%q got=%q", f.Case, f.Assert, f.Want, f.Got)
		}
	}
	if res.Passed != res.Total || res.Total != 6 {
		t.Errorf("passed %d/%d, want 6/6", res.Passed, res.Total)
	}
}

func TestFailingAssertionsAreReported(t *testing.T) {
	res := runYAML(t, `
- name: wrong rule expected
  request: { method: POST, path: /auth/login }
  expect:
    matched_rules: [redact-payments]

- name: leak assertion catches an unredacted field
  request:
    method: POST
    path: /payments/charge
    body: { cvv: "999" }
  expect:
    not_contains: ["999"]
`)
	if res.Passed != 0 {
		t.Errorf("expected both cases to fail, %d passed", res.Passed)
	}
	if len(res.Failures) != 2 {
		t.Fatalf("want 2 failures, got %d: %+v", len(res.Failures), res.Failures)
	}
	joined := ""
	for _, f := range res.Failures {
		joined += f.Assert + " "
	}
	for _, want := range []string{"matched_rules", "not_contains"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q failure in %q", want, joined)
		}
	}
}

func TestLoadAcceptsBothShapes(t *testing.T) {
	dir := t.TempDir()
	bare := filepath.Join(dir, "a.yaml")
	os.WriteFile(bare, []byte("- name: x\n  request: {path: /a}\n"), 0o644)
	wrapped := filepath.Join(dir, "b.yaml")
	os.WriteFile(wrapped, []byte("cases:\n  - name: y\n    request: {path: /b}\n"), 0o644)

	for _, p := range []string{bare, wrapped} {
		cases, err := Load(p)
		if err != nil || len(cases) != 1 {
			t.Errorf("Load(%s) = %v, %v", filepath.Base(p), cases, err)
		}
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file should error")
	}
}

// A rule keyed on the request body is the one kind that is easiest to ship
// broken, because the payload is the part a config author cannot see from the
// route table. `optictrace test` used to evaluate cases without the body at
// all, so those rules silently never matched and no case could catch it.
// This locks the body into the evaluation context.
func TestRunEvaluatesBodyRulesAndJSONLabels(t *testing.T) {
	const cfg = `
version: 1
service: { name: test }
rules:
  - name: redact-card
    match: { path: "/payments/**" }
    redact: { json_fields: ["$.**.card.number"] }
  - name: tag-marketplace
    match:
      path: "/payments/**"
      body: { "$.**.source": "^(flipkart|amazon)$" }
    labels: { channel: "static:marketplace" }
  - name: label-from-body
    match: { path: "/payments/**" }
    labels:
      partner: "json:$.**.source"
      outcome: "json_response:$.status"
`
	parsed, err := config.Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(parsed)

	cases := []Case{{
		Name: "marketplace caller",
		Request: Request{
			Method:   "POST",
			Path:     "/payments/charge",
			Body:     map[string]any{"source": "flipkart", "card": map[string]any{"number": "4111111111111111"}},
			Response: map[string]any{"status": "captured"},
		},
		Expect: Expect{
			MatchedRules: &[]string{"redact-card", "tag-marketplace", "label-from-body"},
			Labels:       map[string]string{"channel": "marketplace", "partner": "flipkart", "outcome": "captured"},
			NotContains:  []string{"4111111111111111"},
		},
	}, {
		Name: "off-criteria caller does not get the tag",
		Request: Request{
			Method: "POST",
			Path:   "/payments/charge",
			Body:   map[string]any{"source": "walk-in"},
		},
		Expect: Expect{
			MatchedRules: &[]string{"redact-card", "label-from-body"},
		},
	}}

	if res := Run(eng, cases); len(res.Failures) > 0 {
		for _, f := range res.Failures {
			t.Errorf("%s: %s: want %q got %q", f.Case, f.Assert, f.Want, f.Got)
		}
	}
}

// A label must never be able to read a value the policy redacts. config.Parse
// refuses that combination outright, so the guard is checked there — but a case
// asserting on a redacted body path must still see the mask, not the original.
func TestRunLabelsSeeRedactedBody(t *testing.T) {
	const cfg = `
version: 1
service: { name: test }
rules:
  - name: redact-and-tag
    match:
      path: "/payments/**"
      body: { "$.note": "^plain$" }
    redact: { json_fields: ["$.secret"] }
    labels: { seen: "static:yes" }
`
	parsed, err := config.Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	cases := []Case{{
		Name: "redaction applies before criteria read the body",
		Request: Request{
			Method: "POST",
			Path:   "/payments/charge",
			Body:   map[string]any{"note": "plain", "secret": "hunter2"},
		},
		Expect: Expect{
			MatchedRules: &[]string{"redact-and-tag"},
			Labels:       map[string]string{"seen": "yes"},
			NotContains:  []string{"hunter2"},
		},
	}}
	if res := Run(engine.New(parsed), cases); len(res.Failures) > 0 {
		for _, f := range res.Failures {
			t.Errorf("%s: %s: want %q got %q", f.Case, f.Assert, f.Want, f.Got)
		}
	}
}
