package suggest

import (
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

const governedCfg = `
version: 1
service: { name: t }
rules:
  - name: payments
    match: { path: "/payments/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.card_number", "$.customer.email"]
`

func eng(t *testing.T, yaml string) *engine.Engine {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return engine.New(cfg)
}

func TestSuggestsBySensitiveFieldName(t *testing.T) {
	recs := []store.Record{{
		Time: time.Now(), Method: "POST", Path: "/orders", Route: "/orders",
		RequestBody: `{"password":"x","buyer":{"email":"a@b.c","phone":"1"},"payment":{"card_number":"1"},"qty":2}`,
	}}
	rep := Records(recs, eng(t, governedCfg))

	byField := map[string]Suggestion{}
	for _, s := range rep.Actionable() {
		byField[s.Field] = s
	}
	for field, wantConf := range map[string]string{
		"$.password":            High,
		"$.payment.card_number": High,
		"$.buyer.email":         Medium,
		"$.buyer.phone":         Medium,
	} {
		s, ok := byField[field]
		if !ok {
			t.Errorf("expected a suggestion for %s", field)
			continue
		}
		if s.Confidence != wantConf {
			t.Errorf("%s confidence = %s, want %s", field, s.Confidence, wantConf)
		}
		if s.Why == "" {
			t.Errorf("%s should explain why it matters", field)
		}
	}
	// Ordinary fields must not be flagged, or the tool becomes noise.
	if _, flagged := byField["$.qty"]; flagged {
		t.Error("qty should not be flagged")
	}
}

// The whole value of the tool depends on not re-reporting what's already
// handled — otherwise every run is the same wall of text and gets ignored.
func TestAlreadyGovernedFieldsAreNotActionable(t *testing.T) {
	recs := []store.Record{{
		Time: time.Now(), Method: "POST", Path: "/payments/charge", Route: "/payments/**",
		RequestBody:    `{"card_number":"1","customer":{"email":"a@b.c"},"password":"x"}`,
		RequestHeaders: map[string]string{"Authorization": "Bearer x"},
	}}
	rep := Records(recs, eng(t, governedCfg))

	actionable := map[string]bool{}
	for _, s := range rep.Actionable() {
		actionable[s.Field] = true
	}
	// Covered by the rule (card_number via $.**, email exactly, Authorization).
	for _, covered := range []string{"$.card_number", "$.customer.email", "Authorization"} {
		if actionable[covered] {
			t.Errorf("%s is already governed and should not be actionable", covered)
		}
	}
	// Not covered — must still surface.
	if !actionable["$.password"] {
		t.Error("password is ungoverned and should be suggested")
	}
	if len(rep.Suggestions) == len(rep.Actionable()) {
		t.Error("governed fields should still be reported as informational")
	}
}

func TestYAMLOutputIsPasteable(t *testing.T) {
	recs := []store.Record{{
		Time: time.Now(), Method: "POST", Path: "/orders", Route: "/orders",
		RequestBody:    `{"password":"x"}`,
		RequestHeaders: map[string]string{"Cookie": "sid=1"},
		Query:          "session=abc&page=2",
	}}
	rep := Records(recs, eng(t, governedCfg))
	yaml := rep.YAML()

	for _, want := range []string{
		"- name: govern-orders",
		`path: "/orders"`,
		"redact:",
		"headers: [Cookie]",
		"query_params: [session]",
		`- "$.password"`,
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("generated YAML missing %q\n---\n%s", want, yaml)
		}
	}
	// It must parse as part of a real config, or "pasteable" is a lie.
	full := "version: 1\nservice: { name: t }\nrules:\n" + yaml
	if _, err := config.Parse([]byte(full)); err != nil {
		t.Errorf("suggested YAML does not parse as optic.yaml: %v\n---\n%s", err, full)
	}
	// page is not sensitive and must not appear.
	if strings.Contains(yaml, "page") {
		t.Error("non-sensitive query params should not be suggested")
	}
}

// Regression: "pan" used to be a substring match, so ordinary parameters
// like `expand` were reported as high-confidence card data. A heuristic that
// cries wolf gets muted, and a muted heuristic protects nothing.
func TestNoSubstringFalsePositives(t *testing.T) {
	recs := []store.Record{{
		Time: time.Now(), Method: "GET", Path: "/users/1", Route: "/users/:id",
		Query:        "expand=profile&company=acme&panel=main",
		ResponseBody: `{"expand":"profile","japan_office":true,"company":"acme","plan":"pro"}`,
	}}
	rep := Records(recs, eng(t, governedCfg))
	for _, s := range rep.Actionable() {
		t.Errorf("false positive: %s %q flagged as %s", s.Kind, s.Field, s.Confidence)
	}

	// ...while a field genuinely named `pan` is still caught.
	real := []store.Record{{
		Time: time.Now(), Method: "POST", Path: "/orders", Route: "/orders",
		RequestBody: `{"payment":{"pan":"4111111111111111","cvv":"123"}}`,
	}}
	got := map[string]bool{}
	for _, s := range Records(real, eng(t, governedCfg)).Actionable() {
		got[s.Field] = true
	}
	for _, want := range []string{"$.payment.pan", "$.payment.cvv"} {
		if !got[want] {
			t.Errorf("exact match should still catch %s", want)
		}
	}
}

func TestPathCoverageSemantics(t *testing.T) {
	cases := []struct {
		pattern []string
		field   string
		want    bool
	}{
		{[]string{"**", "card"}, "$.a.b.card", true},
		{[]string{"*", "ssn"}, "$.person.ssn", true},
		{[]string{"*", "ssn"}, "$.a.b.ssn", false},
		{[]string{"card", "number"}, "$.card.number", true},
		{[]string{"card", "number"}, "$.card.cvv", false},
	}
	for _, c := range cases {
		p := &engine.Policy{RedactJSONPaths: [][]string{c.pattern}}
		if got := fieldGoverned(p, c.field); got != c.want {
			t.Errorf("fieldGoverned(%v, %s) = %v, want %v", c.pattern, c.field, got, c.want)
		}
	}
}
