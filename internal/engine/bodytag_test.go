package engine

import (
	"encoding/json"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
)

func doc(t *testing.T, s string) any {
	t.Helper()
	var d any
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return d
}

// The scenario this exists for: one lead endpoint, one tenant, one product,
// called by partners who differ only in a field of the payload.
func TestBodyLabelSegregatesIdenticalCallers(t *testing.T) {
	body := `{"lead":{"source":"flipkart","channel":"app","product":"personal-loan"}}`
	for _, tc := range []struct{ src, want string }{
		{"json:$.lead.source", "flipkart"},
		{"json:$.**.source", "flipkart"}, // wherever a wrapper puts it
		{"json:$.*.channel", "app"},
		{"json:$.lead.missing", ""},
		{"json:$.**.product", "personal-loan"},
		// Regex capture composes with body extraction.
		{`json:$.**.product|^([a-z]+)-`, "personal"},
	} {
		t.Run(tc.src, func(t *testing.T) {
			ls, err := ParseLabelSource(tc.src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := ls.ValueFromBody(doc(t, body)); got != tc.want {
				t.Errorf("= %q, want %q", got, tc.want)
			}
		})
	}
}

// A partner id arriving as a number must still become a label; silently
// dropping it because the payload used 4471 instead of "4471" would be a
// miserable thing to debug.
func TestBodyLabelRendersNonStrings(t *testing.T) {
	d := doc(t, `{"partner_id":4471,"pct":12.5,"active":true}`)
	for _, tc := range []struct{ path, want string }{
		{"$.partner_id", "4471"},
		{"$.pct", "12.5"},
		{"$.active", "true"},
	} {
		ls, _ := ParseLabelSource("json:" + tc.path)
		if got := ls.ValueFromBody(d); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestBodyLabelLooksInsideArrays(t *testing.T) {
	ls, _ := ParseLabelSource("json:$.items.sku")
	if got := ls.ValueFromBody(doc(t, `{"items":[{"sku":"A1"},{"sku":"B2"}]}`)); got != "A1" {
		t.Errorf("= %q, want the first match A1", got)
	}
}

// Body criteria: the same endpoint routed to different tags by payload.
func TestBodyCriteria(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{
		{
			Name:   "base",
			Match:  config.Match{Path: "/api/**"},
			Labels: map[string]string{"partner": "json:$.**.source"},
		},
		{
			Name: "marketplace",
			Match: config.Match{Path: "/api/**",
				Body: map[string]string{"$.**.source": "^(flipkart|amazon)$"}},
			Labels: map[string]string{"channel_type": "static:marketplace"},
		},
		{
			Name: "oem",
			Match: config.Match{Path: "/api/**",
				Body: map[string]string{"$.**.source": "^(samsung|xiaomi)$"}},
			Labels: map[string]string{"channel_type": "static:oem"},
		},
	}}
	e := New(cfg)

	for _, tc := range []struct{ source, wantType string }{
		{"flipkart", "marketplace"},
		{"amazon", "marketplace"},
		{"samsung", "oem"},
		{"xiaomi", "oem"},
		{"direct", ""}, // neither
	} {
		t.Run(tc.source, func(t *testing.T) {
			b := doc(t, `{"lead":{"source":"`+tc.source+`"}}`)
			p := e.EvaluateAttrs(Attrs{
				Method: "POST", Path: "/api/v1/leads", Body: b, BodyKnown: true,
			})
			got := ""
			if src, ok := p.Labels["channel_type"]; ok {
				got = src.Value(nil)
			}
			if got != tc.wantType {
				t.Errorf("channel_type = %q, want %q", got, tc.wantType)
			}
			if p.Labels["partner"].ValueFromBody(b) != tc.source {
				t.Errorf("partner label wrong")
			}
		})
	}
}

// Before the body has been read, a body rule must not match — otherwise a
// narrowly-scoped rule applies to everything for the part of the request
// lifecycle where it matters most.
func TestBodyCriteriaDoNotMatchBeforeTheBodyIsKnown(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{{
		Name:   "oem",
		Match:  config.Match{Path: "/**", Body: map[string]string{"$.source": "^samsung$"}},
		Labels: map[string]string{"t": "static:oem"},
	}}}
	e := New(cfg)
	if p := e.Evaluate("POST", "/api/leads"); len(p.MatchedRules) != 0 {
		t.Errorf("matched with no body: %v", p.MatchedRules)
	}
	// BodyKnown with a body that lacks the field is a real decision: no match.
	p := e.EvaluateAttrs(Attrs{Method: "POST", Path: "/api/leads",
		Body: doc(t, `{"other":1}`), BodyKnown: true})
	if len(p.MatchedRules) != 0 {
		t.Errorf("matched on an absent field: %v", p.MatchedRules)
	}
}

// Only routes with a body rule should pay for buffering.
func TestBodyRulePathsIsScopedToRulesThatNeedIt(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{
		{Name: "plain", Match: config.Match{Path: "/health"}},
		{Name: "body-crit", Match: config.Match{Path: "/api/leads",
			Body: map[string]string{"$.s": "x"}}},
		{Name: "json-label", Match: config.Match{Path: "/api/orders"},
			Labels: map[string]string{"p": "json:$.p"}},
		{Name: "resp-label", Match: config.Match{Path: "/api/x"},
			Labels: map[string]string{"id": "json_response:$.id"}},
	}}
	e := New(cfg)
	got := e.BodyRulePaths()
	if len(got) != 2 {
		t.Errorf("BodyRulePaths returned %d globs, want 2 (body criterion + json label)", len(got))
	}
	if !e.NeedsResponseBody() {
		t.Error("a json_response label should be reported")
	}
	plain := New(&config.Config{Version: 1, Rules: []config.Rule{
		{Name: "a", Match: config.Match{Path: "/**"}}}})
	if len(plain.BodyRulePaths()) != 0 || plain.NeedsResponseBody() {
		t.Error("a config without body rules must not ask for buffering")
	}
}

func TestJSONLabelSourceValidation(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"json:lead.source", "dotted path"},
		{"json:$.", "dotted path"},
		{"json_response:nope", "dotted path"},
	} {
		if _, err := ParseLabelSource(tc.src); err == nil {
			t.Errorf("%q should be rejected", tc.src)
		} else if !contains(err.Error(), tc.want) {
			t.Errorf("%q: message %q lacks %q", tc.src, err, tc.want)
		}
	}
	if ls, err := ParseLabelSource("json:$.a.b"); err != nil || !ls.NeedsBody() {
		t.Errorf("a json source should report NeedsBody: %v %v", ls, err)
	}
	if ls, _ := ParseLabelSource("header:X"); ls.NeedsBody() {
		t.Error("a header source must not ask for a body")
	}
}
