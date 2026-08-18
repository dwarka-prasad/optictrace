package engine

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
)

func attrs(method, path string, headers map[string]string, query string) Attrs {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	q, _ := url.ParseQuery(query)
	return Attrs{Method: method, Path: path, Headers: h, Query: q}
}

func req(path string, headers map[string]string, query string) *http.Request {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Request{Header: h, URL: &url.URL{Path: path, RawQuery: query}}
}

// --- label sources ----------------------------------------------------------

func TestLabelSources(t *testing.T) {
	for _, tc := range []struct {
		name, src, path, query string
		headers                map[string]string
		want                   string
	}{
		{name: "header", src: "header:X-Tenant-ID", headers: map[string]string{"X-Tenant-ID": "acme"}, want: "acme"},
		{name: "header is case-insensitive", src: "header:x-tenant-id", headers: map[string]string{"X-Tenant-ID": "acme"}, want: "acme"},
		{name: "query", src: "query:tenant", query: "tenant=globex", want: "globex"},
		{name: "static", src: "static:premium", want: "premium"},
		// Tenant in the URL: /api/v1/tenants/acme/orders
		{name: "path segment", src: "path:4", path: "/api/v1/tenants/acme/orders", want: "acme"},
		{name: "path segment out of range", src: "path:9", path: "/api/v1", want: ""},
		// Regex capture: eu-west-1 -> eu
		{name: "regex capture", src: `header:X-Region|^([a-z]{2})-`,
			headers: map[string]string{"X-Region": "eu-west-1"}, want: "eu"},
		{name: "regex on a path segment", src: `path:2|^v(\d+)$`, path: "/api/v3/x", want: "3"},
		// A non-match yields nothing rather than the whole value — a missing
		// label is safer than a surprising one.
		{name: "regex miss yields empty", src: `header:X-Region|^([a-z]{2})-`,
			headers: map[string]string{"X-Region": "NOPE"}, want: ""},
		{name: "absent header", src: "header:X-Nope", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ls, err := ParseLabelSource(tc.src)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.src, err)
			}
			if got := ls.Value(req(tc.path, tc.headers, tc.query)); got != tc.want {
				t.Errorf("Value = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseLabelSourceRejects(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"X-Tenant", "must be"},
		{"cookie:t", "unknown kind"},
		{"header:", "needs a name"},
		{"static:", "needs a value"},
		{"path:zero", "positive 1-indexed"},
		{"path:0", "positive 1-indexed"},
		{"path:-1", "positive 1-indexed"},
		{`header:X|([a-z]`, "error parsing regexp"},
		// Zero or two capture groups are ambiguous about which is the label.
		{`header:X|^[a-z]+$`, "exactly one capture group"},
		{`header:X|^([a-z])-([a-z])$`, "exactly one capture group"},
		{`static:x|^(a)$`, "nothing to extract"},
	} {
		t.Run(tc.src, func(t *testing.T) {
			_, err := ParseLabelSource(tc.src)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !contains(err.Error(), tc.want) {
				t.Errorf("message %q does not mention %q", err, tc.want)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}

// --- match criteria ---------------------------------------------------------

// The headline use case: one API, many tenants, tagged by plan tier. Rules
// merge top to bottom, so a broad default plus a narrow override is all that
// conditional tagging needs — no separate `tags:` concept.
func TestConditionalTaggingViaRuleMerge(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{
		{
			Name:   "baseline",
			Match:  config.Match{Path: "/api/**"},
			Labels: map[string]string{"tenant": "header:X-Tenant-ID", "tier": "static:standard"},
		},
		{
			Name: "premium-plans",
			Match: config.Match{
				Path:    "/api/**",
				Headers: map[string]string{"X-Plan": "^(gold|platinum)$"},
			},
			Labels: map[string]string{"tier": "static:premium"},
		},
	}}
	e := New(cfg)

	for _, tc := range []struct {
		plan, wantTier string
	}{
		{"gold", "premium"},
		{"platinum", "premium"},
		{"silver", "standard"},
		{"", "standard"},
		// Anchored pattern: a value merely containing "gold" must not match.
		{"golden-oldie", "standard"},
	} {
		t.Run("plan="+tc.plan, func(t *testing.T) {
			a := attrs("GET", "/api/orders", map[string]string{
				"X-Tenant-ID": "acme", "X-Plan": tc.plan,
			}, "")
			p := e.EvaluateAttrs(a)
			src, ok := p.Labels["tier"]
			if !ok {
				t.Fatal("tier label not defined")
			}
			r := req("/api/orders", map[string]string{"X-Tenant-ID": "acme", "X-Plan": tc.plan}, "")
			if got := src.Value(r); got != tc.wantTier {
				t.Errorf("tier = %q, want %q", got, tc.wantTier)
			}
			if got := p.Labels["tenant"].Value(r); got != "acme" {
				t.Errorf("tenant = %q, want acme", got)
			}
		})
	}
}

// A criteria rule must not apply when the evaluation has no headers to check
// it against. The alternative — treating "cannot decide" as "matches" — would
// silently apply a narrowly-scoped rule to everything.
func TestCriteriaRulesDoNotMatchWithoutContext(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{{
		Name:   "internal-only",
		Match:  config.Match{Path: "/api/**", Headers: map[string]string{"X-Internal": "^1$"}},
		Labels: map[string]string{"audience": "static:internal"},
	}}}
	e := New(cfg)

	if p := e.Evaluate("GET", "/api/x"); len(p.MatchedRules) != 0 {
		t.Errorf("a header rule must not fire without headers, matched %v", p.MatchedRules)
	}
	p := e.EvaluateAttrs(attrs("GET", "/api/x", map[string]string{"X-Internal": "1"}, ""))
	if len(p.MatchedRules) != 1 {
		t.Errorf("with headers supplied it should match, got %v", p.MatchedRules)
	}
}

func TestQueryCriteria(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{{
		Name:   "sandbox",
		Match:  config.Match{Path: "/api/**", Query: map[string]string{"mode": "^sandbox$"}},
		Labels: map[string]string{"env": "static:sandbox"},
	}}}
	e := New(cfg)
	if p := e.EvaluateAttrs(attrs("GET", "/api/x", nil, "mode=sandbox")); len(p.MatchedRules) != 1 {
		t.Errorf("query criteria should match, got %v", p.MatchedRules)
	}
	if p := e.EvaluateAttrs(attrs("GET", "/api/x", nil, "mode=live")); len(p.MatchedRules) != 0 {
		t.Errorf("query criteria should not match, got %v", p.MatchedRules)
	}
}

// All listed criteria must hold — they are an AND, so adding one narrows.
func TestMultipleCriteriaAreConjunctive(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{{
		Name: "eu-premium",
		Match: config.Match{Path: "/**", Headers: map[string]string{
			"X-Plan":   "^gold$",
			"X-Region": "^eu-",
		}},
		Labels: map[string]string{"segment": "static:eu-gold"},
	}}}
	e := New(cfg)
	both := attrs("GET", "/x", map[string]string{"X-Plan": "gold", "X-Region": "eu-west-1"}, "")
	if len(e.EvaluateAttrs(both).MatchedRules) != 1 {
		t.Error("both criteria met should match")
	}
	one := attrs("GET", "/x", map[string]string{"X-Plan": "gold", "X-Region": "us-east-1"}, "")
	if len(e.EvaluateAttrs(one).MatchedRules) != 0 {
		t.Error("one criterion unmet must not match")
	}
}

// "." is the idiom for "present and non-empty", worth pinning since it is the
// most common criterion after an exact match.
func TestPresenceCriterion(t *testing.T) {
	cfg := &config.Config{Version: 1, Rules: []config.Rule{{
		Name:   "has-tenant",
		Match:  config.Match{Path: "/**", Headers: map[string]string{"X-Tenant-ID": "."}},
		Labels: map[string]string{"attributed": "static:yes"},
	}}}
	e := New(cfg)
	if len(e.EvaluateAttrs(attrs("GET", "/x", map[string]string{"X-Tenant-ID": "acme"}, "")).MatchedRules) != 1 {
		t.Error("a present header should match")
	}
	if len(e.EvaluateAttrs(attrs("GET", "/x", map[string]string{"X-Tenant-ID": ""}, "")).MatchedRules) != 0 {
		t.Error("an empty header should not match")
	}
	if len(e.EvaluateAttrs(attrs("GET", "/x", nil, "")).MatchedRules) != 0 {
		t.Error("an absent header should not match")
	}
}

func TestHasCriteriaRules(t *testing.T) {
	plain := New(&config.Config{Version: 1, Rules: []config.Rule{
		{Name: "a", Match: config.Match{Path: "/**"}},
	}})
	if plain.HasCriteriaRules() {
		t.Error("no criteria configured")
	}
	tagged := New(&config.Config{Version: 1, Rules: []config.Rule{
		{Name: "a", Match: config.Match{Path: "/**", Headers: map[string]string{"X": "y"}}},
	}})
	if !tagged.HasCriteriaRules() {
		t.Error("criteria configured")
	}
}
