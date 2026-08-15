package review

import (
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

const baseCfg = `
version: 1
service: { name: t }
rules:
  - name: auth
    match: { path: "/auth/**" }
    restrict: [request_body, response_body, headers]
  - name: payments
    match: { path: "/payments/**" }
    redact:
      headers: [Authorization]
      query_params: [api_key]
      json_fields: ["$.**.card.number", "$.**.customer.email"]
    labels: { tenant: "header:X-Tenant-ID" }
`

// The PR under review: drops one redaction, drops a query mask, drops a
// label, and opens up the auth route.
const weakenedCfg = `
version: 1
service: { name: t }
rules:
  - name: auth
    match: { path: "/auth/**" }
    restrict: [response_body]
  - name: payments
    match: { path: "/payments/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.card.number"]
`

func cfg(t *testing.T, y string) *config.Config {
	t.Helper()
	c, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func traffic() []store.Record {
	now := time.Now()
	return []store.Record{
		{Time: now, Method: "POST", Path: "/payments/charge", Route: "/payments/**", Status: 201,
			Query:          "api_key=k&page=1",
			RequestBody:    `{"card":{"number":"[REDACTED]"},"customer":{"email":"[REDACTED]"}}`,
			RequestHeaders: map[string]string{"Authorization": "[REDACTED]"},
			Labels:         map[string]string{"tenant": "acme"}},
		{Time: now, Method: "POST", Path: "/auth/login", Route: "/auth/**", Status: 200},
		{Time: now, Method: "POST", Path: "/orders", Route: "/orders", Status: 201,
			RequestBody: `{"password":"x","payment":{"pan":"5500005555555559"}}`},
		// A 404 probe: not part of the API surface, must not count against coverage.
		{Time: now, Method: "GET", Path: "/wp-admin.php", Route: "/wp-admin.php", Status: 404},
	}
}

func TestPolicyDiffDetectsWeakening(t *testing.T) {
	rep := Run(Options{
		Records: traffic(), Base: cfg(t, baseCfg), Head: cfg(t, weakenedCfg), Window: "1h",
	})
	if !rep.Attributable() {
		t.Fatal("dropping redactions must be attributable to the change")
	}
	if rep.Regressions() < 2 {
		t.Errorf("expected several regressions, got %d: %+v", rep.Regressions(), rep.PolicyChanges)
	}
	joined := ""
	for _, c := range rep.PolicyChanges {
		joined += c.Severity + ":" + c.What + "\n"
	}
	for _, want := range []string{
		"blocking:stops redacting `$.**.customer.email`",
		"blocking:stops redacting query param `api_key`",
		"warn:drops label `tenant`",
		"now captures request bodies",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("policy diff missing %q\ngot:\n%s", want, joined)
		}
	}
	// Every change must carry the number of real requests it touches —
	// that's what makes it arguable rather than theoretical.
	for _, c := range rep.PolicyChanges {
		if c.Affected == 0 {
			t.Errorf("change %q reports 0 affected requests", c.What)
		}
	}
}

// A PR that changes nothing must pass, even when the codebase already has
// leaks. Failing every PR for an inherited problem is how a bot gets muted.
func TestUnchangedPolicyDoesNotBlock(t *testing.T) {
	rep := Run(Options{Records: traffic(), Base: cfg(t, baseCfg), Head: cfg(t, baseCfg), Window: "1h"})

	if len(rep.PolicyChanges) != 0 {
		t.Errorf("identical policies should produce no changes: %+v", rep.PolicyChanges)
	}
	if rep.Attributable() {
		t.Error("nothing is attributable to a no-op change")
	}
	if len(rep.Leaks) == 0 {
		t.Fatal("the fixture has an ungoverned card number; scan should still report it")
	}
	if rep.Blocking(FailOnRegression) {
		t.Error("default policy must not fail a PR for pre-existing findings")
	}
	// ...but a team that wants a hard gate can opt in.
	if !rep.Blocking(FailOnHigh) {
		t.Error("-review-fail-on high should escalate pre-existing findings")
	}
	if rep.Blocking(FailOnNever) {
		t.Error("never must never block")
	}
}

func TestCoverageExcludes404s(t *testing.T) {
	rep := Run(Options{Records: traffic(), Head: cfg(t, baseCfg), Window: "1h"})
	c := rep.Coverage
	if c.NotFound != 1 {
		t.Errorf("expected 1 excluded 404, got %d", c.NotFound)
	}
	if c.Requests != 3 {
		t.Errorf("404 should be excluded from the denominator, got %d", c.Requests)
	}
	// /payments and /auth are governed; /orders is not.
	if c.GovernedRequests != 2 || c.GovernedRoutes != 2 || c.Routes != 3 {
		t.Errorf("coverage wrong: %+v", c)
	}
	for _, r := range c.UngovernedRoutes {
		if strings.Contains(r, "wp-admin") {
			t.Error("a 404 path must not be listed as an ungoverned route")
		}
	}
	if got := c.RequestPct(); got < 66 || got > 67 {
		t.Errorf("RequestPct = %v, want ~66.7", got)
	}
}

func TestMarkdownIsUsable(t *testing.T) {
	rep := Run(Options{Records: traffic(), Base: cfg(t, baseCfg), Head: cfg(t, weakenedCfg), Window: "1h"})
	md := rep.Markdown()

	if !strings.HasPrefix(md, CommentMarker) {
		t.Error("comment must start with the marker so the bot can update in place")
	}
	for _, want := range []string{
		"weakens governance",
		"### Coverage",
		"### What this PR changes about governance",
		"stops redacting",
		"Requests affected",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("comment missing %q", want)
		}
	}
	// A report that leaks the values it is warning about would be absurd.
	if strings.Contains(md, "5500005555555559") {
		t.Error("comment leaked a raw card number")
	}
	// GitHub rejects comments over 65536 bytes.
	if len(md) > 60000 {
		t.Errorf("comment too long for GitHub: %d bytes", len(md))
	}
}

func TestNoBaseStillReportsCoverage(t *testing.T) {
	// First PR that adds optic.yaml: nothing to diff against, and that must
	// not be treated as a failure.
	rep := Run(Options{Records: traffic(), Head: cfg(t, baseCfg), Window: "1h"})
	if rep.ComparedBase {
		t.Error("ComparedBase should be false without a base config")
	}
	if rep.Blocking(FailOnRegression) {
		t.Error("absence of a base must not block")
	}
	if !strings.Contains(rep.Markdown(), "### Coverage") {
		t.Error("coverage should still be reported")
	}
}
