// Package review turns everything OpticTrace knows into one pull-request
// comment.
//
// The other commands are things you have to remember to run. This one is
// meant to run itself, on every PR, and say something worth reading — which
// means it has to answer questions a reviewer actually has:
//
//	"Does this change quietly stop redacting something?"   <- policy diff
//	"Is the new endpoint governed at all?"                 <- coverage
//	"Is anything sensitive already leaking?"                <- scan
//	"Will this break a live client?"                        <- spec check
//
// The policy diff is the part no other tool can do: it evaluates the SAME
// captured traffic under the base branch's rules and the PR's rules, and
// reports where governance got weaker. A rule reordering that silently stops
// masking a card number looks harmless in a text diff and is obvious here.
package review

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/scan"
	"github.com/dwarka-prasad/optictrace/internal/spec"
	"github.com/dwarka-prasad/optictrace/internal/store"
	"github.com/dwarka-prasad/optictrace/internal/suggest"
)

// Severity of a review finding.
const (
	SevBlocking = "blocking" // governance got weaker, or a live client breaks
	SevWarn     = "warn"
	SevInfo     = "info"
)

// PolicyChange is one difference in how the same request is governed
// between the base branch and the PR.
type PolicyChange struct {
	Severity string `json:"severity"`
	Method   string `json:"method"`
	Route    string `json:"route"`
	What     string `json:"what"`     // human-readable description
	Affected int    `json:"affected"` // requests in the window this touches
}

// Coverage is the headline number: how much of the observed API surface is
// actually governed by a rule.
type Coverage struct {
	Requests         int      `json:"requests"`
	GovernedRequests int      `json:"governed_requests"`
	Routes           int      `json:"routes"`
	GovernedRoutes   int      `json:"governed_routes"`
	SensitiveFields  int      `json:"sensitive_fields"`
	GovernedFields   int      `json:"governed_fields"`
	UngovernedRoutes []string `json:"ungoverned_routes,omitempty"`
	// NotFound counts requests excluded from coverage because the upstream
	// returned 404 — those paths are not part of the API surface.
	NotFound int `json:"not_found_excluded"`
}

// RequestPct is the share of observed requests matched by at least one rule.
func (c Coverage) RequestPct() float64 {
	if c.Requests == 0 {
		return 0
	}
	return float64(c.GovernedRequests) / float64(c.Requests) * 100
}

// FieldPct is the share of sensitive-looking fields already covered.
func (c Coverage) FieldPct() float64 {
	if c.SensitiveFields == 0 {
		return 100
	}
	return float64(c.GovernedFields) / float64(c.SensitiveFields) * 100
}

// Report is a complete review.
type Report struct {
	Window        string               `json:"window"`
	Coverage      Coverage             `json:"coverage"`
	PolicyChanges []PolicyChange       `json:"policy_changes"`
	Leaks         []scan.Finding       `json:"leaks"`
	Suggestions   []suggest.Suggestion `json:"suggestions"`
	SpecFindings  []spec.Finding       `json:"spec_findings"`
	ComparedBase  bool                 `json:"compared_base"`
}

// Options configures a review.
type Options struct {
	Records []store.Record
	Head    *config.Config // policy as of this PR (required)
	Base    *config.Config // policy on the base branch (optional)
	Spec    *spec.Spec     // optional: also run the breaking-change check
	Window  string         // for display only
}

// Run performs the analysis.
func Run(o Options) *Report {
	head := engine.New(o.Head)
	rep := &Report{Window: o.Window}

	rep.Coverage = coverage(o.Records, head)
	if o.Base != nil {
		rep.ComparedBase = true
		rep.PolicyChanges = diffPolicies(o.Records, engine.New(o.Base), head)
	}
	rep.Leaks = scan.Records(o.Records, time.Time{}).Findings
	rep.Suggestions = suggest.Records(o.Records, head).Actionable()
	if o.Spec != nil {
		rep.SpecFindings = spec.Check(o.Spec, o.Records)
	}
	return rep
}

// Fail-on levels, controlling what makes the check run red.
const (
	// FailOnRegression is the default and the reason this bot is bearable:
	// a pull request fails only for what IT changed. Pre-existing leaks are
	// reported for context but don't block, because failing every PR for a
	// problem someone else introduced is how a bot gets muted — and a muted
	// bot protects nothing.
	FailOnRegression = "regression"
	FailOnCritical   = "critical" // also fail on any critical leak, however old
	FailOnHigh       = "high"
	FailOnNever      = "never"
)

// Regressions counts governance weakened by this change specifically.
func (r *Report) Regressions() int {
	n := 0
	for _, c := range r.PolicyChanges {
		if c.Severity == SevBlocking {
			n++
		}
	}
	return n
}

// BreakingForClients counts spec changes that would break observed clients.
func (r *Report) BreakingForClients() int {
	n := 0
	for _, f := range r.SpecFindings {
		if f.Severity == spec.SevBreaking {
			n++
		}
	}
	return n
}

// Attributable reports whether anything is this change's fault.
func (r *Report) Attributable() bool {
	return r.Regressions() > 0 || r.BreakingForClients() > 0
}

// Blocking decides the exit code for the given policy.
func (r *Report) Blocking(failOn string) bool {
	if failOn == FailOnNever {
		return false
	}
	if r.Attributable() {
		return true
	}
	switch failOn {
	case FailOnCritical:
		for _, f := range r.Leaks {
			if f.Severity == scan.SevCritical {
				return true
			}
		}
	case FailOnHigh:
		for _, f := range r.Leaks {
			if f.Severity == scan.SevCritical || f.Severity == scan.SevHigh {
				return true
			}
		}
	}
	return false
}

// --- coverage ---------------------------------------------------------------

func coverage(records []store.Record, eng *engine.Engine) Coverage {
	var c Coverage
	routes := map[string]bool{} // route -> governed
	for i := range records {
		rec := &records[i]
		// A 404 means the upstream has no such route, so it is not part of
		// the API surface you could write a rule for. Counting scanner
		// noise and typo'd paths against coverage would make the score
		// drop the moment anyone probes the service, which is exactly when
		// people stop trusting a metric.
		if rec.Status == 404 {
			c.NotFound++
			continue
		}
		c.Requests++
		p := eng.Evaluate(rec.Method, rec.Path)
		governed := len(p.MatchedRules) > 0
		if governed {
			c.GovernedRequests++
		}
		key := rec.Method + " " + routeOf(rec, &p)
		if was, seen := routes[key]; !seen || (!was && governed) {
			routes[key] = governed
		}
	}
	c.Routes = len(routes)
	var ungoverned []string
	for route, governed := range routes {
		if governed {
			c.GovernedRoutes++
		} else {
			ungoverned = append(ungoverned, route)
		}
	}
	sort.Strings(ungoverned)
	if len(ungoverned) > 8 {
		ungoverned = ungoverned[:8]
	}
	c.UngovernedRoutes = ungoverned

	// Field coverage comes from the name heuristics: how many
	// sensitive-looking fields exist, and how many are already handled.
	sug := suggest.Records(records, eng)
	c.SensitiveFields = len(sug.Suggestions)
	c.GovernedFields = c.SensitiveFields - len(sug.Actionable())
	return c
}

func routeOf(rec *store.Record, p *engine.Policy) string {
	if p.RoutePattern != "" {
		return p.RoutePattern
	}
	if rec.Route != "" {
		return rec.Route
	}
	return engine.NormalizeRoute(rec.Path)
}

// --- policy diff ------------------------------------------------------------

// diffPolicies replays the same traffic through both policies and reports
// where the PR weakens governance. Only weakening is blocking: tightening is
// reported as info so the reviewer can see the intent, not punished.
func diffPolicies(records []store.Record, base, head *engine.Engine) []PolicyChange {
	type agg struct {
		change PolicyChange
		count  int
	}
	seen := map[string]*agg{}

	note := func(rec *store.Record, sev, route, what string) {
		k := rec.Method + "|" + route + "|" + what
		a := seen[k]
		if a == nil {
			a = &agg{change: PolicyChange{Severity: sev, Method: rec.Method, Route: route, What: what}}
			seen[k] = a
		}
		a.count++
	}

	for i := range records {
		rec := &records[i]
		bp := base.Evaluate(rec.Method, rec.Path)
		hp := head.Evaluate(rec.Method, rec.Path)
		route := routeOf(rec, &hp)

		// --- capture flags -------------------------------------------------
		for _, f := range []struct {
			name       string
			was, isNow bool
		}{
			{"request bodies", bp.CaptureRequestBody, hp.CaptureRequestBody},
			{"response bodies", bp.CaptureResponseBody, hp.CaptureResponseBody},
			{"headers", bp.CaptureHeaders, hp.CaptureHeaders},
			{"query strings", bp.CaptureQuery, hp.CaptureQuery},
		} {
			switch {
			case !f.was && f.isNow:
				// Capturing MORE is a governance loosening: data that was
				// deliberately not recorded will now be stored.
				note(rec, SevWarn, route, fmt.Sprintf("now captures %s (was restricted)", f.name))
			case f.was && !f.isNow:
				note(rec, SevInfo, route, fmt.Sprintf("no longer captures %s", f.name))
			}
		}

		// --- redaction: the case that matters most --------------------------
		for h := range bp.RedactHeaders {
			if _, still := hp.RedactHeaders[h]; !still && hp.CaptureHeaders {
				note(rec, SevBlocking, route, fmt.Sprintf("stops redacting header `%s`", h))
			}
		}
		for q := range bp.RedactQuery {
			if _, still := hp.RedactQuery[q]; !still && hp.CaptureQuery {
				note(rec, SevBlocking, route, fmt.Sprintf("stops redacting query param `%s`", q))
			}
		}
		basePaths := pathSet(bp.RedactJSONPaths)
		headPaths := pathSet(hp.RedactJSONPaths)
		for p := range basePaths {
			if !headPaths[p] {
				note(rec, SevBlocking, route, fmt.Sprintf("stops redacting `$.%s`", p))
			}
		}
		for p := range headPaths {
			if !basePaths[p] {
				note(rec, SevInfo, route, fmt.Sprintf("now redacts `$.%s`", p))
			}
		}

		// --- labels and meters ---------------------------------------------
		for l := range bp.Labels {
			if _, still := hp.Labels[l]; !still {
				note(rec, SevWarn, route, fmt.Sprintf("drops label `%s` (breaks its Prometheus dimension)", l))
			}
		}
		for m := range bp.Meters {
			if _, still := hp.Meters[m]; !still {
				note(rec, SevWarn, route, fmt.Sprintf("drops meter `%s` (usage and cost stop being attributed)", m))
			}
		}
	}

	out := make([]PolicyChange, 0, len(seen))
	for _, a := range seen {
		a.change.Affected = a.count
		out = append(out, a.change)
	}
	rank := map[string]int{SevBlocking: 0, SevWarn: 1, SevInfo: 2}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if out[i].Affected != out[j].Affected {
			return out[i].Affected > out[j].Affected
		}
		return out[i].What < out[j].What
	})
	return out
}

func pathSet(paths [][]string) map[string]bool {
	out := make(map[string]bool, len(paths))
	for _, p := range paths {
		out[strings.Join(p, ".")] = true
	}
	return out
}
