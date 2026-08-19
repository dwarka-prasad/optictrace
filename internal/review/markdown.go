package review

import (
	"fmt"
	"strings"

	"github.com/dwarka-prasad/optictrace/internal/scan"
	"github.com/dwarka-prasad/optictrace/internal/spec"
	"github.com/dwarka-prasad/optictrace/internal/suggest"
)

// CommentMarker lets the PR bot find and update its own previous comment
// instead of posting a new one on every push. Reviewers should see one
// comment that stays current, not a wall of stale ones.
const CommentMarker = "<!-- optictrace-governance-review -->"

// Markdown renders the report as a pull-request comment.
//
// Structure is deliberate: verdict first, then the thing that blocks, then
// context. A reviewer who reads only the first line should still learn
// whether they need to do anything.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	b.WriteString("## OpticTrace governance review\n\n")

	// --- verdict ----------------------------------------------------------
	// The headline is about THIS change. Pre-existing problems are context,
	// not an accusation — a reviewer must be able to tell instantly whether
	// they broke something or merely inherited it.
	switch {
	case r.Regressions() > 0:
		fmt.Fprintf(&b, "> ### ✗ This change weakens governance on %d point(s)\n>\n", r.Regressions())
		b.WriteString("> Each one below was verified by replaying real traffic. If it's deliberate, say so in the PR.\n\n")
	case r.BreakingForClients() > 0:
		fmt.Fprintf(&b, "> ### ✗ This change breaks %d thing(s) live clients rely on\n>\n", r.BreakingForClients())
		b.WriteString("> Usage counts are from observed traffic, not guesses.\n\n")
	case len(r.Leaks) > 0 || len(r.Suggestions) > 0:
		b.WriteString("> ### ✓ This change doesn't weaken governance\n>\n")
		fmt.Fprintf(&b, "> Some pre-existing findings are listed below for context — they aren't caused by this PR.\n\n")
	default:
		b.WriteString("> ### ✓ No governance concerns\n>\n")
		fmt.Fprintf(&b, "> Checked against %s of observed traffic.\n\n", r.Window)
	}

	// --- coverage --------------------------------------------------------
	c := r.Coverage
	b.WriteString("### Coverage\n\n")
	b.WriteString("| | Covered | Total | |\n|---|--:|--:|---|\n")
	fmt.Fprintf(&b, "| Requests governed by a rule | %d | %d | %s |\n",
		c.GovernedRequests, c.Requests, bar(c.RequestPct()))
	fmt.Fprintf(&b, "| Routes with a rule | %d | %d | %s |\n",
		c.GovernedRoutes, c.Routes, bar(pct(c.GovernedRoutes, c.Routes)))
	fmt.Fprintf(&b, "| Sensitive-looking fields handled | %d | %d | %s |\n",
		c.GovernedFields, c.SensitiveFields, bar(c.FieldPct()))
	if c.NotFound > 0 {
		fmt.Fprintf(&b, "\n<sub>%d request(s) excluded: the upstream returned 404, so those paths aren't part of the API surface.</sub>\n",
			c.NotFound)
	}
	b.WriteString("\n")
	if len(c.UngovernedRoutes) > 0 {
		b.WriteString("<details><summary>Routes with no matching rule</summary>\n\n")
		for _, r := range c.UngovernedRoutes {
			fmt.Fprintf(&b, "- `%s`\n", r)
		}
		b.WriteString("\n</details>\n\n")
	}

	// --- policy diff: the PR-specific part --------------------------------
	if r.ComparedBase {
		b.WriteString("### What this PR changes about governance\n\n")
		if len(r.PolicyChanges) == 0 {
			b.WriteString("No behavioural change: the same traffic is governed identically before and after.\n\n")
		} else {
			b.WriteString("Measured by replaying the same captured traffic under both policies.\n\n")
			b.WriteString("| | Route | Change | Requests affected |\n|---|---|---|--:|\n")
			for _, ch := range capChanges(r.PolicyChanges, 15) {
				fmt.Fprintf(&b, "| %s | `%s %s` | %s | %d |\n",
					icon(ch.Severity), ch.Method, ch.Route, ch.What, ch.Affected)
			}
			if n := len(r.PolicyChanges) - 15; n > 0 {
				fmt.Fprintf(&b, "\n_…and %d more._\n", n)
			}
			b.WriteString("\n")
		}
	}

	// --- leaks -----------------------------------------------------------
	if len(r.Leaks) > 0 {
		crit, high, med := countLeaks(r.Leaks)
		b.WriteString("### Sensitive values already in stored telemetry\n\n")
		fmt.Fprintf(&b, "%d critical · %d high · %d medium — pre-existing, not introduced by this PR. Samples are masked.\n\n",
			crit, high, med)
		if r.LogLinesReviewed > 0 {
			fmt.Fprintf(&b, "<sub>Includes %d application log line(s). A log line is free text, "+
				"so its fix is a pattern or field name under `app_logs.redact` rather than a JSON path.</sub>\n\n",
				r.LogLinesReviewed)
		}
		b.WriteString("| | Where | Field | Seen | Fix |\n|---|---|---|--:|---|\n")
		for _, f := range r.Leaks {
			if len(b.String()) > 40000 {
				break // stay well inside GitHub's comment limit
			}
			fmt.Fprintf(&b, "| %s | `%s %s` | `%s.%s` | %d | %s |\n",
				leakIcon(f.Severity), f.Method, f.Route, f.Location, f.Field, f.Count,
				inlineYAML(f.Suggest))
		}
		b.WriteString("\n")
	}

	// --- spec breaking changes -------------------------------------------
	if breaking := filterBreaking(r.SpecFindings); len(breaking) > 0 {
		b.WriteString("### Live clients depend on this\n\n")
		for _, f := range breaking {
			fmt.Fprintf(&b, "- ✗ %s\n", f.Message)
		}
		b.WriteString("\n")
	}

	// --- suggestions ------------------------------------------------------
	if len(r.Suggestions) > 0 {
		b.WriteString("<details><summary>")
		fmt.Fprintf(&b, "%d ungoverned field(s) that look sensitive — suggested rules", len(r.Suggestions))
		b.WriteString("</summary>\n\n")
		for _, s := range capSuggestions(r.Suggestions, 20) {
			fmt.Fprintf(&b, "- **%s** `%s` on `%s` — %s\n", s.Confidence, s.Field, s.Route, s.Why)
		}
		b.WriteString("\n</details>\n\n")
	}

	b.WriteString("---\n")
	fmt.Fprintf(&b, "<sub>Analysed %d captured request(s) over %s · ", r.Coverage.Requests, r.Window)
	b.WriteString("`optictrace review` · governance is declared in `optic.yaml`</sub>\n")
	return b.String()
}

// Summary is a one-line verdict for a check-run title or a log line.
func (r *Report) Summary() string {
	if r.Attributable() {
		var reasons []string
		if n := r.Regressions(); n > 0 {
			reasons = append(reasons, fmt.Sprintf("%d governance regression(s)", n))
		}
		if n := r.BreakingForClients(); n > 0 {
			reasons = append(reasons, fmt.Sprintf("%d breaking change(s)", n))
		}
		return "✗ " + strings.Join(reasons, ", ")
	}
	msg := fmt.Sprintf("✓ no regressions · %.0f%% of traffic governed", r.Coverage.RequestPct())
	if crit, high, _ := countLeaks(r.Leaks); crit+high > 0 {
		msg += fmt.Sprintf(" (%d pre-existing critical/high finding(s))", crit+high)
	}
	return msg
}

// --- helpers ----------------------------------------------------------------

func bar(p float64) string {
	const width = 12
	filled := int(p/100*width + 0.5)
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return fmt.Sprintf("`%s%s` %.0f%%", strings.Repeat("█", filled),
		strings.Repeat("░", width-filled), p)
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func icon(sev string) string {
	switch sev {
	case SevBlocking:
		return "✗"
	case SevWarn:
		return "⚠"
	default:
		return "·"
	}
}

func leakIcon(sev string) string {
	switch sev {
	case scan.SevCritical:
		return "✗"
	case scan.SevHigh:
		return "⚠"
	default:
		return "·"
	}
}

// inlineYAML flattens a multi-line suggestion into something that survives
// a Markdown table cell.
func inlineYAML(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	return "`" + s + "`"
}

func countLeaks(fs []scan.Finding) (crit, high, med int) {
	for _, f := range fs {
		switch f.Severity {
		case scan.SevCritical:
			crit++
		case scan.SevHigh:
			high++
		default:
			med++
		}
	}
	return
}

func filterBreaking(fs []spec.Finding) []spec.Finding {
	var out []spec.Finding
	for _, f := range fs {
		if f.Severity == spec.SevBreaking {
			out = append(out, f)
		}
	}
	return out
}

func capChanges(cs []PolicyChange, n int) []PolicyChange {
	if len(cs) > n {
		return cs[:n]
	}
	return cs
}

func capSuggestions(ss []suggest.Suggestion, n int) []suggest.Suggestion {
	if len(ss) > n {
		return ss[:n]
	}
	return ss
}
