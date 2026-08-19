package scaffold

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dwarka-prasad/optictrace/internal/suggest"
)

// Options tunes generation.
type Options struct {
	// ServiceName overrides the title from the document.
	ServiceName string
	Listen      string
	Upstream    string
	// IncludeLow adds Low-confidence name matches (`name`, `first_name`).
	// Off by default: masking every `name` field in an API produces telemetry
	// nobody can debug with, and a rule people delete in week one protects
	// nothing thereafter.
	IncludeLow bool
}

// Result is the generated config plus what the generator could not determine.
type Result struct {
	YAML string
	// Notes are things the operator has to check by hand. Surfaced rather than
	// buried: a scaffolded config that looks finished is worse than one that
	// admits what it left out.
	Notes []string
	// Stats for the summary line.
	Routes, Rules, MaskedFields int
}

// authPathHints are route fragments whose payloads are credentials by
// definition, whatever their schema calls the fields.
var authPathHints = []string{"/login", "/logout", "/signin", "/sign-in", "/auth",
	"/token", "/oauth", "/session", "/password", "/register", "/signup"}

// Generate produces a starting optic.yaml.
func Generate(doc *Document, o Options) *Result {
	res := &Result{Routes: len(doc.Paths)}

	name := o.ServiceName
	if name == "" {
		name = slug(doc.Title)
	}
	if name == "" {
		name = "my-api"
	}

	var b strings.Builder
	writeHeader(&b, doc, name, o)

	// --- credential rules, from declared security schemes ------------------
	// These come first because they are the one thing a spec states rather
	// than implies, and because a later rule can only add to them.
	var globalHeaders, globalQueries []string
	globalHeaders = append(globalHeaders, doc.SecurityHeaders...)
	globalQueries = append(globalQueries, doc.SecurityQueries...)
	// Cookie is not usually a declared scheme, but a session cookie in stored
	// telemetry is a replayable credential wherever it came from.
	globalHeaders = dedupe(append(globalHeaders, "Cookie"))

	fmt.Fprintf(&b, "rules:\n")
	fmt.Fprintf(&b, "  # Credentials, from the document's security schemes. This is the part a\n")
	fmt.Fprintf(&b, "  # specification states outright rather than implies, so it is the part\n")
	fmt.Fprintf(&b, "  # least likely to be wrong.\n")
	fmt.Fprintf(&b, "  - name: redact-credentials\n")
	fmt.Fprintf(&b, "    match:\n      path: \"/**\"\n")
	fmt.Fprintf(&b, "    redact:\n")
	fmt.Fprintf(&b, "      headers: [%s]\n", strings.Join(quoteAll(globalHeaders), ", "))
	if len(globalQueries) > 0 {
		fmt.Fprintf(&b, "      query_params: [%s]\n", strings.Join(quoteAll(globalQueries), ", "))
	}
	res.Rules++

	// --- auth routes: metadata only ----------------------------------------
	var authGlobs []string
	for _, p := range doc.Paths {
		if looksLikeAuth(p.Raw) {
			authGlobs = append(authGlobs, p.Glob)
		}
	}
	if len(authGlobs) > 0 {
		fmt.Fprintf(&b, "\n  # Credential exchanges. Capture nothing but metadata: the request body\n")
		fmt.Fprintf(&b, "  # here IS a password, and no redaction rule is as reliable as not\n")
		fmt.Fprintf(&b, "  # recording it. Attribution still works — labels read the live request.\n")
		for _, g := range dedupe(authGlobs) {
			fmt.Fprintf(&b, "  - name: no-capture-on-%s\n", slug(g))
			fmt.Fprintf(&b, "    match:\n      path: %q\n", g)
			fmt.Fprintf(&b, "    restrict: [request_body, response_body, headers]\n")
			res.Rules++
		}
	}

	// --- per-path field redaction ------------------------------------------
	type finding struct {
		field string
		class suggest.Classification
	}
	for _, p := range doc.Paths {
		if looksLikeAuth(p.Raw) {
			continue // already covered, and more strictly
		}
		var found []finding
		for _, f := range append(append([]string{}, p.RequestFields...), p.ResponseFields...) {
			c, ok := suggest.ClassifyField(f)
			if !ok {
				continue
			}
			if c.Confidence == suggest.Low && !o.IncludeLow {
				continue
			}
			found = append(found, finding{field: f, class: c})
		}
		// Header and query parameters declared on the path.
		var hdrs, qrys []string
		for _, h := range p.HeaderParams {
			if _, ok := suggest.ClassifyHeader(h); ok {
				hdrs = append(hdrs, h)
			}
		}
		for _, q := range p.QueryParams {
			if _, ok := suggest.ClassifyField(q); ok {
				qrys = append(qrys, q)
			}
		}
		if len(found) == 0 && len(hdrs) == 0 && len(qrys) == 0 {
			continue
		}

		sort.Slice(found, func(i, j int) bool { return found[i].field < found[j].field })
		fmt.Fprintf(&b, "\n  - name: redact-%s\n", slug(p.Glob))
		fmt.Fprintf(&b, "    match:\n      path: %q\n", p.Glob)
		fmt.Fprintf(&b, "    redact:\n")
		if len(hdrs) > 0 {
			fmt.Fprintf(&b, "      headers: [%s]\n", strings.Join(quoteAll(dedupe(hdrs)), ", "))
		}
		if len(qrys) > 0 {
			fmt.Fprintf(&b, "      query_params: [%s]\n", strings.Join(quoteAll(dedupe(qrys)), ", "))
		}
		if len(found) > 0 {
			fmt.Fprintf(&b, "      json_fields:\n")
			seen := map[string]bool{}
			for _, f := range found {
				// `$.**.` rather than `$.`: the document describes one shape,
				// but the same object often appears nested inside a wrapper or
				// echoed back in a response envelope.
				path := "$.**." + f.field
				if seen[path] {
					continue
				}
				seen[path] = true
				fmt.Fprintf(&b, "        - %-34q # %s · %s\n", path, f.class.Confidence, f.class.Why)
				res.MaskedFields++
			}
		}
		res.Rules++
	}

	writeFooter(&b, doc)
	res.YAML = b.String()
	res.Notes = notes(doc, res, o)
	return res
}

func writeHeader(b *strings.Builder, doc *Document, name string, o Options) {
	kind := "OpenAPI " + doc.Version
	if doc.Swagger {
		kind = "Swagger " + doc.Version
	}
	fmt.Fprintf(b, `# =============================================================================
# optic.yaml — GENERATED from a %s document
# =============================================================================
# This is a starting point, not a finished policy. It was derived from what the
# specification DESCRIBES; governance has to hold for what the API actually
# DOES, and the two differ in ways that matter here:
#
#   * A field the document does not model cannot be masked by a rule generated
#     from it. Free-form objects and additionalProperties are invisible.
#   * Specifications drift. A field added after this one was written is not here.
#   * Names lie. A field called "ref" can hold a card number — which is what
#     'optictrace scan' finds and a name heuristic never will.
#
# So: review it, then run the agent and check with real traffic.
#
#     optictrace validate -config optic.yaml
#     optictrace scan -config optic.yaml -window 24h   # after traffic flows
#
# Capture is OPT-OUT: everything is recorded unless a rule restricts it. Rules
# merge top to bottom; later rules win on conflicting capture flags, while
# redactions and labels accumulate.
# =============================================================================

version: 1

service:
  name: %s
`, kind, name)

	if o.Listen != "" {
		fmt.Fprintf(b, "  listen: %q\n", o.Listen)
	} else {
		fmt.Fprintf(b, "  # listen: \":8080\"        # sidecar mode: where OpticTrace accepts traffic\n")
	}
	if o.Upstream != "" {
		fmt.Fprintf(b, "  upstream: %q\n", o.Upstream)
	} else {
		fmt.Fprintf(b, "  # upstream: \"http://localhost:9000\"   # and where it forwards\n")
	}

	fmt.Fprintf(b, `
telemetry:
  admin_listen: "127.0.0.1:9095"   # loopback: this port serves every captured payload
  metrics:
    enabled: true
  store:
    driver: sqlite
    dsn: optictrace.db
    retention_max_age: 720h

`)
}

func writeFooter(b *strings.Builder, doc *Document) {
	fmt.Fprintf(b, `
# -----------------------------------------------------------------------------
# Worth adding by hand, because a specification cannot tell you:
#
#   labels:            who a request belongs to - a tenant header, a plan tier.
#                      Nothing in a spec says which header identifies a customer.
#   meter:             numeric usage to bill on, e.g. tokens: "$.usage.total"
#   sample / keep_*:   volume control on hot routes. keep_errors and
#                      keep_slower_than rescue the requests worth having.
# -----------------------------------------------------------------------------
`)
}

// notes reports what the generator could not determine. A scaffolded config
// that looks finished is worse than one that admits what it left out.
func notes(doc *Document, res *Result, o Options) []string {
	var out []string
	if len(doc.SecurityHeaders) == 0 && len(doc.SecurityQueries) == 0 {
		out = append(out, "The document declares no security schemes, so credential headers were "+
			"guessed rather than read. Check `redact-credentials` names the header your API "+
			"actually authenticates with.")
	}
	if res.MaskedFields == 0 {
		out = append(out, "No payload field matched a sensitive-name heuristic. That may be correct, "+
			"or it may mean the schemas are free-form — a field the document does not model "+
			"cannot be masked by a rule derived from it.")
	}
	if !o.IncludeLow {
		out = append(out, "Low-confidence matches (name, first_name) were skipped. Re-run with "+
			"-include-low if this API's personal names need masking.")
	}
	out = append(out, "Nothing here restricts capture volume. Add `sample` with `keep_errors` on "+
		"hot read paths before pointing this at production traffic.")
	out = append(out, "Run `optictrace scan` once real traffic exists: it reads VALUES, and will "+
		"find sensitive data in fields whose names gave no clue.")
	return out
}

func looksLikeAuth(route string) bool {
	lower := strings.ToLower(route)
	for _, hint := range authPathHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// slug makes a YAML-safe rule name fragment from a path or title.
func slug(s string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func quoteAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, fmt.Sprintf("%q", s))
	}
	return out
}
