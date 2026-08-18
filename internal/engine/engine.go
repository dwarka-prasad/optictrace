// Package engine compiles an optic.yaml Config into an immutable, allocation-
// light rule engine evaluated on every request.
//
// Compilation happens once at startup: path globs are pre-split into segments
// and method lists become sets, so the per-request hot path is a linear scan
// of cheap comparisons — no regex, no locks, no allocation beyond the Policy.
package engine

import (
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
)

// LabelSource is re-exported from config: this grammar is part of the schema,
// and one parser means validation and runtime cannot disagree about it — a
// rule that validates but never fires is the worst failure mode for a
// config-driven product.
type LabelSource = config.LabelSource

// ParseLabelSource compiles a label source expression. See config.
func ParseLabelSource(src string) (LabelSource, error) { return config.ParseLabelSource(src) }

// Policy is the fully-resolved governance decision for one request:
// the merge of the defaults and every matching rule, in order.
type Policy struct {
	CaptureRequestBody  bool
	CaptureResponseBody bool
	CaptureHeaders      bool
	CaptureQuery        bool
	CaptureLimitBytes   int64

	// RedactHeaders holds canonical header names whose values are masked
	// in captured telemetry.
	RedactHeaders map[string]struct{}
	// RedactQuery holds lower-cased query parameter names to mask.
	RedactQuery map[string]struct{}
	// RedactJSONPaths holds pre-split dotted paths ($.a.b -> ["a","b"]).
	RedactJSONPaths [][]string
	Labels          map[string]LabelSource

	// MatchedRules records which rule names fired (for log transparency).
	MatchedRules []string

	// RoutePattern is the glob of the last matched rule — a stable,
	// low-cardinality identifier for metrics ("/api/v1/payments/**" instead
	// of one series per payment ID). Empty when no rule matched.
	RoutePattern string

	// SampleRate is the fraction of matched requests whose bodies are
	// captured (1.0 = all). Metrics and metadata ignore sampling.
	SampleRate float64

	// KeepErrors and KeepSlowerThan are tail-based sampling: they rescue
	// requests that the uniform SampleRate draw would have discarded.
	// Because the outcome is only known after the response, a policy with
	// either set buffers bodies for every request and decides at the end.
	KeepErrors     bool
	KeepSlowerThan time.Duration

	// Meters maps meter names to pre-split response-body JSON paths whose
	// numeric values are extracted for usage/cost attribution. Metering is
	// independent of capture restriction and sampling.
	Meters map[string][][]string
}

// CapturesAnything reports whether any telemetry channel is open.
func (p *Policy) CapturesAnything() bool {
	return p.CaptureRequestBody || p.CaptureResponseBody || p.CaptureHeaders
}

// TailSampled reports whether tail-based rules are in play, meaning the
// keep/discard decision must be deferred until the response is complete.
func (p *Policy) TailSampled() bool {
	return p.KeepErrors || p.KeepSlowerThan > 0
}

// KeepBody decides whether a request's captured bodies are retained.
// drew is the uniform SampleRate draw made at request start; status and
// elapsed are the outcome. Tail rules can only ever rescue a request that
// the draw discarded — they never suppress one it kept.
func (p *Policy) KeepBody(drew bool, status int, elapsed time.Duration) bool {
	if drew {
		return true
	}
	if p.KeepErrors && status >= 500 {
		return true
	}
	if p.KeepSlowerThan > 0 && elapsed >= p.KeepSlowerThan {
		return true
	}
	return false
}

type compiledRule struct {
	name       string
	rawPattern string
	// gqlOp is the graphql_operation glob, empty when the rule does not
	// constrain the operation. A rule that does can only be evaluated once
	// the request body has been read, so Evaluate skips it and EvaluateOp
	// applies it.
	gqlOp      string
	sample     *float64
	keepErrors *bool
	keepSlower time.Duration
	pathSegs   []string
	methods    map[string]struct{} // nil = all methods
	// hdrCriteria and qryCriteria are the regex conditions from match.headers
	// and match.query. ALL must match for the rule to apply. A rule that has
	// them cannot be decided from the request line alone, so an evaluation
	// without that context skips it — same fail-safe stance as
	// graphql_operation.
	hdrCriteria map[string]*regexp.Regexp
	qryCriteria map[string]*regexp.Regexp
	restrict    []config.CaptureField
	redactHdrs  []string
	redactQuery []string
	redactPaths [][]string
	labels      map[string]LabelSource
	meters      map[string][]string
}

// Engine is safe for concurrent use after New returns.
type Engine struct {
	defaults config.Defaults
	rules    []compiledRule
}

// New compiles a validated Config. Config must have passed Validate().
func New(cfg *config.Config) *Engine {
	e := &Engine{defaults: cfg.Defaults}
	// Parse always fills this in, but the embedded API lets a caller build a
	// Config by hand — and a zero limit means every capture buffer holds
	// nothing, which looks like governance working rather than like a
	// misconfiguration.
	if e.defaults.CaptureLimitBytes <= 0 {
		e.defaults.CaptureLimitBytes = config.DefaultCaptureLimitBytes
	}
	for _, r := range cfg.Rules {
		cr := compiledRule{
			name:       r.Name,
			rawPattern: r.Match.Path,
			sample:     r.Sample,
			keepErrors: r.KeepErrors,
			keepSlower: r.SlowerThan(),
			pathSegs:   splitPath(r.Match.Path),
			gqlOp:      r.Match.GraphQLOperation,
			restrict:   r.Restrict,
		}
		if len(r.Match.Headers) > 0 {
			cr.hdrCriteria = make(map[string]*regexp.Regexp, len(r.Match.Headers))
			for name, pat := range r.Match.Headers {
				// Validate proved these compile; a failure here means the
				// config was mutated after loading.
				if re, err := regexp.Compile(pat); err == nil {
					cr.hdrCriteria[textproto.CanonicalMIMEHeaderKey(name)] = re
				}
			}
		}
		if len(r.Match.Query) > 0 {
			cr.qryCriteria = make(map[string]*regexp.Regexp, len(r.Match.Query))
			for name, pat := range r.Match.Query {
				if re, err := regexp.Compile(pat); err == nil {
					cr.qryCriteria[name] = re
				}
			}
		}
		if len(r.Match.Methods) > 0 {
			cr.methods = make(map[string]struct{}, len(r.Match.Methods))
			for _, m := range r.Match.Methods {
				cr.methods[m] = struct{}{}
			}
		}
		if r.Redact != nil {
			for _, h := range r.Redact.Headers {
				cr.redactHdrs = append(cr.redactHdrs, http.CanonicalHeaderKey(h))
			}
			for _, q := range r.Redact.QueryParams {
				cr.redactQuery = append(cr.redactQuery, strings.ToLower(q))
			}
			for _, jp := range r.Redact.JSONFields {
				// "$.credit_card.number" -> ["credit_card", "number"]
				cr.redactPaths = append(cr.redactPaths, strings.Split(strings.TrimPrefix(jp, "$."), "."))
			}
		}
		if len(r.Labels) > 0 {
			cr.labels = make(map[string]LabelSource, len(r.Labels))
			for k, src := range r.Labels {
				ls, err := ParseLabelSource(src)
				if err != nil {
					continue // Validate already rejected this
				}
				cr.labels[k] = ls
			}
		}
		if len(r.Meter) > 0 {
			cr.meters = make(map[string][]string, len(r.Meter))
			for name, jp := range r.Meter {
				cr.meters[name] = strings.Split(strings.TrimPrefix(jp, "$."), ".")
			}
		}
		e.rules = append(e.rules, cr)
	}
	return e
}

// Evaluate resolves the effective Policy for a method + URL path.
// Rules merge in declaration order: restrictions only ever narrow capture,
// redactions and labels accumulate.
// Attrs is everything a rule can match on. Callers pass what they have:
// the proxy has a full request, `review` and `suggest` have a stored record,
// `ruletest` has a synthetic case.
//
// A rule whose criteria cannot be decided from the supplied Attrs does not
// match. That is the fail-safe direction — the same stance graphql_operation
// takes — because the alternative is a redaction rule silently applying to
// traffic it was never scoped to.
type Attrs struct {
	Method  string
	Path    string
	Headers http.Header
	Query   url.Values
	// Operation is the GraphQL operation name, when known.
	Operation string
}

// AttrsOf builds Attrs from a live request.
func AttrsOf(r *http.Request) Attrs {
	return Attrs{
		Method: r.Method, Path: r.URL.Path,
		Headers: r.Header, Query: r.URL.Query(),
	}
}

// Evaluate resolves policy from the request line alone. Rules constrained by
// graphql_operation, match.headers or match.query are skipped here — there is
// nothing to decide them against — and applied by EvaluateAttrs.
func (e *Engine) Evaluate(method, urlPath string) Policy {
	return e.EvaluateAttrs(Attrs{Method: method, Path: urlPath})
}

// EvaluateAttrs resolves policy against everything the caller knows.
func (e *Engine) EvaluateAttrs(a Attrs) Policy { return e.evaluate(a) }

// EvaluateOp resolves policy including rules that target a GraphQL operation.
// Called after the request body has been parsed.
//
// Late binding is sound because OpticTrace governs telemetry, never live
// traffic: redaction, labels and the route pattern are all applied when the
// record is built, so learning the operation mid-request is not too late for
// any of them.
func (e *Engine) EvaluateOp(method, urlPath, operation string) Policy {
	return e.evaluate(Attrs{Method: method, Path: urlPath, Operation: operation})
}

// HasCriteriaRules reports whether any rule matches on headers or query
// parameters, so a caller can tell whether passing Attrs would change the
// answer it already has.
func (e *Engine) HasCriteriaRules() bool {
	for i := range e.rules {
		if len(e.rules[i].hdrCriteria) > 0 || len(e.rules[i].qryCriteria) > 0 {
			return true
		}
	}
	return false
}

// HasGraphQLRules reports whether any rule constrains a GraphQL operation, so
// the interceptor can skip the extra work entirely when none do.
func (e *Engine) HasGraphQLRules() bool {
	for i := range e.rules {
		if e.rules[i].gqlOp != "" {
			return true
		}
	}
	return false
}

func (e *Engine) evaluate(a Attrs) Policy {
	method, urlPath, operation := a.Method, a.Path, a.Operation
	p := Policy{
		CaptureRequestBody:  config.Bool(e.defaults.Capture.RequestBody),
		CaptureResponseBody: config.Bool(e.defaults.Capture.ResponseBody),
		CaptureHeaders:      config.Bool(e.defaults.Capture.Headers),
		CaptureQuery:        config.Bool(e.defaults.Capture.Query),
		CaptureLimitBytes:   e.defaults.CaptureLimitBytes,
		SampleRate:          1.0,
	}
	reqSegs := splitPath(urlPath)

	for i := range e.rules {
		r := &e.rules[i]
		if r.methods != nil {
			if _, ok := r.methods[method]; !ok {
				continue
			}
		}
		if !matchSegments(r.pathSegs, reqSegs) {
			continue
		}
		if !r.criteriaMatch(a) {
			continue
		}
		if r.gqlOp != "" {
			// Unknown operation: the rule cannot be decided yet, so it does
			// not apply. Evaluate passes "" for exactly this case.
			if operation == "" || !matchSegments(splitPath(r.gqlOp), splitPath(operation)) {
				continue
			}
		}

		p.MatchedRules = append(p.MatchedRules, r.name)
		p.RoutePattern = r.rawPattern
		if r.sample != nil {
			p.SampleRate = *r.sample
		}
		if r.keepErrors != nil {
			p.KeepErrors = *r.keepErrors
		}
		if r.keepSlower > 0 {
			p.KeepSlowerThan = r.keepSlower
		}
		for _, f := range r.restrict {
			switch f {
			case config.FieldRequestBody:
				p.CaptureRequestBody = false
			case config.FieldResponseBody:
				p.CaptureResponseBody = false
			case config.FieldHeaders:
				p.CaptureHeaders = false
			case config.FieldQuery:
				p.CaptureQuery = false
			}
		}
		if len(r.redactHdrs) > 0 {
			if p.RedactHeaders == nil {
				p.RedactHeaders = make(map[string]struct{})
			}
			for _, h := range r.redactHdrs {
				p.RedactHeaders[h] = struct{}{}
			}
		}
		if len(r.redactQuery) > 0 {
			if p.RedactQuery == nil {
				p.RedactQuery = make(map[string]struct{})
			}
			for _, q := range r.redactQuery {
				p.RedactQuery[q] = struct{}{}
			}
		}
		p.RedactJSONPaths = append(p.RedactJSONPaths, r.redactPaths...)
		if len(r.labels) > 0 {
			if p.Labels == nil {
				p.Labels = make(map[string]LabelSource)
			}
			for k, v := range r.labels {
				p.Labels[k] = v
			}
		}
		if len(r.meters) > 0 {
			if p.Meters == nil {
				p.Meters = make(map[string][][]string)
			}
			for name, path := range r.meters {
				p.Meters[name] = append(p.Meters[name], path)
			}
		}
	}
	return p
}

// LabelKeys returns the sorted union of custom label names across all rules.
// Prometheus requires a fixed label schema per metric, so the collector is
// built once from this set; requests missing a label export "".
func (e *Engine) LabelKeys() []string {
	set := map[string]struct{}{}
	for i := range e.rules {
		for k := range e.rules[i].labels {
			set[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	numRe  = regexp.MustCompile(`^\d+$`)
)

// NormalizeRoute collapses identifier-looking path segments (numbers, UUIDs,
// long hex tokens) into ":id" so unmatched routes still produce bounded
// metric cardinality: /api/v1/users/42 -> /api/v1/users/:id.
func NormalizeRoute(urlPath string) string {
	segs := splitPath(urlPath)
	for i, s := range segs {
		if numRe.MatchString(s) || uuidRe.MatchString(s) || hexRe.MatchString(s) {
			segs[i] = ":id"
		}
	}
	return "/" + strings.Join(segs, "/")
}

// splitPath normalizes "/api/v1/x/" into ["api", "v1", "x"].
// criteriaMatch reports whether every header and query condition holds.
//
// Absent context means no match, never a free pass: a rule scoped to
// `X-Plan: gold` must not apply to a request whose headers were not supplied.
func (r *compiledRule) criteriaMatch(a Attrs) bool {
	for name, re := range r.hdrCriteria {
		if a.Headers == nil {
			return false
		}
		if !re.MatchString(a.Headers.Get(name)) {
			return false
		}
	}
	for name, re := range r.qryCriteria {
		if a.Query == nil {
			return false
		}
		if !re.MatchString(a.Query.Get(name)) {
			return false
		}
	}
	return true
}

// SplitPath and MatchSegments expose the glob matcher so other packages —
// notably the interceptor's GraphQL path check — use the same semantics as
// rule matching rather than a second, subtly different implementation.
func SplitPath(s string) []string { return splitPath(s) }

// MatchSegments reports whether a split glob matches split path segments.
func MatchSegments(pattern, segs []string) bool { return matchSegments(pattern, segs) }

func splitPath(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

// matchSegments implements segment-wise globbing: "*" matches exactly one
// segment (shell patterns also work within a segment), while "**" matches
// zero or more segments.
func matchSegments(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	if pattern[0] == "**" {
		if len(pattern) == 1 {
			return true
		}
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], segs[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], segs[1:])
}
