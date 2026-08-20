// Package spans governs inner spans on the way into the store.
//
// An inner span is one operation inside a request: a query, a cache lookup, an
// outbound call. The timings are harmless; the ATTRIBUTES are not. A statement
// quotes its parameters, a cache key embeds an account id, an outbound URL
// carries a token in its query string. So attributes are scrubbed and capped
// BEFORE they are persisted, for the same reason app log lines are: "clean it
// up later" is after the data is already at rest.
package spans

import (
	"regexp"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/telcap"
)

// Defaults chosen so that enabling this without tuning it cannot swamp the
// store. An N+1 query inside a loop is the normal case, not the pathological
// one, and it is exactly what someone turns this on to find.
const (
	DefaultMaxPerRequest = 200
	DefaultMaxAttrBytes  = 4 << 10 // 4 KiB — a long statement, not a whole dump
)

// Reason explains why a span was not stored. Every drop is counted under one
// of these: data discarded silently is data nobody knows they are missing.
type Reason string

const (
	ReasonOrphan     Reason = "orphan"      // no parent span — belongs to no request
	ReasonTooFast    Reason = "too_fast"    // under min_duration
	ReasonRequestCap Reason = "request_cap" // request already at max_per_request
	ReasonDisabled   Reason = "disabled"    // feature off
	ReasonEmpty      Reason = "empty"       // no name, nothing to file it under
)

// Governor applies the span policy. Safe for concurrent use: ingest is an HTTP
// handler and several requests land at once.
type Governor struct {
	enabled     bool
	dropOrphans bool
	minDuration time.Duration
	maxPer      int
	maxBytes    int
	patterns    []*regexp.Regexp
	redactAttr  map[string]bool

	// Per-request span counts, memory-bounded by design — see telcap.Counter.
	counter *telcap.Counter
}

// New builds a Governor from config. A nil or disabled config yields a
// Governor that rejects everything with ReasonDisabled, so callers need no
// special case.
func New(cfg *config.SpansCfg) (*Governor, error) {
	g := &Governor{
		counter:    telcap.NewCounter(0),
		redactAttr: map[string]bool{},
	}
	if cfg == nil || !cfg.Enabled {
		return g, nil
	}
	g.enabled = true
	g.dropOrphans = cfg.DropOrphanSpans()
	g.minDuration = cfg.MinDuration

	g.maxPer = cfg.MaxPerRequest
	if g.maxPer == 0 {
		g.maxPer = DefaultMaxPerRequest
	}
	if g.maxPer < 0 {
		g.maxPer = 0 // -1 in config means "no cap"; telcap reads 0 that way
	}
	g.maxBytes = cfg.MaxAttrBytes
	if g.maxBytes == 0 {
		g.maxBytes = DefaultMaxAttrBytes
	}

	for _, pat := range cfg.Redact.Patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			// Config validation rejects this at load; reaching here means a
			// caller built a config by hand. Fail rather than run with a
			// redaction rule that silently does nothing.
			return nil, err
		}
		g.patterns = append(g.patterns, re)
	}
	for _, f := range cfg.Redact.Fields {
		g.redactAttr[strings.ToLower(f)] = true
	}
	return g, nil
}

func (g *Governor) Enabled() bool { return g.enabled }

// Admit applies the policy to one span. It returns true when the span should
// be stored, or the reason it was dropped.
//
// The span is mutated in place: redaction must happen before anything else can
// hold a reference to the raw attributes.
func (g *Governor) Admit(s *ext.Span) (bool, Reason) {
	if !g.enabled {
		return false, ReasonDisabled
	}
	s.Name = strings.TrimSpace(s.Name)
	s.Kind = strings.ToLower(strings.TrimSpace(s.Kind))
	if s.Name == "" {
		return false, ReasonEmpty
	}

	// Correlation first: an orphan is dropped before it is worth redacting.
	if s.ParentSpanID == "" && g.dropOrphans {
		return false, ReasonOrphan
	}

	// A failed operation is kept however fast it was. "It returned in 200µs"
	// and "it returned in 200µs with an error" are not the same event, and the
	// second is the one someone is looking for.
	if g.minDuration > 0 && s.Error == "" &&
		time.Duration(s.DurationMS*float64(time.Millisecond)) < g.minDuration {
		return false, ReasonTooFast
	}

	// Redaction BEFORE the cap check, so a span dropped by the cap was never
	// held in raw form any longer than one that is kept.
	g.scrub(s)

	if s.ParentSpanID != "" && !g.counter.Allow(s.ParentSpanID, g.maxPer) {
		return false, ReasonRequestCap
	}
	return true, ""
}

// scrub redacts every attribute value and the error text.
func (g *Governor) scrub(s *ext.Span) {
	s.Error = g.clean(s.Error, &s.Truncated)
	for k, v := range s.Attrs {
		if g.redactAttr[strings.ToLower(k)] {
			s.Attrs[k] = "[REDACTED]"
			continue
		}
		s.Attrs[k] = g.clean(v, &s.Truncated)
	}
}

// clean applies the redaction patterns and the byte cap to one value.
//
// Order matters: redact first, then truncate. Truncating first can cut a
// secret in half and leave the front of it stored — and a pattern anchored to
// the whole token would then no longer match what remains.
func (g *Governor) clean(v string, truncated *bool) string {
	if v == "" {
		return v
	}
	for _, re := range g.patterns {
		v = re.ReplaceAllString(v, "[REDACTED]")
	}
	if g.maxBytes > 0 && len(v) > g.maxBytes {
		v = telcap.TruncateUTF8(v, g.maxBytes)
		*truncated = true
	}
	return v
}
