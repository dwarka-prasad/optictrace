// Package applog governs application log lines on the way into the store.
//
// App logs are the highest-risk surface OpticTrace touches. A payload is
// structured and can be redacted by JSON path; a log line is free text written
// by whoever was debugging that day, and it routinely carries bearer tokens,
// email addresses and whole request bodies inside stack traces. So lines are
// scrubbed and capped BEFORE they are persisted rather than stored raw and
// cleaned up later — "later" is after the data is already at rest.
package applog

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/telcap"
)

// Defaults chosen so that turning the feature on without tuning it cannot
// swamp the store: a debug-level floor would be, and one pathological retry
// loop would.
const (
	DefaultMaxLinesPerSpan = 200
	DefaultMaxMessageBytes = 8 << 10 // 8 KiB — enough for a stack trace head
	defaultMaxTrackedSpans = 4096
)

// Reason explains why a line was not stored. Every drop is counted under one
// of these: data discarded silently is data nobody knows they are missing.
type Reason string

const (
	ReasonOrphan   Reason = "orphan"    // no span id — belongs to no request
	ReasonLevel    Reason = "level"     // below level_min
	ReasonSpanCap  Reason = "span_cap"  // span already at max_lines_per_span
	ReasonDisabled Reason = "disabled"  // feature off
	ReasonEmpty    Reason = "empty"     // nothing left after trimming
	ReasonRuleDrop Reason = "rule_drop" // a rule's logs.drop discarded it
)

// Governor applies the app-log policy. Safe for concurrent use: ingest is an
// HTTP handler and several requests land at once.
type Governor struct {
	enabled     bool
	dropOrphans bool
	minRank     int
	maxLines    int
	maxBytes    int
	patterns    []*regexp.Regexp
	redactField map[string]bool

	// Per-span line counts, memory-bounded by design — see telcap.Counter.
	counter *telcap.Counter

	// routes are per-rule overrides, checked in config order so that later
	// rules win the same way they do everywhere else in optic.yaml.
	routes []routePolicy
}

// routePolicy is one rule's compiled `logs:` block.
type routePolicy struct {
	name     string
	segs     []string
	minRank  int // -1 = no override
	maxLines int // 0 = no override
	drop     bool
	patterns []*regexp.Regexp
	fields   map[string]bool
}

// effective is the policy actually applied to one line: the global settings,
// tightened by every rule whose path matches.
type effective struct {
	minRank  int
	maxLines int
	drop     bool
	patterns []*regexp.Regexp
	fields   map[string]bool
}

// New builds a Governor from config. A nil or disabled config yields a
// Governor that rejects everything with ReasonDisabled, so callers need no
// special case.
func New(cfg *config.AppLogsCfg) (*Governor, error) {
	g := &Governor{
		counter:     telcap.NewCounter(defaultMaxTrackedSpans),
		redactField: map[string]bool{},
	}
	if cfg == nil || !cfg.Enabled {
		return g, nil
	}
	g.enabled = true
	g.dropOrphans = cfg.DropOrphanLines()

	g.minRank = -1
	if cfg.LevelMin != "" {
		g.minRank = ext.LevelRank(cfg.LevelMin)
	}

	g.maxLines = cfg.MaxLinesPerSpan
	if g.maxLines == 0 {
		g.maxLines = DefaultMaxLinesPerSpan
	}
	g.maxBytes = cfg.MaxMessageBytes
	if g.maxBytes == 0 {
		g.maxBytes = DefaultMaxMessageBytes
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
		g.redactField[strings.ToLower(f)] = true
	}
	return g, nil
}

// WithRules compiles the per-rule `logs:` blocks. Call after New.
//
// These can only TIGHTEN what New established. A per-route override able to
// weaken the global policy would make telemetry.app_logs a suggestion rather
// than a guarantee, and reviewing one file would stop telling you what is
// enforced.
func (g *Governor) WithRules(rules []config.Rule) error {
	for _, r := range rules {
		if r.Logs == nil {
			continue
		}
		rp := routePolicy{
			name:     r.Name,
			segs:     engine.SplitPath(r.Match.Path),
			minRank:  -1,
			maxLines: r.Logs.MaxLinesPerSpan,
			drop:     r.Logs.Drop,
			fields:   map[string]bool{},
		}
		if r.Logs.LevelMin != "" {
			rp.minRank = ext.LevelRank(r.Logs.LevelMin)
		}
		for _, pat := range r.Logs.Redact.Patterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				return fmt.Errorf("rule %q logs.redact: %w", r.Name, err)
			}
			rp.patterns = append(rp.patterns, re)
		}
		for _, f := range r.Logs.Redact.Fields {
			rp.fields[strings.ToLower(f)] = true
		}
		g.routes = append(g.routes, rp)
	}
	return nil
}

// resolve merges the global policy with every rule matching this line's route.
//
// A line with no route — or an unrecognised one — gets the global policy. That
// is safe precisely because rules only tighten: an unknown route can never end
// up with less protection than the floor, which is why the route may be taken
// from the producer without verifying it.
func (g *Governor) resolve(route string) effective {
	eff := effective{
		minRank:  g.minRank,
		maxLines: g.maxLines,
		patterns: g.patterns,
		fields:   g.redactField,
	}
	if route == "" || len(g.routes) == 0 {
		return eff
	}
	segs := engine.SplitPath(route)
	for i := range g.routes {
		rp := &g.routes[i]
		// Exact pattern match first: a governed record's Route IS the rule's
		// glob, so the common case needs no globbing at all.
		if !(route == "/"+strings.Join(rp.segs, "/") || engine.MatchSegments(rp.segs, segs)) {
			continue
		}
		if rp.drop {
			eff.drop = true
		}
		// Tighten only: a HIGHER floor and a LOWER cap.
		if rp.minRank > eff.minRank {
			eff.minRank = rp.minRank
		}
		if rp.maxLines > 0 && (eff.maxLines <= 0 || rp.maxLines < eff.maxLines) {
			eff.maxLines = rp.maxLines
		}
		if len(rp.patterns) > 0 {
			merged := make([]*regexp.Regexp, 0, len(eff.patterns)+len(rp.patterns))
			merged = append(merged, eff.patterns...)
			merged = append(merged, rp.patterns...)
			eff.patterns = merged
		}
		if len(rp.fields) > 0 {
			merged := make(map[string]bool, len(eff.fields)+len(rp.fields))
			for k := range eff.fields {
				merged[k] = true
			}
			for k := range rp.fields {
				merged[k] = true
			}
			eff.fields = merged
		}
	}
	return eff
}

// Enabled reports whether app-log ingestion is turned on.
func (g *Governor) Enabled() bool { return g.enabled }

// Admit applies the policy to one line. It returns the governed line and true
// when it should be stored, or the reason it was dropped.
//
// The line is mutated in place: redaction must happen before anything else
// can hold a reference to the raw text.
func (g *Governor) Admit(l *ext.AppLog) (bool, Reason) {
	if !g.enabled {
		return false, ReasonDisabled
	}
	l.Level = ext.NormaliseLevel(l.Level)

	// Correlation first: an orphan is dropped before it is worth redacting.
	if l.SpanID == "" && g.dropOrphans {
		return false, ReasonOrphan
	}

	// The route decides which per-rule block applies. Resolved per line rather
	// than cached per span, because a producer may report a different route on
	// the same span and the tighter answer must win either way.
	eff := g.resolve(l.Route)
	if eff.drop {
		return false, ReasonRuleDrop
	}
	if eff.minRank >= 0 && ext.LevelRank(l.Level) < eff.minRank {
		return false, ReasonLevel
	}

	// Redaction BEFORE the cap check, so that a line dropped by the cap was
	// never held in memory in its raw form any longer than one that is kept.
	g.scrub(l, eff)

	l.Message = strings.TrimSpace(l.Message)
	if l.Message == "" && len(l.Fields) == 0 {
		return false, ReasonEmpty
	}
	if g.maxBytes > 0 && len(l.Message) > g.maxBytes {
		l.Message = telcap.TruncateUTF8(l.Message, g.maxBytes)
		l.Truncated = true
	}

	if l.SpanID != "" && eff.maxLines > 0 && !g.allow(l.SpanID, eff.maxLines) {
		return false, ReasonSpanCap
	}
	return true, ""
}

// scrub applies redaction to the message and every field value, using the
// resolved policy so a rule's extra patterns are honoured.
func (g *Governor) scrub(l *ext.AppLog, eff effective) {
	for _, re := range eff.patterns {
		l.Message = re.ReplaceAllString(l.Message, "[REDACTED]")
	}
	for k, v := range l.Fields {
		if eff.fields[strings.ToLower(k)] {
			l.Fields[k] = "[REDACTED]"
			continue
		}
		// A token in a field is exactly as leaked as one in the message.
		for _, re := range eff.patterns {
			v = re.ReplaceAllString(v, "[REDACTED]")
		}
		l.Fields[k] = v
	}
}

// allow reports whether this span may store another line, and counts it.
// maxLines is the resolved cap, which a per-rule block may have lowered.
func (g *Governor) allow(span string, maxLines int) bool {
	return g.counter.Allow(span, maxLines)
}
