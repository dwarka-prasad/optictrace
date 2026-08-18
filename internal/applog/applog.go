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
	"regexp"
	"strings"
	"sync"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
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
	ReasonOrphan   Reason = "orphan"   // no span id — belongs to no request
	ReasonLevel    Reason = "level"    // below level_min
	ReasonSpanCap  Reason = "span_cap" // span already at max_lines_per_span
	ReasonDisabled Reason = "disabled" // feature off
	ReasonEmpty    Reason = "empty"    // nothing left after trimming
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

	// Per-span line counts, memory-bounded by design. An unbounded map keyed
	// by span id is a slow leak: every request that ever logged would be
	// remembered forever. Two generations are kept and the older is dropped
	// wholesale once the newer fills, so the count is exact for recent spans
	// and forgotten for old ones — which is the right trade, since the cap
	// exists to stop a burst, not to be an audited total.
	mu       sync.Mutex
	cur      map[string]int
	prev     map[string]int
	maxSpans int
}

// New builds a Governor from config. A nil or disabled config yields a
// Governor that rejects everything with ReasonDisabled, so callers need no
// special case.
func New(cfg *config.AppLogsCfg) (*Governor, error) {
	g := &Governor{
		maxSpans:    defaultMaxTrackedSpans,
		cur:         map[string]int{},
		prev:        map[string]int{},
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
	if g.minRank >= 0 && ext.LevelRank(l.Level) < g.minRank {
		return false, ReasonLevel
	}

	// Redaction BEFORE the cap check, so that a line dropped by the cap was
	// never held in memory in its raw form any longer than one that is kept.
	g.scrub(l)

	l.Message = strings.TrimSpace(l.Message)
	if l.Message == "" && len(l.Fields) == 0 {
		return false, ReasonEmpty
	}
	if g.maxBytes > 0 && len(l.Message) > g.maxBytes {
		l.Message = truncateUTF8(l.Message, g.maxBytes)
		l.Truncated = true
	}

	if l.SpanID != "" && g.maxLines > 0 && !g.allow(l.SpanID) {
		return false, ReasonSpanCap
	}
	return true, ""
}

// scrub applies redaction to the message and every field value.
func (g *Governor) scrub(l *ext.AppLog) {
	for _, re := range g.patterns {
		l.Message = re.ReplaceAllString(l.Message, "[REDACTED]")
	}
	for k, v := range l.Fields {
		if g.redactField[strings.ToLower(k)] {
			l.Fields[k] = "[REDACTED]"
			continue
		}
		// A token in a field is exactly as leaked as one in the message.
		for _, re := range g.patterns {
			v = re.ReplaceAllString(v, "[REDACTED]")
		}
		l.Fields[k] = v
	}
}

// allow reports whether this span may store another line, and counts it.
func (g *Governor) allow(span string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	n, ok := g.cur[span]
	if !ok {
		if p, hit := g.prev[span]; hit {
			n = p
		}
	}
	if n >= g.maxLines {
		return false
	}
	if len(g.cur) >= g.maxSpans && !ok {
		g.prev, g.cur = g.cur, make(map[string]int, g.maxSpans)
	}
	g.cur[span] = n + 1
	return true
}

// truncateUTF8 cuts to at most max bytes without splitting a rune, so a
// truncated stack trace is still valid UTF-8 and still renders.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

// utf8Start reports whether b begins a rune (i.e. is not a continuation byte).
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
