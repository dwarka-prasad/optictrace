package applog

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
)

func newGov(t *testing.T, cfg *config.AppLogsCfg) *Governor {
	t.Helper()
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func boolPtr(b bool) *bool { return &b }

// The reason this feature is dangerous: a log line carries whatever someone
// pasted into it. If redaction does not reach the message AND every field, the
// store becomes the biggest leak in a tool built to prevent leaks.
func TestRedactionCoversMessageAndFields(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{
		Enabled: true,
		Redact: config.AppLogRedact{
			Patterns: []string{`Bearer\s+\S+`, `\b\d{16}\b`},
			Fields:   []string{"Authorization"},
		},
	})
	l := &ext.AppLog{
		SpanID:  "abc",
		Message: "calling upstream with Bearer topsecret123 for card 4111111111111111",
		Fields: map[string]string{
			"authorization": "Bearer another-secret",
			"note":          "card 4111111111111111 declined",
			"safe":          "order-42",
		},
	}
	ok, reason := g.Admit(l)
	if !ok {
		t.Fatalf("line dropped: %s", reason)
	}
	for _, leak := range []string{"topsecret123", "4111111111111111", "another-secret"} {
		if strings.Contains(l.Message, leak) {
			t.Errorf("message leaked %q: %s", leak, l.Message)
		}
		for k, v := range l.Fields {
			if strings.Contains(v, leak) {
				t.Errorf("field %s leaked %q: %s", k, leak, v)
			}
		}
	}
	if l.Fields["safe"] != "order-42" {
		t.Errorf("redaction ate an innocent field: %q", l.Fields["safe"])
	}
}

// The user's choice: lines with no span are discarded. The drop must be
// reported so it can be counted, never swallowed.
func TestOrphansDroppedWithReason(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true})
	ok, reason := g.Admit(&ext.AppLog{Message: "server started"})
	if ok || reason != ReasonOrphan {
		t.Fatalf("want drop/orphan, got ok=%v reason=%q", ok, reason)
	}
	// And the escape hatch works without a code change.
	g2 := newGov(t, &config.AppLogsCfg{Enabled: true, DropOrphans: boolPtr(false)})
	if ok, reason := g2.Admit(&ext.AppLog{Message: "server started"}); !ok {
		t.Fatalf("drop_orphans:false should keep the line, got %q", reason)
	}
}

func TestLevelFloor(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true, LevelMin: "warn"})
	if ok, r := g.Admit(&ext.AppLog{SpanID: "s", Level: "debug", Message: "noise"}); ok || r != ReasonLevel {
		t.Errorf("debug should be dropped below warn: ok=%v r=%q", ok, r)
	}
	if ok, _ := g.Admit(&ext.AppLog{SpanID: "s", Level: "warning", Message: "kept"}); !ok {
		t.Error(`"warning" should normalise to warn and be kept`)
	}
	// An unrecognised level must survive a floor. Dropping someone's custom
	// "panic" because it is not in our list is the wrong failure.
	if ok, _ := g.Admit(&ext.AppLog{SpanID: "s", Level: "emergency", Message: "kept"}); !ok {
		t.Error("unknown level should outrank the floor, not be dropped")
	}
}

func TestSpanCapBoundsOneRequest(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true, MaxLinesPerSpan: 3})
	kept := 0
	for i := 0; i < 10; i++ {
		if ok, _ := g.Admit(&ext.AppLog{SpanID: "hot", Message: fmt.Sprintf("line %d", i)}); ok {
			kept++
		}
	}
	if kept != 3 {
		t.Errorf("cap 3 kept %d lines", kept)
	}
	// A different span has its own budget.
	if ok, _ := g.Admit(&ext.AppLog{SpanID: "other", Message: "x"}); !ok {
		t.Error("one span's burst must not spend another span's budget")
	}
}

// The per-span counter is the obvious place to leak memory: one entry per
// request, forever. Two generations bound it.
// The counter's memory bound is now telcap's, and is asserted there against
// the map sizes directly. What matters HERE is that the per-span cap still
// holds after many other spans have been seen — i.e. that forgetting old spans
// does not also forget the cap for a span still in flight.
func TestSpanCapSurvivesOtherTraffic(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true, MaxLinesPerSpan: 3})
	admit := func(span string) bool {
		ok, _ := g.Admit(&ext.AppLog{SpanID: span, Message: "x"})
		return ok
	}
	for i := 0; i < 3; i++ {
		if !admit("hot") {
			t.Fatalf("line %d of 3 rejected", i+1)
		}
	}
	for i := 0; i < 1000; i++ {
		admit(fmt.Sprintf("other-%d", i))
	}
	if admit("hot") {
		t.Error("cap forgotten for a span still in flight after other traffic")
	}
}

func TestTruncationKeepsValidUTF8(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true, MaxMessageBytes: 10})
	l := &ext.AppLog{SpanID: "s", Message: strings.Repeat("é", 20)} // 2 bytes each
	if ok, r := g.Admit(l); !ok {
		t.Fatalf("dropped: %s", r)
	}
	if !l.Truncated {
		t.Error("truncation not flagged")
	}
	if len(l.Message) > 10 {
		t.Errorf("message %d bytes, cap 10", len(l.Message))
	}
	for _, r := range l.Message {
		if r == '�' {
			t.Fatal("truncation split a rune")
		}
	}
}

func TestDisabledGovernorRejectsEverything(t *testing.T) {
	g := newGov(t, nil)
	if g.Enabled() {
		t.Error("nil config should be disabled")
	}
	if ok, r := g.Admit(&ext.AppLog{SpanID: "s", Message: "x"}); ok || r != ReasonDisabled {
		t.Errorf("want drop/disabled, got ok=%v r=%q", ok, r)
	}
}

func TestConcurrentAdmitIsSafe(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true, MaxLinesPerSpan: 1000})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g.Admit(&ext.AppLog{SpanID: fmt.Sprintf("s-%d", n%8), Message: "x"})
			}
		}(i)
	}
	wg.Wait()
}

// The whole safety argument for trusting a producer-supplied route is that a
// per-rule block can only TIGHTEN. If it could loosen, telemetry.app_logs
// would be a suggestion rather than a guarantee, and a lying client could ask
// for less protection than the floor.
func TestPerRuleLogsOnlyTightens(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{
		Enabled:         true,
		LevelMin:        "info",
		MaxLinesPerSpan: 100,
		Redact:          config.AppLogRedact{Patterns: []string{`GLOBAL-\d+`}},
	})
	if err := g.WithRules([]config.Rule{
		{
			Name:  "strict-payments",
			Match: config.Match{Path: "/api/v1/payments/**"},
			Logs: &config.RuleLogs{
				LevelMin:        "error",
				MaxLinesPerSpan: 2,
				Redact:          config.AppLogRedact{Patterns: []string{`RULE-\d+`}, Fields: []string{"pan"}},
			},
		},
		{
			// Tries to loosen every setting. All of it must be ignored.
			Name:  "loose-health",
			Match: config.Match{Path: "/healthz"},
			Logs: &config.RuleLogs{
				LevelMin:        "debug", // lower than the global floor
				MaxLinesPerSpan: 9000,    // higher than the global cap
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// --- the strict route ------------------------------------------------
	if ok, r := g.Admit(&ext.AppLog{SpanID: "s1", Route: "/api/v1/payments/**",
		Level: "warn", Message: "noise"}); ok || r != ReasonLevel {
		t.Errorf("a rule raising the floor to error kept a warn: ok=%v r=%q", ok, r)
	}
	l := &ext.AppLog{SpanID: "s1", Route: "/api/v1/payments/**", Level: "error",
		Message: "failed with RULE-123 and GLOBAL-456",
		Fields:  map[string]string{"pan": "4111111111111111", "amount": "42"}}
	if ok, r := g.Admit(l); !ok {
		t.Fatalf("an error line on the strict route was dropped: %q", r)
	}
	if strings.Contains(l.Message, "RULE-123") {
		t.Errorf("the rule's own pattern did not apply: %q", l.Message)
	}
	if strings.Contains(l.Message, "GLOBAL-456") {
		t.Errorf("a rule block must ADD to the global patterns, not replace them: %q", l.Message)
	}
	if l.Fields["pan"] != "[REDACTED]" {
		t.Errorf("the rule's field redaction did not apply: %v", l.Fields)
	}
	if l.Fields["amount"] != "42" {
		t.Errorf("redaction ate an innocent field: %v", l.Fields)
	}

	// The rule's cap of 2 applies, not the global 100. One line is already in.
	kept := 1
	for i := 0; i < 5; i++ {
		if ok, _ := g.Admit(&ext.AppLog{SpanID: "s1", Route: "/api/v1/payments/**",
			Level: "error", Message: "more"}); ok {
			kept++
		}
	}
	if kept != 2 {
		t.Errorf("the rule cap of 2 kept %d lines", kept)
	}

	// --- the route that tried to loosen ----------------------------------
	if ok, r := g.Admit(&ext.AppLog{SpanID: "s2", Route: "/healthz",
		Level: "debug", Message: "chatty"}); ok || r != ReasonLevel {
		t.Errorf("a rule lowered the global floor: ok=%v r=%q", ok, r)
	}
	// And its inflated cap must not beat the global one.
	allowed := 0
	for i := 0; i < 150; i++ {
		if ok, _ := g.Admit(&ext.AppLog{SpanID: "s3", Route: "/healthz",
			Level: "info", Message: "tick"}); ok {
			allowed++
		}
	}
	if allowed != 100 {
		t.Errorf("a rule raised the global cap: %d lines allowed, want 100", allowed)
	}

	// --- an unknown or absent route gets the global policy ---------------
	// Safe precisely because rules only tighten: the worst a producer can do
	// by lying is land on the floor.
	unknown := &ext.AppLog{SpanID: "s4", Route: "/who/knows", Level: "info",
		Message: "GLOBAL-999 and RULE-999"}
	if ok, r := g.Admit(unknown); !ok {
		t.Fatalf("an unknown route was dropped: %q", r)
	}
	if strings.Contains(unknown.Message, "GLOBAL-999") {
		t.Error("the global pattern did not apply to an unknown route")
	}
	if !strings.Contains(unknown.Message, "RULE-999") {
		t.Error("another rule's pattern leaked onto an unrelated route")
	}
}

func TestRuleLogsDropDiscardsWithItsOwnReason(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true})
	if err := g.WithRules([]config.Rule{{
		Name:  "no-logs-here",
		Match: config.Match{Path: "/debug/**"},
		Logs:  &config.RuleLogs{Drop: true},
	}}); err != nil {
		t.Fatal(err)
	}
	if ok, r := g.Admit(&ext.AppLog{SpanID: "s", Route: "/debug/pprof", Level: "info", Message: "x"}); ok || r != ReasonRuleDrop {
		t.Errorf("want drop/rule_drop, got ok=%v r=%q", ok, r)
	}
	// Everything else is unaffected.
	if ok, _ := g.Admit(&ext.AppLog{SpanID: "s", Route: "/api/v1/orders", Level: "info", Message: "x"}); !ok {
		t.Error("logs.drop on one route silenced another")
	}
}
