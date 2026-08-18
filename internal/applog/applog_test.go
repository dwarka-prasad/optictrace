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
func TestSpanCounterMemoryIsBounded(t *testing.T) {
	g := newGov(t, &config.AppLogsCfg{Enabled: true, MaxLinesPerSpan: 5})
	g.maxSpans = 64
	for i := 0; i < 10_000; i++ {
		g.Admit(&ext.AppLog{SpanID: fmt.Sprintf("span-%d", i), Message: "x"})
	}
	g.mu.Lock()
	total := len(g.cur) + len(g.prev)
	g.mu.Unlock()
	if total > 2*g.maxSpans {
		t.Errorf("tracked %d spans, want <= %d", total, 2*g.maxSpans)
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
