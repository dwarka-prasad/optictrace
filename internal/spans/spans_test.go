package spans

import (
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
)

func gov(t *testing.T, cfg *config.SpansCfg) *Governor {
	t.Helper()
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return g
}

func span(parent, name string, ms float64) *ext.Span {
	return &ext.Span{ParentSpanID: parent, SpanID: "s", Name: name, DurationMS: ms,
		Attrs: map[string]string{}}
}

// A disabled feature must reject with a reason rather than silently accept and
// discard, which is how the FastAPI SDK shipped nothing for weeks.
func TestDisabledRejectsWithAReason(t *testing.T) {
	g := gov(t, nil)
	ok, why := g.Admit(span("p", "db.query", 5))
	if ok || why != ReasonDisabled {
		t.Errorf("got ok=%v reason=%q", ok, why)
	}
}

// The statement is the whole risk. A driver that interpolates parameters puts
// customer data in the one field a breakdown most wants to show.
func TestAttributesAreRedactedBeforeStorage(t *testing.T) {
	g := gov(t, &config.SpansCfg{
		Enabled: true,
		Redact: config.SpanRedact{
			Patterns: []string{`\b\d{13,19}\b`, `[\w.+-]+@[\w-]+\.[\w.]+`},
			Fields:   []string{"cache.key"},
		},
	})
	s := span("p", "db.query", 12)
	s.Attrs["db.statement"] = "SELECT * FROM cards WHERE number = '4111111111111111' AND email = 'a@b.com'"
	s.Attrs["cache.key"] = "session:cust-9931"
	s.Error = "duplicate key 4111111111111111"

	if ok, why := g.Admit(s); !ok {
		t.Fatalf("dropped: %s", why)
	}
	if strings.Contains(s.Attrs["db.statement"], "4111111111111111") {
		t.Errorf("card number survived in the statement: %s", s.Attrs["db.statement"])
	}
	if strings.Contains(s.Attrs["db.statement"], "a@b.com") {
		t.Errorf("email survived in the statement: %s", s.Attrs["db.statement"])
	}
	if s.Attrs["cache.key"] != "[REDACTED]" {
		t.Errorf("a listed field must be replaced wholesale, got %q", s.Attrs["cache.key"])
	}
	if strings.Contains(s.Error, "4111111111111111") {
		t.Errorf("driver errors quote the statement too: %q", s.Error)
	}
	if !strings.Contains(s.Attrs["db.statement"], "SELECT") {
		t.Error("redaction must leave the statement shape readable")
	}
}

// Truncating before redacting would cut a secret in half and store the front
// of it — and a pattern anchored to the whole token would stop matching.
func TestRedactionHappensBeforeTruncation(t *testing.T) {
	g := gov(t, &config.SpansCfg{
		Enabled:      true,
		MaxAttrBytes: 40,
		Redact:       config.SpanRedact{Patterns: []string{`\b\d{16}\b`}},
	})
	s := span("p", "db.query", 5)
	// The card sits past the byte cap: truncate-then-redact would drop the
	// pattern's tail, leave a fragment, and never match.
	s.Attrs["db.statement"] = strings.Repeat("x", 35) + " 4111111111111111"
	if ok, why := g.Admit(s); !ok {
		t.Fatalf("dropped: %s", why)
	}
	if strings.Contains(s.Attrs["db.statement"], "4111") {
		t.Errorf("a fragment of the card was stored: %q", s.Attrs["db.statement"])
	}
	if len(s.Attrs["db.statement"]) > 40 {
		t.Errorf("%d bytes, cap 40", len(s.Attrs["db.statement"]))
	}
	if !s.Truncated {
		t.Error("truncation not flagged")
	}
}

// A fast cache hit repeated a thousand times is volume without information.
// A fast FAILURE is the opposite, and must survive the same filter.
func TestMinDurationKeepsErrorsHoweverFast(t *testing.T) {
	g := gov(t, &config.SpansCfg{Enabled: true, MinDuration: 5 * time.Millisecond})
	if ok, why := g.Admit(span("p", "redis.get", 0.2)); ok || why != ReasonTooFast {
		t.Errorf("a 0.2ms success should be dropped, got ok=%v %q", ok, why)
	}
	failed := span("p", "redis.get", 0.2)
	failed.Error = "connection refused"
	if ok, why := g.Admit(failed); !ok {
		t.Errorf("a fast FAILURE must be kept, dropped as %q", why)
	}
}

func TestOrphansAndCaps(t *testing.T) {
	g := gov(t, &config.SpansCfg{Enabled: true, MaxPerRequest: 3})
	if ok, why := g.Admit(span("", "job.tick", 5)); ok || why != ReasonOrphan {
		t.Errorf("a span with no parent must not be attributed to a request: ok=%v %q", ok, why)
	}
	for i := 0; i < 3; i++ {
		if ok, why := g.Admit(span("req", "db.query", 5)); !ok {
			t.Fatalf("span %d of 3 dropped: %s", i+1, why)
		}
	}
	if ok, why := g.Admit(span("req", "db.query", 5)); ok || why != ReasonRequestCap {
		t.Errorf("the cap must hold: ok=%v %q", ok, why)
	}

	// -1 means no cap at all.
	unlimited := gov(t, &config.SpansCfg{Enabled: true, MaxPerRequest: -1})
	for i := 0; i < 500; i++ {
		if ok, why := unlimited.Admit(span("req", "db.query", 5)); !ok {
			t.Fatalf("max_per_request:-1 must mean unlimited, dropped at %d: %s", i, why)
		}
	}
}

func TestAnUnnamedSpanIsDropped(t *testing.T) {
	g := gov(t, &config.SpansCfg{Enabled: true})
	if ok, why := g.Admit(span("p", "   ", 5)); ok || why != ReasonEmpty {
		t.Errorf("nothing to file it under: ok=%v %q", ok, why)
	}
}
