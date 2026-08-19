package applog

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
)

type fakeSink struct {
	mu    sync.Mutex
	lines []ext.AppLog
}

func (f *fakeSink) SaveAppLogs(_ context.Context, lines []ext.AppLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lines = append(f.lines, lines...)
	return nil
}

func (f *fakeSink) all() []ext.AppLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ext.AppLog{}, f.lines...)
}

func newCollector(t *testing.T, cfg *config.AppLogsCfg) (*Collector, *fakeSink, map[string]int) {
	t.Helper()
	g := newGov(t, cfg)
	sink := &fakeSink{}
	c := NewCollector(g, sink, "svc", nil)
	c.interval = 20 * time.Millisecond

	drops := map[string]int{}
	var mu sync.Mutex
	c.OnDrop(func(reason string) {
		mu.Lock()
		drops[reason]++
		mu.Unlock()
	})
	c.Start(context.Background())
	t.Cleanup(c.Close)
	return c, sink, drops
}

func TestCollectorParsesStructuredLines(t *testing.T) {
	c, sink, _ := newCollector(t, &config.AppLogsCfg{
		Enabled: true, LevelMin: "debug",
		Redact: config.AppLogRedact{Patterns: []string{`Bearer\s+\S+`}},
	})

	var echoed bytes.Buffer
	in := strings.NewReader(strings.Join([]string{
		`{"time":"2026-08-19T10:00:00Z","level":"error","message":"charge failed","span_id":"abc123abc123abc1","trace_id":"t1","route":"/pay/**","order":"ord-1","attempt":2}`,
		`{"level":"info","msg":"uses msg not message","span_id":"abc123abc123abc1"}`,
		`not json at all, but a panic trace is never json`,
		`{"level":"warn","message":"leaking Bearer topsecret123","span_id":"abc123abc123abc1"}`,
		``,
	}, "\n"))

	c.Read(context.Background(), in, config.AppLogSource{Type: "stdout"}, &echoed)
	c.Close()

	got := sink.all()
	// Three, not four: the non-JSON line has no span, so it is an orphan and
	// the default policy drops it. Worth stating explicitly, because it is the
	// tailer's sharpest edge — a panic trace interleaved into a JSON log is
	// exactly the line you want and exactly the one with no span. The answer is
	// drop_orphans: false or a span_pattern, not guessing an owner from the
	// preceding line: under concurrency that attributes one request's stack
	// trace to another's span.
	if len(got) != 3 {
		t.Fatalf("collected %d line(s), want 3: %+v", len(got), got)
	}

	first := got[0]
	if first.Level != "error" || first.Message != "charge failed" {
		t.Errorf("level/message: %q %q", first.Level, first.Message)
	}
	if first.SpanID != "abc123abc123abc1" || first.TraceID != "t1" || first.Route != "/pay/**" {
		t.Errorf("correlation fields lost: %+v", first)
	}
	if first.Time.UTC().Format(time.RFC3339) != "2026-08-19T10:00:00Z" {
		t.Errorf("the line's own timestamp was ignored: %s", first.Time)
	}
	// Structure is the point of a structured log; keeping only the message
	// would throw away what makes it worth collecting.
	if first.Fields["order"] != "ord-1" || first.Fields["attempt"] != "2" {
		t.Errorf("extra fields lost: %v", first.Fields)
	}
	if _, dup := first.Fields["span_id"]; dup {
		t.Errorf("span_id duplicated into fields: %v", first.Fields)
	}

	if got[1].Message != "uses msg not message" {
		t.Errorf("a logger writing msg should not need configuring: %q", got[1].Message)
	}
	if strings.Contains(got[2].Message, "topsecret123") {
		t.Errorf("collected lines must be redacted like ingested ones: %q", got[2].Message)
	}

	// Collecting must not stop the logs reaching wherever operators already
	// read them — including the line that was NOT stored.
	if !strings.Contains(echoed.String(), "charge failed") ||
		!strings.Contains(echoed.String(), "panic trace") {
		t.Errorf("lines were swallowed instead of echoed:\n%s", echoed.String())
	}
	// And the echo is the ORIGINAL text, not the redacted one — this process
	// does not get to rewrite another program's output stream.
	if !strings.Contains(echoed.String(), "Bearer topsecret123") {
		t.Error("the echoed stream was altered; it must pass through untouched")
	}
}

func TestCollectorExtractsSpanFromAPattern(t *testing.T) {
	c, sink, _ := newCollector(t, &config.AppLogsCfg{Enabled: true, LevelMin: "debug"})
	in := strings.NewReader("2026-08-19 INFO [span=abc123abc123abc1] charge captured\n")
	c.Read(context.Background(), in, config.AppLogSource{
		Type: "stdout", Format: "text", SpanPattern: `span=([0-9a-f]{16})`,
	}, nil)
	c.Close()

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("collected %d line(s), want 1", len(got))
	}
	if got[0].SpanID != "abc123abc123abc1" {
		t.Errorf("span not extracted from the text line: %q", got[0].SpanID)
	}
}

// Orphans are the normal case for a text log, and they must be COUNTED rather
// than vanishing — otherwise "my logs aren't appearing" has no explanation.
func TestCollectorCountsDroppedOrphans(t *testing.T) {
	c, sink, drops := newCollector(t, &config.AppLogsCfg{Enabled: true, LevelMin: "debug"})
	c.Read(context.Background(), strings.NewReader("a line with no span at all\n"),
		config.AppLogSource{Type: "stdout", Format: "text"}, nil)
	c.Close()

	if n := len(sink.all()); n != 0 {
		t.Errorf("stored %d orphan line(s); the default is to drop them", n)
	}
	if drops["orphan"] != 1 {
		t.Errorf("orphan drops = %v, want orphan:1", drops)
	}
}

func TestTailFollowsAppendsAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte(`{"message":"history","span_id":"aaaaaaaaaaaaaaa1"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c, sink, _ := newCollector(t, &config.AppLogsCfg{Enabled: true, LevelMin: "debug"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Tail(ctx, config.AppLogSource{Type: "file", Path: path})
	time.Sleep(150 * time.Millisecond)

	appendLine := func(p, text string) {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(text + "\n")
		f.Close()
	}
	appendLine(path, `{"message":"appended","span_id":"aaaaaaaaaaaaaaa1"}`)
	time.Sleep(300 * time.Millisecond)

	// Rotate the way logrotate does: move the file aside, create a new one.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(path, `{"message":"after rotation","span_id":"aaaaaaaaaaaaaaa1"}`)
	time.Sleep(600 * time.Millisecond)
	cancel()
	c.Close()

	var seen []string
	for _, l := range sink.all() {
		seen = append(seen, l.Message)
	}
	joined := strings.Join(seen, "|")

	// Starting at the end is deliberate: replaying a large log on every restart
	// would flood the store with history nobody asked for, and retention would
	// then discard the recent lines that were actually wanted.
	if strings.Contains(joined, "history") {
		t.Errorf("tail replayed pre-existing history: %q", joined)
	}
	if !strings.Contains(joined, "appended") {
		t.Errorf("tail missed an appended line: %q", joined)
	}
	if !strings.Contains(joined, "after rotation") {
		t.Errorf("tail did not follow the rotation: %q", joined)
	}
}
