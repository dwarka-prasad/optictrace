package export

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
)

// recordsOnly implements Exporter but NOT AppLogExporter — the third-party
// exporter that must keep working untouched.
type recordsOnly struct {
	mu   sync.Mutex
	seen int
}

func (r *recordsOnly) Name() string { return "records-only" }
func (r *recordsOnly) Type() string { return "test" }
func (r *recordsOnly) Export(_ context.Context, batch []*ext.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen += len(batch)
	return nil
}
func (r *recordsOnly) Close() error { return nil }

// bothStreams accepts records and log lines.
type bothStreams struct {
	mu      sync.Mutex
	records int
	logs    []string
}

func (b *bothStreams) Name() string { return "both" }
func (b *bothStreams) Type() string { return "test" }
func (b *bothStreams) Export(_ context.Context, batch []*ext.Record) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records += len(batch)
	return nil
}
func (b *bothStreams) ExportAppLogs(_ context.Context, batch []*ext.AppLog) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, l := range batch {
		b.logs = append(b.logs, l.Message)
	}
	return nil
}
func (b *bothStreams) Close() error { return nil }

func (b *bothStreams) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string{}, b.logs...)
}

// dispatcherWith builds a Dispatcher around pre-made exporters, mirroring what
// New does. Kept local so the test does not need config plumbing for a fake.
func dispatcherWith(t *testing.T, exps ...Exporter) *Dispatcher {
	t.Helper()
	d := &Dispatcher{logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
	for _, e := range exps {
		w := &worker{exp: e, queue: make(chan *ext.Record, 64), batchSize: 16, flushEach: 20 * time.Millisecond}
		if ale, ok := e.(ext.AppLogExporter); ok {
			w.logExp = ale
			w.logs = make(chan *ext.AppLog, 64)
		}
		d.workers = append(d.workers, w)
		d.wg.Add(1)
		go d.run(w)
	}
	return d
}

// The whole point of a separate optional interface: an exporter that predates
// app logs keeps compiling and keeps receiving records.
func TestRecordsOnlyExporterIsUnaffected(t *testing.T) {
	ro := &recordsOnly{}
	both := &bothStreams{}
	d := dispatcherWith(t, ro, both)

	if !d.AcceptsAppLogs() {
		t.Error("AcceptsAppLogs should be true when any exporter takes lines")
	}
	d.Enqueue(&ext.Record{Path: "/a"})
	d.EnqueueAppLog(&ext.AppLog{Message: "only the app-log exporter sees this"})
	d.Shutdown()

	ro.mu.Lock()
	seen := ro.seen
	ro.mu.Unlock()
	if seen != 1 {
		t.Errorf("records-only exporter received %d record(s), want 1", seen)
	}
	if got := both.lines(); len(got) != 1 || got[0] != "only the app-log exporter sees this" {
		t.Errorf("app-log exporter received %v", got)
	}
}

func TestNoAppLogExportersMeansNoWork(t *testing.T) {
	d := dispatcherWith(t, &recordsOnly{})
	if d.AcceptsAppLogs() {
		t.Error("AcceptsAppLogs must be false when nothing takes lines")
	}
	// Must not panic or block on an exporter with no log queue.
	d.EnqueueAppLog(&ext.AppLog{Message: "dropped on the floor, by design"})
	d.Shutdown()
}

// Shutdown closes both queues and select picks a ready arm at random, so the
// record arm can win while lines are still queued. Relying on close ORDER
// loses the last batch about half the time; this asserts the drain.
func TestShutdownDrainsQueuedLogLines(t *testing.T) {
	for attempt := 0; attempt < 25; attempt++ {
		both := &bothStreams{}
		// flushEach long enough that only the shutdown drain can deliver these.
		d := &Dispatcher{logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}
		w := &worker{exp: both, queue: make(chan *ext.Record, 64), batchSize: 100, flushEach: time.Hour,
			logExp: both, logs: make(chan *ext.AppLog, 64)}
		d.workers = append(d.workers, w)
		d.wg.Add(1)
		go d.run(w)

		for i := 0; i < 5; i++ {
			d.EnqueueAppLog(&ext.AppLog{Message: "queued"})
		}
		d.Enqueue(&ext.Record{Path: "/a"})
		d.Shutdown()

		if got := len(both.lines()); got != 5 {
			t.Fatalf("attempt %d: shutdown delivered %d of 5 queued lines", attempt, got)
		}
	}
}

func TestFileExporterWritesBothStreamsToOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	e, err := newFileExporter(&config.ExporterCfg{Name: "audit", Type: "file", Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Export(context.Background(), []*ext.Record{{Path: "/api/v1/pay", Status: 201}}); err != nil {
		t.Fatal(err)
	}
	if err := e.ExportAppLogs(context.Background(), []*ext.AppLog{
		{SpanID: "s1", Level: "error", Message: "gateway declined"},
	}); err != nil {
		t.Fatal(err)
	}
	e.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("wrote %d line(s), want 2:\n%s", len(lines), raw)
	}

	// A consumer must be able to tell what a line IS without guessing from
	// which fields happen to be present — a record and a log line share most.
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if _, tagged := first["kind"]; tagged {
		t.Error("records must stay untagged, so existing consumers keep parsing them")
	}
	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if second["kind"] != "app_log" {
		t.Errorf("log line not discriminated: %v", second)
	}
	if second["app_log"] == nil {
		t.Errorf("log line payload missing: %v", second)
	}
}
