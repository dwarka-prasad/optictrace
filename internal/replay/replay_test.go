package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

func TestReplayMatchesAndDiverges(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var sawReplayHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if r.Header.Get("X-OpticTrace-Replay") == "1" {
			sawReplayHeader = true
		}
		mu.Unlock()
		if r.URL.Path == "/gone" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	now := time.Now()
	records := []store.Record{
		{Time: now.Add(2 * time.Second), Method: "GET", Path: "/second", Status: 200},
		{Time: now, Method: "GET", Path: "/first", Query: "page=2", Status: 200},
		// Recorded as 200 but now 404 — a regression replay should surface.
		{Time: now.Add(3 * time.Second), Method: "GET", Path: "/gone", Status: 200},
	}
	sum, err := Run(context.Background(), records, Options{Target: srv.URL, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Sent != 3 {
		t.Fatalf("sent %d, want 3", sum.Sent)
	}
	if sum.Matched != 2 || sum.Diverged != 1 {
		t.Errorf("matched=%d diverged=%d, want 2/1", sum.Matched, sum.Diverged)
	}
	if len(sum.Diffs) != 1 || sum.Diffs[0].Path != "/gone" || sum.Diffs[0].ReplayedCode != 404 {
		t.Errorf("divergence not reported correctly: %+v", sum.Diffs)
	}
	if !sawReplayHeader {
		t.Error("replayed requests should be identifiable via X-OpticTrace-Replay")
	}
	// Capture order is preserved so stateful sequences behave.
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 || seen[0] != "GET /first?page=2" {
		t.Errorf("expected oldest-first replay with query preserved, got %v", seen)
	}
}

// Governance removes data, and replay must say so rather than quietly
// sending an empty body that looks like the original request.
func TestReplaySkipsWhatGovernanceRemoved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	records := []store.Record{
		// Restricted route: bytes were sent originally, none were stored.
		{Time: time.Now(), Method: "POST", Path: "/auth/login", Status: 200, ReqBytes: 42, RequestBody: ""},
		// Truncated at the capture limit: replaying a partial body is wrong.
		{Time: time.Now(), Method: "POST", Path: "/upload", Status: 200, RequestBody: `{"partial":`, ReqTruncated: true},
		// Fine to replay.
		{Time: time.Now(), Method: "GET", Path: "/ok", Status: 200},
	}
	sum, err := Run(context.Background(), records, Options{Target: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if sum.Sent != 1 || sum.Skipped != 2 {
		t.Fatalf("sent=%d skipped=%d, want 1/2", sum.Sent, sum.Skipped)
	}
	var reasons string
	for r := range sum.SkipReason {
		reasons += r + "|"
	}
	for _, want := range []string{"not captured", "truncated"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("skip reasons should explain %q, got %q", want, reasons)
		}
	}
}

func TestReplayRedactedBodiesSkippableOnDemand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	recs := []store.Record{
		{Time: time.Now(), Method: "POST", Path: "/pay", Status: 200,
			RequestBody: `{"card":"[REDACTED]"}`},
	}
	// Default: replay it anyway (the placeholder is what was stored).
	sum, _ := Run(context.Background(), recs, Options{Target: srv.URL})
	if sum.Sent != 1 {
		t.Errorf("default should replay redacted bodies, sent=%d", sum.Sent)
	}
	// Opt in to skipping so a target that validates payloads isn't fed junk.
	sum, _ = Run(context.Background(), recs, Options{Target: srv.URL, SkipRedacted: true})
	if sum.Skipped != 1 {
		t.Errorf("SkipRedacted should skip, skipped=%d", sum.Skipped)
	}
}

func TestReplayRequiresTarget(t *testing.T) {
	if _, err := Run(context.Background(), nil, Options{}); err == nil {
		t.Error("replay without a target must error")
	}
}

func TestDryRunSendsNothing(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer srv.Close()
	recs := []store.Record{{Time: time.Now(), Method: "GET", Path: "/a", Status: 200}}
	sum, _ := Run(context.Background(), recs, Options{Target: srv.URL, DryRun: true})
	if hits != 0 {
		t.Errorf("dry run must not send requests, got %d", hits)
	}
	if sum.Sent != 1 {
		t.Errorf("dry run should report what it would send, got %d", sum.Sent)
	}
}
