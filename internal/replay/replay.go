// Package replay re-issues captured traffic against a target service.
//
// The honest caveat, stated up front because it determines what replay is
// good for: OpticTrace stores GOVERNED records. A redacted field was replaced
// by "[REDACTED]" and a restricted body was never stored at all, so replay
// cannot reproduce the original bytes for those routes. That makes this a
// tool for exercising routing, status behaviour and regression shape — not
// for reproducing a payment with the original card number.
//
// Replay reports which requests were skipped and why, so the gap is visible
// rather than silently changing what you think you tested.
package replay

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Options control a replay run.
type Options struct {
	Target       string        // base URL to replay against
	RatePerSec   float64       // 0 = as fast as possible
	Concurrency  int           // parallel in-flight requests (default 4)
	Timeout      time.Duration // per-request timeout
	DryRun       bool          // print what would be sent, send nothing
	SkipRedacted bool          // skip requests whose body contains a placeholder
	Headers      map[string]string
}

// Result is one replayed exchange.
type Result struct {
	Method       string
	Path         string
	OriginalCode int
	ReplayedCode int
	Err          error
	Skipped      string // non-empty when the request was not sent
	Duration     time.Duration
}

// Summary aggregates a run.
type Summary struct {
	Total      int
	Sent       int
	Skipped    int
	Matched    int // replayed status == original status
	Diverged   int
	Failed     int
	SkipReason map[string]int
	Diffs      []Result
	Elapsed    time.Duration
}

// Run replays records against opts.Target.
func Run(ctx context.Context, records []store.Record, opts Options) (*Summary, error) {
	if opts.Target == "" {
		return nil, fmt.Errorf("replay requires a target URL")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	target := strings.TrimRight(opts.Target, "/")
	client := &http.Client{Timeout: opts.Timeout}

	// Oldest first: replaying in capture order is what makes stateful
	// sequences (create then fetch) behave like the original session.
	ordered := make([]store.Record, len(records))
	copy(ordered, records)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Time.Before(ordered[j].Time) })

	sum := &Summary{Total: len(ordered), SkipReason: map[string]int{}}
	start := time.Now()

	var ticker *time.Ticker
	if opts.RatePerSec > 0 {
		ticker = time.NewTicker(time.Duration(float64(time.Second) / opts.RatePerSec))
		defer ticker.Stop()
	}

	sem := make(chan struct{}, opts.Concurrency)
	results := make(chan Result, len(ordered))
	var inflight int

	for i := range ordered {
		rec := &ordered[i]
		if reason := skipReason(rec, opts); reason != "" {
			sum.Skipped++
			sum.SkipReason[reason]++
			continue
		}
		if ticker != nil {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return sum, ctx.Err()
			}
		}
		if opts.DryRun {
			sum.Sent++
			continue
		}
		sem <- struct{}{}
		inflight++
		go func(r *store.Record) {
			defer func() { <-sem }()
			results <- replayOne(ctx, client, target, r, opts.Headers)
		}(rec)
	}

	for i := 0; i < inflight; i++ {
		res := <-results
		sum.Sent++
		switch {
		case res.Err != nil:
			sum.Failed++
			sum.Diffs = append(sum.Diffs, res)
		case res.ReplayedCode == res.OriginalCode:
			sum.Matched++
		default:
			sum.Diverged++
			sum.Diffs = append(sum.Diffs, res)
		}
	}
	sum.Elapsed = time.Since(start)
	return sum, nil
}

// skipReason explains why a record cannot be faithfully replayed.
func skipReason(rec *store.Record, opts Options) string {
	if rec.Method == "" || rec.Path == "" {
		return "incomplete record"
	}
	bodyExpected := rec.Method == http.MethodPost || rec.Method == http.MethodPut || rec.Method == http.MethodPatch
	if bodyExpected && rec.RequestBody == "" && rec.ReqBytes > 0 {
		// The route restricted body capture, so the original payload is gone.
		return "request body was not captured (restricted or sampled out)"
	}
	if rec.ReqTruncated {
		return "request body was truncated at capture_limit_bytes"
	}
	if opts.SkipRedacted && strings.Contains(rec.RequestBody, engine.RedactedPlaceholder) {
		return "request body contains redacted fields"
	}
	return ""
}

func replayOne(ctx context.Context, client *http.Client, target string, rec *store.Record,
	extraHeaders map[string]string) Result {

	res := Result{Method: rec.Method, Path: rec.Path, OriginalCode: rec.Status}

	url := target + rec.Path
	if rec.Query != "" {
		url += "?" + rec.Query
	}
	var body *bytes.Reader
	if rec.RequestBody != "" {
		body = bytes.NewReader([]byte(rec.RequestBody))
	} else {
		body = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, rec.Method, url, body)
	if err != nil {
		res.Err = err
		return res
	}
	// Replay captured headers, minus ones that describe the ORIGINAL
	// connection — sending a stale Content-Length or Host produces failures
	// that look like application bugs but are replay artifacts.
	for k, v := range rec.RequestHeaders {
		if hopByHop(k) || v == engine.RedactedPlaceholder {
			continue
		}
		req.Header.Set(k, v)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-OpticTrace-Replay", "1")

	start := time.Now()
	resp, err := client.Do(req)
	res.Duration = time.Since(start)
	if err != nil {
		res.Err = err
		return res
	}
	defer resp.Body.Close()
	res.ReplayedCode = resp.StatusCode
	return res
}

func hopByHop(h string) bool {
	switch strings.ToLower(h) {
	case "content-length", "host", "connection", "keep-alive", "transfer-encoding",
		"upgrade", "proxy-authenticate", "proxy-authorization", "te", "trailer",
		"accept-encoding":
		return true
	}
	return false
}
