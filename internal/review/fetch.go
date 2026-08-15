package review

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

// FetchRemote pulls governed records from a running agent's export endpoint.
//
// This exists because of where the review runs. CI has no access to a
// staging box's SQLite file, but it can reach an HTTP endpoint — so the
// realistic deployment is "agent watching staging, CI asks it what it saw".
// Records arrive already governed, which means the CI job never handles raw
// payloads even though it is analysing production-shaped traffic.
func FetchRemote(baseURL, token, window string, timeout time.Duration) ([]store.Record, error) {
	url := strings.TrimRight(baseURL, "/") + "/api/export?format=jsonl"
	if window != "" {
		url += "&since=" + window
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach agent at %s: %w", baseURL, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("agent rejected the token (401) — set -token or OPTICTRACE_TOKEN")
	case resp.StatusCode == http.StatusNotImplemented:
		return nil, fmt.Errorf("the agent has no payload store (telemetry.store.driver: none)")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("agent returned %s", resp.Status)
	}
	return decodeJSONL(resp.Body)
}

// LoadJSONL reads records from a file — the offline path, for a capture
// exported as a CI artifact or committed as a fixture.
func LoadJSONL(path string) ([]store.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeJSONL(f)
}

func decodeJSONL(r io.Reader) ([]store.Record, error) {
	var out []store.Record
	sc := bufio.NewScanner(r)
	// Captured bodies can be up to capture_limit_bytes plus envelope; give
	// the scanner room so a large record doesn't silently truncate the feed.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var rec store.Record
		if err := json.Unmarshal(b, &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}
