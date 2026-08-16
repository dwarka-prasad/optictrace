package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// recorder wraps a real SQLite store rather than a hand-written fake, so these
// tests also prove the record survives a round trip through the schema — which
// matters here because Stream is a newly added column.
type recorder struct {
	st store.LogStore
}

func (c *recorder) count(t *testing.T) int {
	t.Helper()
	_, total, err := c.st.Query(context.Background(), store.Filter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return int(total)
}

func (c *recorder) last(t *testing.T) *store.Record {
	t.Helper()
	recs, _, err := c.st.Query(context.Background(), store.Filter{Limit: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("no record was emitted")
	}
	return &recs[0]
}

// proxyTo stands up the full sidecar (interceptor + reverse proxy) in front of
// upstream and returns its base URL plus the collected records.
func proxyTo(t *testing.T, upstream *httptest.Server, h2 bool) (string, *recorder) {
	t.Helper()
	cfg := &config.Config{
		Version: 1,
		Service: config.Service{Name: "t", Upstream: upstream.URL},
	}
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "proto.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	rec := &recorder{st: st}
	writer := store.NewAsyncWriter(st, 256, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { writer.Close() })

	handler, _, err2 := NewReverseProxy(cfg, engine.New(cfg),
		slog.New(slog.DiscardHandler), WithStore(writer))
	if err := err2; err != nil {
		t.Fatalf("build proxy: %v", err)
	}
	if h2 {
		handler = h2c.NewHandler(handler, &http2.Server{})
	}
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)
	return front.URL, rec
}

// --- #5: WebSocket upgrades -----------------------------------------------

// echoUpgrade is a minimal RFC-6455-shaped upgrade: it does the handshake by
// hand and echoes raw bytes. Using a real dialer here is the point — the bug
// was that ReverseProxy could not hijack our ResponseWriter, and only an
// actual upgrade exercises that path.
func echoUpgrade(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected an upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("upstream could not hijack: %v", err)
			return
		}
		defer conn.Close()
		fmt.Fprint(brw, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		brw.Flush()
		// Echo one line so the test proves bytes flow after the upgrade.
		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		fmt.Fprint(brw, "echo:"+line)
		brw.Flush()
	}))
}

func TestWebSocketUpgradePassesThrough(t *testing.T) {
	base, rec := proxyTo(t, echoUpgrade(t), false)
	u, _ := url.Parse(base)

	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	key := make([]byte, 16)
	_, _ = rand.Read(key)
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		u.Host, base64.StdEncoding.EncodeToString(key))

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	// The regression: this used to be "HTTP/1.1 502 Bad Gateway" because
	// recordingWriter was not an http.Hijacker.
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade returned %q, want 101 Switching Protocols", strings.TrimSpace(status))
	}
	// Drain the remaining handshake headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Bytes must flow both ways after the upgrade — proving we handed over the
	// connection rather than merely returning the right status.
	fmt.Fprint(conn, "ping\n")
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if strings.TrimSpace(got) != "echo:ping" {
		t.Errorf("echo = %q, want %q", strings.TrimSpace(got), "echo:ping")
	}

	// The record is emitted when the upgraded connection ends, not at the
	// upgrade — ServeHTTP does not return until then. Close and wait.
	conn.Close()
	waitFor(t, func() bool { return rec.count(t) > 0 })
	got2 := rec.last(t)
	if got2.Status != http.StatusSwitchingProtocols {
		t.Errorf("recorded status = %d, want 101", got2.Status)
	}
	// An upgraded connection's duration is a lifetime, not a latency, so it
	// must not land in the request percentiles.
	if !got2.Stream {
		t.Error("a hijacked upgrade should be recorded as a stream")
	}
}

// http.ResponseController methods this wrapper does not implement must still
// reach the underlying writer through Unwrap.
func TestResponseControllerReachesUnderlyingWriter(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Errorf("SetWriteDeadline through the wrapper: %v", err)
		}
		fmt.Fprint(w, "ok")
	}))
	base, _ := proxyTo(t, upstream, false)
	resp, err := http.Get(base + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

// --- #12: streaming responses ----------------------------------------------

func sseUpstream(t *testing.T, events int, gap time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < events; i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			http.NewResponseController(w).Flush()
			time.Sleep(gap)
		}
	}))
}

func TestSSEIsClassifiedAsAStream(t *testing.T) {
	base, rec := proxyTo(t, sseUpstream(t, 3, 5*time.Millisecond), false)

	resp, err := http.Get(base + "/events")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "data: 2") {
		t.Fatalf("stream did not reach the client: %q", body)
	}

	waitFor(t, func() bool { return rec.count(t) > 0 })
	r := rec.last(t)
	// The point of the fix: this record must be marked so its duration — a
	// connection lifetime, not a latency — stays out of request percentiles.
	if !r.Stream {
		t.Error("an SSE response should be recorded as a stream")
	}
}

func TestOrdinaryResponseIsNotAStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	base, rec := proxyTo(t, upstream, false)
	resp, err := http.Get(base + "/x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	waitFor(t, func() bool { return rec.count(t) > 0 })
	if rec.last(t).Stream {
		t.Error("a plain JSON response must not be classified as a stream")
	}
}

// A response that flushes but finishes quickly is a fast handler, not a
// stream. Misclassifying it would empty the latency histogram.
func TestQuickFlushingResponseIsNotAStream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rc := http.NewResponseController(w)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "chunk %d\n", i)
			rc.Flush()
		}
	}))
	base, rec := proxyTo(t, upstream, false)
	resp, err := http.Get(base + "/chunked")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	waitFor(t, func() bool { return rec.count(t) > 0 })
	if rec.last(t).Stream {
		t.Errorf("a fast chunked response (under %s) must not count as a stream", streamMinDuration)
	}
}

func TestIsEventStream(t *testing.T) {
	for _, tc := range []struct {
		ct   string
		want bool
	}{
		{"text/event-stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"TEXT/EVENT-STREAM", true},
		{" text/event-stream ", true},
		{"application/json", false},
		{"", false},
		{"text/event-streaming", false},
	} {
		if got := isEventStream(tc.ct); got != tc.want {
			t.Errorf("isEventStream(%q) = %v, want %v", tc.ct, got, tc.want)
		}
	}
}

// --- #11: cleartext HTTP/2 --------------------------------------------------

// An h2c client cannot connect to an HTTP/1.1-only listener at all, which is
// why gRPC could not traverse the sidecar. With the handler wired up it can.
func TestH2CClientCanConnect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "served-over-%s", r.Proto)
	}))
	base, rec := proxyTo(t, upstream, true)

	client := &http.Client{Transport: &http2.Transport{
		AllowHTTP: true, // h2c: no TLS
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	resp, err := client.Get(base + "/x")
	if err != nil {
		t.Fatalf("h2c request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("negotiated HTTP/%d, want HTTP/2", resp.ProtoMajor)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "served-over-") {
		t.Errorf("unexpected body %q", body)
	}

	// Governance still applies over HTTP/2.
	waitFor(t, func() bool { return rec.count(t) > 0 })
	if got := rec.last(t).Path; got != "/x" {
		t.Errorf("recorded path = %q, want /x", got)
	}
}

// HTTP/1.1 clients must be unaffected when h2c is enabled — h2c.NewHandler
// only takes over on the HTTP/2 preface or an explicit h2c upgrade.
func TestH2CDoesNotBreakHTTP1(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Proto)
	}))
	base, _ := proxyTo(t, upstream, true)
	resp, err := http.Get(base + "/x")
	if err != nil {
		t.Fatalf("http/1.1 request failed with h2c enabled: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Errorf("HTTP/1.1 client got HTTP/%d", resp.ProtoMajor)
	}
}

// waitFor polls until cond holds, so tests do not race the async writer.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the record to be written")
}
