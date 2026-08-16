package optictracegin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/dwarka-prasad/optictrace"
)

// newAgent builds an agent over a temp config with the payload store enabled,
// so the middleware is exercised end to end rather than in isolation.
func newAgent(t *testing.T) *optictrace.Agent {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "optic.yaml")
	yaml := fmt.Sprintf(`
version: 1
service:
  name: gin-test
telemetry:
  admin_listen: "127.0.0.1:0"
  console_log: false
  store:
    driver: sqlite
    dsn: %s
rules:
  - name: redact-auth
    match: {path: "/**"}
    redact:
      headers: [Authorization]
      json_fields: ["$.**.password"]
`, filepath.Join(dir, "gin.db"))
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	agent, err := optictrace.New(cfg)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	t.Cleanup(func() { agent.Close() })
	return agent
}

func newRouter(t *testing.T) (*gin.Engine, *optictrace.Agent) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	agent := newAgent(t)
	r := gin.New()
	r.Use(Middleware(agent))
	return r, agent
}

// The basics: the handler still runs, the client still gets its response, and
// Gin's own view of status and size is intact through the adapter.
func TestMiddlewarePassesRequestsThrough(t *testing.T) {
	r, _ := newRouter(t)
	var gotStatus, gotSize int
	var written bool
	r.POST("/echo", func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"ok": true})
		gotStatus, gotSize, written = c.Writer.Status(), c.Writer.Size(), c.Writer.Written()
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/echo", strings.NewReader(`{"password":"hunter2"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"ok":true`) {
		t.Errorf("body = %q", body)
	}
	// Gin's ResponseWriter contract must survive the adapter — middleware
	// downstream relies on these.
	if gotStatus != http.StatusCreated {
		t.Errorf("c.Writer.Status() = %d, want 201", gotStatus)
	}
	if gotSize <= 0 {
		t.Errorf("c.Writer.Size() = %d, want the bytes written", gotSize)
	}
	if !written {
		t.Error("c.Writer.Written() should report true after a response")
	}
}

// The core invariant: live traffic is never modified. Redaction applies to
// telemetry only, so the client must receive the real bytes.
func TestClientReceivesUnmodifiedBytes(t *testing.T) {
	r, _ := newRouter(t)
	const secret = `{"password":"hunter2","card":"4111111111111111"}`
	r.POST("/pay", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		c.Data(http.StatusOK, "application/json", body) // echo it back
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/pay", strings.NewReader(secret))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)

	if rec.Body.String() != secret {
		t.Errorf("client got modified bytes:\n got %s\nwant %s", rec.Body.String(), secret)
	}
	if strings.Contains(rec.Body.String(), "REDACTED") {
		t.Error("redaction must never reach the client")
	}
}

// The adapter surface #5 showed is easy to get wrong. A handler that asks for
// these must not find them missing.
func TestAdapterExposesFlusherAndHijacker(t *testing.T) {
	r, _ := newRouter(t)
	var isFlusher, isHijacker, isPusherOK bool
	r.GET("/caps", func(c *gin.Context) {
		_, isFlusher = c.Writer.(http.Flusher)
		_, isHijacker = c.Writer.(http.Hijacker)
		// Pusher() returning nil over HTTP/1.1 is correct; the call must not
		// panic through the adapter.
		isPusherOK = func() (ok bool) {
			defer func() { ok = recover() == nil }()
			_ = c.Writer.Pusher()
			return
		}()
		c.String(http.StatusOK, "ok")
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/caps", nil))

	if !isFlusher {
		t.Error("adapter must expose http.Flusher — streaming handlers need it")
	}
	if !isHijacker {
		t.Error("adapter must expose http.Hijacker — WebSocket upgrades need it")
	}
	if !isPusherOK {
		t.Error("Pusher() panicked through the adapter")
	}
}

// Flush must reach the underlying writer, or a streaming handler buffers until
// the response ends.
func TestFlushReachesTheUnderlyingWriter(t *testing.T) {
	r, _ := newRouter(t)
	r.GET("/stream", func(c *gin.Context) {
		c.Header("Content-Type", "text/event-stream")
		for i := 0; i < 3; i++ {
			fmt.Fprintf(c.Writer, "data: %d\n\n", i)
			c.Writer.Flush()
		}
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/stream", nil))
	if got := rec.Body.String(); !strings.Contains(got, "data: 2") {
		t.Errorf("stream did not reach the client: %q", got)
	}
	if !rec.Flushed {
		t.Error("Flush() did not reach the underlying ResponseWriter")
	}
}

// Handler panics must not be swallowed or reshaped by the adapter — Gin's
// recovery middleware has to see them.
func TestPanicPropagatesToGinRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	agent := newAgent(t)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(Middleware(agent))
	r.GET("/boom", func(c *gin.Context) { panic("boom") })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 from gin.Recovery", rec.Code)
	}
}

func TestStatusDefaultsTo200WhenHandlerOnlyWrites(t *testing.T) {
	r, _ := newRouter(t)
	var status int
	r.GET("/plain", func(c *gin.Context) {
		_, _ = c.Writer.Write([]byte("hello"))
		status = c.Writer.Status()
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/plain", nil))
	if status != http.StatusOK {
		t.Errorf("Status() = %d after a bare Write, want 200", status)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestWriteStringGoesThroughTheRecorder(t *testing.T) {
	r, _ := newRouter(t)
	var size int
	r.GET("/s", func(c *gin.Context) {
		_, _ = c.Writer.WriteString("abcdef")
		size = c.Writer.Size()
	})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/s", nil))
	if size != 6 {
		t.Errorf("Size() = %d after WriteString, want 6", size)
	}
	if rec.Body.String() != "abcdef" {
		t.Errorf("body = %q", rec.Body.String())
	}
}
