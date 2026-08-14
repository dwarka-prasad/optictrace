package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// buildStack spins up a mock upstream + the OpticTrace reverse proxy in front
// of it, returning the proxy's test server and the captured log output.
func buildStack(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/auth"):
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "super-secret"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"charge_id": "ch_1", "status": "succeeded",
			})
		}
	}))
	t.Cleanup(upstream.Close)

	yaml := `
version: 1
service:
  name: test
  upstream: "` + upstream.URL + `"
defaults:
  capture:
    request_body: true
    response_body: true
    headers: true
rules:
  - name: no-capture-on-auth
    match:
      path: "/api/v1/auth/**"
    restrict: [request_body, response_body, headers]
  - name: redact-payments
    match:
      path: "/api/v1/payments/**"
    redact:
      headers: [Authorization]
      json_fields: ["$.credit_card.number"]
    labels:
      tenant: "header:X-Tenant-ID"
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	handler, _, err := NewReverseProxy(cfg, engine.New(cfg), logger)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)
	return proxySrv, &logBuf
}

func TestEndToEndRedaction(t *testing.T) {
	proxySrv, logBuf := buildStack(t)

	body := `{"amount": 100, "credit_card": {"number": "4111111111111111"}}`
	req, _ := http.NewRequest("POST", proxySrv.URL+"/api/v1/payments/charge", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer topsecrettoken")
	req.Header.Set("X-Tenant-ID", "acme-corp")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The client must receive the upstream response untouched.
	var upstreamResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&upstreamResp); err != nil {
		t.Fatalf("client response not JSON: %v", err)
	}
	if upstreamResp["charge_id"] != "ch_1" {
		t.Errorf("proxy altered the response: %v", upstreamResp)
	}

	logs := logBuf.String()
	if strings.Contains(logs, "4111111111111111") {
		t.Error("card number leaked into telemetry")
	}
	if strings.Contains(logs, "topsecrettoken") {
		t.Error("Authorization header leaked into telemetry")
	}
	if !strings.Contains(logs, engine.RedactedPlaceholder) {
		t.Error("expected redaction placeholder in telemetry")
	}
	if !strings.Contains(logs, `"amount":100`) {
		t.Error("non-sensitive request field should still be captured")
	}
	if !strings.Contains(logs, `"tenant":"acme-corp"`) {
		t.Error("custom label extraction failed")
	}
}

func TestEndToEndRestriction(t *testing.T) {
	proxySrv, logBuf := buildStack(t)

	body := `{"username": "ada", "password": "hunter2"}`
	req, _ := http.NewRequest("POST", proxySrv.URL+"/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Secret-Header", "do-not-log-me")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	logs := logBuf.String()
	if strings.Contains(logs, "hunter2") {
		t.Error("restricted request body leaked into telemetry")
	}
	if strings.Contains(logs, "super-secret") {
		t.Error("restricted response body leaked into telemetry")
	}
	if strings.Contains(logs, "do-not-log-me") {
		t.Error("restricted headers leaked into telemetry")
	}
	// Metadata must still be recorded even when capture is fully restricted.
	if !strings.Contains(logs, `"path":"/api/v1/auth/login"`) || !strings.Contains(logs, `"status":200`) {
		t.Errorf("expected metadata-only telemetry record, got: %s", logs)
	}
}

// Metering must work even on routes whose body capture is restricted — the
// buffer is used for extraction only and the body must NOT appear in logs.
func TestMeteringOnRestrictedRoute(t *testing.T) {
	yaml := `
version: 1
service: { name: metered }
rules:
  - name: ai-route
    match: { path: "/v1/complete" }
    restrict: [request_body, response_body, headers]
    meter:
      tokens: "$.usage.total_tokens"
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	ic := NewInterceptor(cfg, engine.New(cfg), slog.New(slog.NewJSONHandler(&logBuf, nil)))

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"completion": "top-secret-output", "usage": {"total_tokens": 512}}`))
	})
	srv := httptest.NewServer(ic.Wrap(app))
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/v1/complete", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	logs := logBuf.String()
	if strings.Contains(logs, "top-secret-output") {
		t.Error("restricted response body leaked into telemetry despite metering")
	}
	// The console log doesn't include meters, but the record does — verify
	// via a store sink instead of parsing logs.
	dbPath := t.TempDir() + "/m.db"
	st, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	w := store.NewAsyncWriter(st, 16, slog.New(slog.NewJSONHandler(&logBuf, nil)))
	ic2 := NewInterceptor(cfg, engine.New(cfg), slog.New(slog.NewJSONHandler(&logBuf, nil)), WithStore(w))
	srv2 := httptest.NewServer(ic2.Wrap(app))
	t.Cleanup(srv2.Close)
	resp, err = http.Post(srv2.URL+"/v1/complete", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recs, _, err := reopened.Query(context.Background(), store.Filter{})
	if err != nil || len(recs) != 1 {
		t.Fatalf("expected 1 stored record: %v %v", recs, err)
	}
	if recs[0].Meters["tokens"] != 512 {
		t.Errorf("meter not persisted: %+v", recs[0].Meters)
	}
	if recs[0].ResponseBody != "" {
		t.Errorf("restricted body must not be stored: %q", recs[0].ResponseBody)
	}
}

func TestEmbeddedMiddlewareMode(t *testing.T) {
	yaml := `
version: 1
service:
  name: embedded
rules:
  - name: hide-admin
    match:
      path: "/admin/**"
    restrict: [request_body, response_body, headers]
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	ic := NewInterceptor(cfg, engine.New(cfg), slog.New(slog.NewJSONHandler(&logBuf, nil)))

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello"))
	})
	srv := httptest.NewServer(ic.Wrap(app))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/admin/panel")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("middleware altered status: %d", resp.StatusCode)
	}
	if !strings.Contains(logBuf.String(), `"status":418`) {
		t.Error("expected telemetry from embedded middleware")
	}
}
