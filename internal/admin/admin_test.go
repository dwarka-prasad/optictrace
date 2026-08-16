package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// srv builds a Server with the store disabled — these tests are about the
// middleware, and every handler behind it returns 501 without a Reader, which
// is enough to prove the request got through.
func srv(token string, origins []string) http.Handler {
	s := &Server{
		AuthToken:   token,
		HealthOpen:  true,
		CORSOrigins: origins,
		Version:     "test",
	}
	return s.Handler()
}

func get(t *testing.T, h http.Handler, method, target string, hdr map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestAuthDisabledLetsEverythingThrough(t *testing.T) {
	h := srv("", nil)
	if got := get(t, h, "GET", "/api/system", nil).StatusCode; got == http.StatusUnauthorized {
		t.Error("no token configured: requests must not be rejected")
	}
}

func TestAuthRejectsAndAccepts(t *testing.T) {
	const token = "s3cret-token"
	h := srv(token, nil)

	for _, tc := range []struct {
		name string
		hdr  map[string]string
		path string
		want int
	}{
		{"no credentials", nil, "/api/system", http.StatusUnauthorized},
		{"wrong token", map[string]string{"Authorization": "Bearer nope"}, "/api/system", http.StatusUnauthorized},
		{"right token", map[string]string{"Authorization": "Bearer " + token}, "/api/system", http.StatusOK},
		{"not a bearer scheme", map[string]string{"Authorization": "Basic " + token}, "/api/system", http.StatusUnauthorized},
		// The query fallback exists so a browser can load the dashboard.
		{"query fallback", nil, "/api/system?token=" + token, http.StatusOK},
		{"wrong query token", nil, "/api/system?token=nope", http.StatusUnauthorized},
		// A prefix of the real token must not pass — guards against a
		// length-only or prefix comparison.
		{"token prefix", map[string]string{"Authorization": "Bearer s3cret"}, "/api/system", http.StatusUnauthorized},
		{"token with suffix", map[string]string{"Authorization": "Bearer " + token + "x"}, "/api/system", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := get(t, h, "GET", tc.path, tc.hdr)
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
			if tc.want == http.StatusUnauthorized {
				if resp.Header.Get("WWW-Authenticate") == "" {
					t.Error("a 401 should say how to authenticate")
				}
			}
		})
	}
}

func TestHealthBypass(t *testing.T) {
	if got := get(t, srv("tok", nil), "GET", "/healthz", nil).StatusCode; got != http.StatusOK {
		t.Errorf("/healthz with HealthOpen must stay reachable for probes, got %d", got)
	}
	s := &Server{AuthToken: "tok", HealthOpen: false, Version: "test"}
	if got := get(t, s.Handler(), "GET", "/healthz", nil).StatusCode; got != http.StatusUnauthorized {
		t.Errorf("HealthOpen=false should protect /healthz, got %d", got)
	}
}

// The regression test for the wildcard-CORS exposure: with no origins
// configured, a cross-origin read must not be authorised by us.
func TestCORSSendsNothingByDefault(t *testing.T) {
	resp := get(t, srv("", nil), "GET", "/api/system",
		map[string]string{"Origin": "https://evil.example"})
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("Allow-Origin = %q, want empty — the browser must block this", v)
	}
}

func TestCORSAllowlist(t *testing.T) {
	const allowed = "http://localhost:3001"
	h := srv("", []string{allowed})

	t.Run("allowed origin is echoed", func(t *testing.T) {
		resp := get(t, h, "GET", "/api/system", map[string]string{"Origin": allowed})
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != allowed {
			t.Errorf("Allow-Origin = %q, want %q", got, allowed)
		}
		// Without Vary, a shared cache could serve this response to a
		// different origin.
		if resp.Header.Get("Vary") == "" {
			t.Error("responses that depend on Origin must Vary on it")
		}
	})

	t.Run("other origins get nothing", func(t *testing.T) {
		resp := get(t, h, "GET", "/api/system", map[string]string{"Origin": "https://evil.example"})
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Allow-Origin = %q, want empty", got)
		}
	})

	t.Run("preflight from a disallowed origin is not authorised", func(t *testing.T) {
		resp := get(t, h, "OPTIONS", "/api/system", map[string]string{"Origin": "https://evil.example"})
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("preflight Allow-Origin = %q, want empty", got)
		}
	})

	t.Run("same-origin requests need no headers", func(t *testing.T) {
		resp := get(t, h, "GET", "/api/system", nil)
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("Allow-Origin = %q on a same-origin request", got)
		}
	})
}

// Preflight carries no credentials by design, so it bypasses auth — but it
// must not therefore leak anything. It should return 204 and no body.
func TestPreflightBypassesAuthButReturnsNothing(t *testing.T) {
	h := srv("tok", []string{"http://localhost:3001"})
	resp := get(t, h, "OPTIONS", "/api/logs", map[string]string{"Origin": "http://localhost:3001"})
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		t.Errorf("preflight returned a %d-byte body", resp.ContentLength)
	}
}
