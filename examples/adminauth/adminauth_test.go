package adminauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace"
	"github.com/dwarka-prasad/optictrace/ext"

	"github.com/dwarka-prasad/optictrace-example-adminauth"
)

// agent stands up a real OpticTrace admin server with this extension installed,
// which is the point: these assertions run against the actual core, not a mock
// of it.
func agent(t *testing.T, audit *bytes.Buffer, directory map[string][]string) *httptest.Server {
	t.Helper()
	ext.ResetRegistriesForTest()
	t.Cleanup(ext.ResetRegistriesForTest)

	dir := t.TempDir()
	cfg := filepath.Join(dir, "optic.yaml")
	if err := os.WriteFile(cfg, []byte(`
version: 1
service:
  name: authdemo
telemetry:
  admin_listen: "127.0.0.1:0"
  console_log: false
  store:
    driver: sqlite
    dsn: `+filepath.Join(dir, "a.db")+`
`), 0o600); err != nil {
		t.Fatal(err)
	}

	sso := adminauth.NewSSO("/login", directory)
	adminauth.Install(sso, adminauth.DefaultRoles, audit)

	a, err := optictrace.New(cfg)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}
	t.Cleanup(func() { a.Close() })

	srv := httptest.NewServer(a.AdminHandler(""))
	t.Cleanup(srv.Close)
	return srv
}

// browser returns a client that keeps cookies and does not auto-follow
// redirects, so the login flow can be stepped through.
func browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, c *http.Client, url string, hdr map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// The whole flow: no session → redirect to the IdP → callback → cookie →
// authorized access, with the right things denied along the way.
func TestSSOLoginFlowEndToEnd(t *testing.T) {
	var audit bytes.Buffer
	srv := agent(t, &audit, map[string][]string{
		"alice": {"support"}, // read:payload, but NOT export
		"root":  {"admin"},
	})
	c := browser(t)

	t.Run("a browser with no session is sent to the IdP", func(t *testing.T) {
		resp := get(t, c, srv.URL+"/api/logs", map[string]string{"Accept": "text/html"})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want 302", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
			t.Errorf("Location = %q", loc)
		}
	})

	t.Run("an API client gets 401, not an HTML redirect", func(t *testing.T) {
		resp := get(t, c, srv.URL+"/api/logs", nil) // no Accept: text/html
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 — a fetch() should not be redirected "+
				"to a login page", resp.StatusCode)
		}
	})

	t.Run("the callback is reachable unauthenticated and sets a session", func(t *testing.T) {
		resp := get(t, c, srv.URL+"/auth/callback?user=alice&redirect_uri=/api/logs", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("callback status = %d, want 302", resp.StatusCode)
		}
		var found bool
		for _, ck := range resp.Cookies() {
			if ck.Name == "optictrace_session" && ck.Value != "" {
				found = true
				if !ck.HttpOnly {
					t.Error("the session cookie should be HttpOnly")
				}
			}
		}
		if !found {
			t.Fatal("no session cookie was set")
		}
	})

	t.Run("the session now authenticates", func(t *testing.T) {
		resp := get(t, c, srv.URL+"/api/logs", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 after login", resp.StatusCode)
		}
	})

	// The line that matters: support can debug one request but cannot
	// download the whole store.
	t.Run("support may read payloads but not export", func(t *testing.T) {
		resp := get(t, c, srv.URL+"/api/export?format=jsonl", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("export status = %d, want 403 for the support role", resp.StatusCode)
		}
	})

	t.Run("and cannot reload the agent", func(t *testing.T) {
		req, _ := http.NewRequest("POST", srv.URL+"/api/reload", nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("reload status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("an unknown user is rejected at the callback", func(t *testing.T) {
		resp := get(t, browser(t), srv.URL+"/auth/callback?user=mallory", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403 for a user not in the directory", resp.StatusCode)
		}
	})

	t.Run("healthz stays reachable throughout", func(t *testing.T) {
		resp := get(t, &http.Client{}, srv.URL+"/healthz", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/healthz = %d — a probe must not need a session", resp.StatusCode)
		}
	})
}

// The audit trail has to answer "who read customer data", not "who visited a
// URL". This asserts the difference.
func TestAuditTrailAnswersTheAuditorsQuestion(t *testing.T) {
	var audit bytes.Buffer
	srv := agent(t, &audit, map[string][]string{"root": {"admin"}})
	c := browser(t)

	resp := get(t, c, srv.URL+"/auth/callback?user=root", nil)
	resp.Body.Close()

	// A payload read and a bulk export.
	for _, path := range []string{"/api/logs?status_min=500", "/api/export?format=jsonl"} {
		r := get(t, c, srv.URL+path, nil)
		r.Body.Close()
	}
	// An aggregate read, which should NOT be logged by default — an audit
	// trail full of dashboard polls buries the line that matters.
	r := get(t, c, srv.URL+"/api/stats", nil)
	r.Body.Close()

	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(audit.String()), "\n") {
		if line == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line is not JSON: %v — %q", err, line)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		t.Fatal("nothing was audited")
	}

	byCap := map[string]map[string]any{}
	for _, e := range entries {
		byCap[e["capability"].(string)] = e
	}

	if _, logged := byCap["read:stats"]; logged {
		t.Error("aggregate reads should not be audited by default")
	}

	payload, ok := byCap["read:payload"]
	if !ok {
		t.Fatalf("payload access was not audited: %v", entries)
	}
	if payload["subject"] != "root" || payload["auth_method"] != "sso" {
		t.Errorf("audit entry does not identify the caller: %v", payload)
	}
	if f, _ := payload["filter"].(string); !strings.Contains(f, "status_min=500") {
		t.Errorf("the filter used was not recorded: %v", payload)
	}

	if _, ok := byCap["export"]; !ok {
		t.Errorf("bulk export was not audited: %v", entries)
	}
}

func TestDeniedAttemptsAreAlwaysAudited(t *testing.T) {
	var audit bytes.Buffer
	srv := agent(t, &audit, map[string][]string{"alice": {"support"}})
	c := browser(t)
	resp := get(t, c, srv.URL+"/auth/callback?user=alice", nil)
	resp.Body.Close()

	r := get(t, c, srv.URL+"/api/export?format=jsonl", nil)
	r.Body.Close()

	if !strings.Contains(audit.String(), `"outcome":"denied"`) {
		t.Errorf("a denied export must be audited: %s", audit.String())
	}
	// The reason belongs in the audit trail...
	if !strings.Contains(audit.String(), "lacks export") {
		t.Errorf("the denial reason should be recorded: %s", audit.String())
	}
	// ...and not in the response.
	body, _ := io.ReadAll(r.Body)
	if strings.Contains(string(body), "lacks") {
		t.Errorf("denial reason leaked to the caller: %s", body)
	}
}

func TestRolesGrantWhatTheyClaim(t *testing.T) {
	for _, tc := range []struct {
		role  string
		cap   ext.Capability
		grant bool
	}{
		{"support", ext.CapReadPayload, true},
		{"support", ext.CapExport, false},
		{"support", ext.CapAdmin, false},
		{"auditor", ext.CapAnalyse, true},
		{"auditor", ext.CapReadPayload, false}, // can assess coverage, not read data
		{"sre", ext.CapReadPayload, true},
		{"sre", ext.CapExport, false},
		{"admin", ext.CapExport, true},
		{"scraper", ext.CapMetrics, true},
		{"scraper", ext.CapReadStats, false},
	} {
		t.Run(tc.role+"/"+string(tc.cap), func(t *testing.T) {
			rbac := &adminauth.RBAC{Roles: adminauth.DefaultRoles}
			id := &ext.Identity{Subject: "u", Groups: []string{tc.role}}
			err := rbac.Authorize(t.Context(), id, ext.Action{Capability: tc.cap})
			if tc.grant && err != nil {
				t.Errorf("%s should grant %s: %v", tc.role, tc.cap, err)
			}
			if !tc.grant && err == nil {
				t.Errorf("%s must NOT grant %s", tc.role, tc.cap)
			}
		})
	}
}

func TestUnauthenticatedIsDenied(t *testing.T) {
	rbac := &adminauth.RBAC{Roles: adminauth.DefaultRoles}
	if err := rbac.Authorize(t.Context(), nil, ext.Action{Capability: ext.CapReadStats}); err == nil {
		t.Error("a nil identity must be denied")
	}
}
