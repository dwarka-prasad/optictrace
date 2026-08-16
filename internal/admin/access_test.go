package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// --- fakes ------------------------------------------------------------------

type fakeAuthn struct {
	name      string
	id        *ext.Identity
	err       error
	challenge bool
	panics    bool
}

func (f *fakeAuthn) Name() string { return f.name }
func (f *fakeAuthn) Authenticate(w http.ResponseWriter, r *http.Request) (*ext.Identity, error) {
	if f.panics {
		panic("boom")
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.id, nil
}

type challengingAuthn struct {
	fakeAuthn
	challenged bool
}

func (c *challengingAuthn) Challenge(w http.ResponseWriter, r *http.Request) bool {
	if !c.challenge {
		return false
	}
	c.challenged = true
	http.Redirect(w, r, "https://idp.example/authorize", http.StatusFound)
	return true
}

type fakeAuthz struct {
	name   string
	allow  map[ext.Capability]bool
	panics bool
	seen   []ext.Action
	mu     sync.Mutex
}

func (f *fakeAuthz) Name() string { return f.name }
func (f *fakeAuthz) Authorize(_ context.Context, id *ext.Identity, a ext.Action) error {
	if f.panics {
		panic("boom")
	}
	f.mu.Lock()
	f.seen = append(f.seen, a)
	f.mu.Unlock()
	if f.allow[a.Capability] {
		return nil
	}
	return ext.ErrForbidden
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []ext.AuditEvent
	panics bool
}

func (f *fakeAuditor) Name() string { return "fake-auditor" }
func (f *fakeAuditor) Record(_ context.Context, e ext.AuditEvent) {
	if f.panics {
		panic("boom")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}
func (f *fakeAuditor) last(t *testing.T) ext.AuditEvent {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) == 0 {
		t.Fatal("no audit event recorded")
	}
	return f.events[len(f.events)-1]
}

// withRegistered swaps the process-wide registries for the duration of a test.
// The registries are package-level by design (extensions register from init),
// so tests must restore them rather than accumulate.
func withRegistered(t *testing.T, authns []ext.Authenticator, authzs []ext.Authorizer, auds []ext.Auditor) {
	t.Helper()
	ext.ResetRegistriesForTest()
	for _, a := range authns {
		ext.RegisterAuthenticator(a)
	}
	for _, a := range authzs {
		ext.RegisterAuthorizer(a)
	}
	for _, a := range auds {
		ext.RegisterAuditor(a)
	}
	t.Cleanup(ext.ResetRegistriesForTest)
}

func serverWithRecords(t *testing.T, token string, n int) *Server {
	t.Helper()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for i := 0; i < n; i++ {
		if err := st.Save(context.Background(), &store.Record{
			Method: "POST", Path: "/api/v1/pay", Route: "/api/**", Status: 200,
			RequestBody: `{"amount":1}`,
			Labels:      map[string]string{"tenant": "acme"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	return &Server{Reader: st, AuthToken: token, HealthOpen: true, Version: "test"}
}

func do(t *testing.T, h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- authentication ---------------------------------------------------------

func TestExtensionAuthenticatorSuppliesIdentity(t *testing.T) {
	want := &ext.Identity{Subject: "u-1", Name: "Alice", Groups: []string{"sre"}, Method: "fake"}
	auditor := &fakeAuditor{}
	withRegistered(t, []ext.Authenticator{&fakeAuthn{name: "fake", id: want}}, nil, []ext.Auditor{auditor})

	h := serverWithRecords(t, "", 2).Handler()
	if got := do(t, h, "GET", "/api/stats", nil).Code; got != http.StatusOK {
		t.Fatalf("status = %d", got)
	}
	e := auditor.last(t)
	if e.Identity == nil || e.Identity.Subject != "u-1" {
		t.Errorf("audit identity = %+v, want subject u-1", e.Identity)
	}
	if e.Outcome != ext.OutcomeAllowed {
		t.Errorf("outcome = %q", e.Outcome)
	}
}

// The built-in token must keep working alongside an extension — it is the
// machine path (CI, SDKs, `optictrace review -from`) and SSO cannot replace it.
func TestTokenStillWorksAlongsideAnExtension(t *testing.T) {
	withRegistered(t, []ext.Authenticator{
		&fakeAuthn{name: "sso", err: ext.ErrNoCredentials}, // browser-only; defers
	}, nil, nil)

	h := serverWithRecords(t, "s3cret", 1).Handler()
	if got := do(t, h, "GET", "/api/stats", map[string]string{"Authorization": "Bearer s3cret"}).Code; got != http.StatusOK {
		t.Errorf("bearer token rejected with an SSO extension present: %d", got)
	}
	if got := do(t, h, "GET", "/api/stats", map[string]string{"Authorization": "Bearer wrong"}).Code; got != http.StatusUnauthorized {
		t.Errorf("wrong token = %d, want 401", got)
	}
}

// A browser with no session must reach the identity provider, not a bare 401 —
// even though a token authenticator ran first and simply found no header.
// This is why Challenge exists separately from Authenticate.
func TestChallengeRedirectsWhenNothingAuthenticates(t *testing.T) {
	ch := &challengingAuthn{fakeAuthn: fakeAuthn{name: "oidc", err: ext.ErrNoCredentials, challenge: true}}
	withRegistered(t, []ext.Authenticator{ch}, nil, nil)

	h := serverWithRecords(t, "s3cret", 1).Handler()
	rec := do(t, h, "GET", "/api/stats", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want a 302 to the IdP", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "idp.example") {
		t.Errorf("Location = %q", loc)
	}
	if !ch.challenged {
		t.Error("Challenge was never called")
	}
}

func TestErrResponseWrittenStopsTheChain(t *testing.T) {
	written := &fakeAuthn{name: "oidc", err: ext.ErrResponseWritten}
	auditor := &fakeAuditor{}
	withRegistered(t, []ext.Authenticator{written}, nil, []ext.Auditor{auditor})

	h := serverWithRecords(t, "", 1).Handler()
	rec := do(t, h, "GET", "/api/stats", nil)
	if rec.Body.Len() != 0 {
		t.Errorf("core wrote a body after the authenticator claimed the response: %q", rec.Body.String())
	}
	if auditor.last(t).Outcome != ext.OutcomeUnauthorized {
		t.Error("a redirect should audit as unauthorized")
	}
}

// A plugin bug must not take down the admin API, and must not open it either.
func TestPanickingAuthenticatorFailsClosed(t *testing.T) {
	withRegistered(t, []ext.Authenticator{&fakeAuthn{name: "bad", panics: true}}, nil, nil)
	h := serverWithRecords(t, "", 1).Handler()
	if got := do(t, h, "GET", "/api/logs", nil).Code; got != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — a panicking authenticator must not grant access", got)
	}
}

func TestPanickingAuthorizerFailsClosed(t *testing.T) {
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "ok", id: &ext.Identity{Subject: "u"}}},
		[]ext.Authorizer{&fakeAuthz{name: "bad", panics: true}}, nil)
	h := serverWithRecords(t, "", 1).Handler()
	if got := do(t, h, "GET", "/api/logs", nil).Code; got != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — a panicking authorizer must deny", got)
	}
}

func TestPanickingAuditorDoesNotBreakTheRequest(t *testing.T) {
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "ok", id: &ext.Identity{Subject: "u"}}},
		nil, []ext.Auditor{&fakeAuditor{panics: true}})

	h := serverWithRecords(t, "", 1).Handler()
	if got := do(t, h, "GET", "/api/stats", nil).Code; got != http.StatusOK {
		t.Errorf("status = %d — an audit sink failing must not fail the request", got)
	}
}

// --- authorization ----------------------------------------------------------

// The capability split is the whole point: someone who may debug one request
// should not thereby be able to download the entire store.
func TestCapabilitiesAreEnforcedPerRoute(t *testing.T) {
	az := &fakeAuthz{name: "rbac", allow: map[ext.Capability]bool{
		ext.CapReadStats:   true,
		ext.CapReadPayload: true,
		// CapExport withheld on purpose.
	}}
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "ok", id: &ext.Identity{Subject: "u", Groups: []string{"support"}}}},
		[]ext.Authorizer{az}, nil)

	h := serverWithRecords(t, "", 3).Handler()
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/stats", http.StatusOK},
		{"/api/logs", http.StatusOK},
		{"/api/logs/1", http.StatusOK},
		{"/api/export?format=jsonl", http.StatusForbidden}, // the separation
		{"/api/scan", http.StatusForbidden},                // CapAnalyse withheld
		{"/api/config", http.StatusForbidden},              // CapReadConfig withheld
	} {
		t.Run(tc.path, func(t *testing.T) {
			if got := do(t, h, "GET", tc.path, nil).Code; got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRouteCapabilitiesAreCorrectlyClassified(t *testing.T) {
	az := &fakeAuthz{name: "spy", allow: map[ext.Capability]bool{}}
	for _, c := range ext.Capabilities() {
		az.allow[c] = true
	}
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "ok", id: &ext.Identity{Subject: "u"}}},
		[]ext.Authorizer{az}, nil)

	h := serverWithRecords(t, "", 2).Handler()
	for path, want := range map[string]ext.Capability{
		"/api/stats":  ext.CapReadStats,
		"/api/usage":  ext.CapReadStats,
		"/api/logs":   ext.CapReadPayload,
		"/api/logs/1": ext.CapReadPayload,
		"/api/export": ext.CapExport,
		"/api/scan":   ext.CapAnalyse,
		"/api/spec":   ext.CapAnalyse,
		"/api/config": ext.CapReadConfig,
	} {
		az.mu.Lock()
		az.seen = nil
		az.mu.Unlock()
		do(t, h, "GET", path, nil)
		az.mu.Lock()
		seen := append([]ext.Action(nil), az.seen...)
		az.mu.Unlock()
		if len(seen) == 0 {
			t.Errorf("%s: authorizer never consulted", path)
			continue
		}
		if seen[0].Capability != want {
			t.Errorf("%s classified as %q, want %q", path, seen[0].Capability, want)
		}
	}
}

// Two authorizers compose by intersection: adding one can only narrow access.
func TestAuthorizersCompose(t *testing.T) {
	permissive := &fakeAuthz{name: "a", allow: map[ext.Capability]bool{ext.CapReadStats: true, ext.CapReadPayload: true}}
	strict := &fakeAuthz{name: "b", allow: map[ext.Capability]bool{ext.CapReadStats: true}}
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "ok", id: &ext.Identity{Subject: "u"}}},
		[]ext.Authorizer{permissive, strict}, nil)

	h := serverWithRecords(t, "", 1).Handler()
	if got := do(t, h, "GET", "/api/stats", nil).Code; got != http.StatusOK {
		t.Errorf("both allow → %d, want 200", got)
	}
	if got := do(t, h, "GET", "/api/logs", nil).Code; got != http.StatusForbidden {
		t.Errorf("one denies → %d, want 403", got)
	}
}

// A denial reason is itself information and must not reach the caller.
func TestDenialReasonIsNotLeakedToTheCaller(t *testing.T) {
	az := &fakeAuthz{name: "rbac", allow: map[ext.Capability]bool{}}
	auditor := &fakeAuditor{}
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "ok", id: &ext.Identity{Subject: "u"}}},
		[]ext.Authorizer{az}, []ext.Auditor{auditor})

	h := serverWithRecords(t, "", 1).Handler()
	rec := do(t, h, "GET", "/api/logs", nil)
	if strings.Contains(rec.Body.String(), "rbac") || strings.Contains(rec.Body.String(), "forbidden:") {
		t.Errorf("denial detail leaked to the caller: %s", rec.Body.String())
	}
	// It must still be in the audit trail, where it is useful.
	if e := auditor.last(t); !strings.Contains(e.Reason, "rbac") {
		t.Errorf("audit reason = %q, want the authorizer named", e.Reason)
	}
}

// --- public routes ----------------------------------------------------------

func TestPublicRoutesBypassAuthAndPolicy(t *testing.T) {
	az := &fakeAuthz{name: "deny-all", allow: map[ext.Capability]bool{}}
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "none", err: ext.ErrNoCredentials}},
		[]ext.Authorizer{az}, nil)

	h := serverWithRecords(t, "tok", 1).Handler()
	// A probe must not need credentials, and a deny-all policy must not
	// break liveness — that would take the pod down.
	if got := do(t, h, "GET", "/healthz", nil).Code; got != http.StatusOK {
		t.Errorf("/healthz = %d, want 200", got)
	}
}

func TestExtensionRouteWithPublicCapabilityIsReachable(t *testing.T) {
	ext.ResetRegistriesForTest()
	t.Cleanup(ext.ResetRegistriesForTest)
	ext.RegisterAuthenticator(&fakeAuthn{name: "none", err: ext.ErrNoCredentials})
	ext.RegisterAdminRoutes(ext.AdminRoute{
		Pattern:    "GET /auth/callback",
		Capability: ext.CapPublic,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("callback ok"))
		}),
	})

	h := serverWithRecords(t, "tok", 1).Handler()
	rec := do(t, h, "GET", "/auth/callback?code=abc", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback = %d, want 200 — a login callback runs before a session exists", rec.Code)
	}
	if rec.Body.String() != "callback ok" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestExtensionRouteCollidingWithACoreRoutePanics(t *testing.T) {
	ext.ResetRegistriesForTest()
	t.Cleanup(ext.ResetRegistriesForTest)
	ext.RegisterAdminRoutes(ext.AdminRoute{
		Pattern: "GET /api/logs", Capability: ext.CapPublic,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	})
	defer func() {
		if recover() == nil {
			t.Error("shadowing a core route must panic, not silently replace it")
		}
	}()
	serverWithRecords(t, "", 0).Handler()
}

// --- audit ------------------------------------------------------------------

// "alice listed logs" answers nothing. The event must say what was reached.
func TestAuditRecordsWhatWasAccessed(t *testing.T) {
	auditor := &fakeAuditor{}
	withRegistered(t,
		[]ext.Authenticator{&fakeAuthn{name: "ok", id: &ext.Identity{Subject: "alice", Method: "oidc"}}},
		nil, []ext.Auditor{auditor})

	h := serverWithRecords(t, "", 7).Handler()

	t.Run("single record names the id and consumer", func(t *testing.T) {
		do(t, h, "GET", "/api/logs/3", nil)
		e := auditor.last(t)
		if e.Accessed.Count != 1 || len(e.Accessed.RecordIDs) != 1 || e.Accessed.RecordIDs[0] != 3 {
			t.Errorf("accessed = %+v, want record 3", e.Accessed)
		}
		if e.Accessed.Consumer != "acme" {
			t.Errorf("consumer = %q, want acme", e.Accessed.Consumer)
		}
	})

	t.Run("bulk export accumulates across pages", func(t *testing.T) {
		do(t, h, "GET", "/api/export?format=jsonl", nil)
		e := auditor.last(t)
		if e.Action.Capability != ext.CapExport {
			t.Errorf("capability = %q", e.Action.Capability)
		}
		if e.Accessed.Count != 7 {
			t.Errorf("exported count = %d, want 7 — a paged export must accumulate", e.Accessed.Count)
		}
		if e.Status != http.StatusOK {
			t.Errorf("status = %d", e.Status)
		}
	})

	t.Run("filter is recorded", func(t *testing.T) {
		do(t, h, "GET", "/api/logs?status_min=500", nil)
		if f := auditor.last(t).Accessed.Filter; !strings.Contains(f, "status_min=500") {
			t.Errorf("filter = %q", f)
		}
	})
}

func TestAuditRecordsDenialsAndUnauthenticated(t *testing.T) {
	auditor := &fakeAuditor{}
	withRegistered(t, nil, nil, []ext.Auditor{auditor})

	h := serverWithRecords(t, "tok", 1).Handler()
	do(t, h, "GET", "/api/logs", nil) // no credentials
	e := auditor.last(t)
	if e.Outcome != ext.OutcomeUnauthorized {
		t.Errorf("outcome = %q, want unauthorized", e.Outcome)
	}
	if e.Status != http.StatusUnauthorized {
		t.Errorf("status = %d", e.Status)
	}
	if e.Action.Capability != ext.CapReadPayload {
		t.Errorf("a rejected attempt should still record what was attempted, got %q", e.Action.Capability)
	}
}

// --- no extensions: the OSS path is untouched -------------------------------

func TestNoExtensionsBehavesExactlyAsBefore(t *testing.T) {
	ext.ResetRegistriesForTest()
	t.Cleanup(ext.ResetRegistriesForTest)

	t.Run("no token: everything open", func(t *testing.T) {
		h := serverWithRecords(t, "", 1).Handler()
		if got := do(t, h, "GET", "/api/logs", nil).Code; got != http.StatusOK {
			t.Errorf("status = %d", got)
		}
	})
	t.Run("token: enforced", func(t *testing.T) {
		h := serverWithRecords(t, "tok", 1).Handler()
		if got := do(t, h, "GET", "/api/logs", nil).Code; got != http.StatusUnauthorized {
			t.Errorf("no credentials = %d, want 401", got)
		}
		if got := do(t, h, "GET", "/api/logs?token=tok", nil).Code; got != http.StatusOK {
			t.Errorf("query token = %d, want 200", got)
		}
	})
}

func TestIdentityReachesHandlers(t *testing.T) {
	ext.ResetRegistriesForTest()
	t.Cleanup(ext.ResetRegistriesForTest)
	want := &ext.Identity{Subject: "u-9", Groups: []string{"sre"}}
	ext.RegisterAuthenticator(&fakeAuthn{name: "ok", id: want})

	var got *ext.Identity
	ext.RegisterAdminRoutes(ext.AdminRoute{
		Pattern: "GET /ext/whoami", Capability: ext.CapReadStats,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = ext.IdentityFrom(r.Context())
			w.WriteHeader(http.StatusOK)
		}),
	})
	h := serverWithRecords(t, "", 0).Handler()
	do(t, h, "GET", "/ext/whoami", nil)
	if got == nil || got.Subject != "u-9" {
		t.Errorf("IdentityFrom = %+v, want subject u-9", got)
	}
	if !got.InGroup("sre") || got.InGroup("admin") {
		t.Error("InGroup is wrong")
	}
}
