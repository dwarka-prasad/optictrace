// Package adminauth is a reference implementation of OpticTrace's admin
// extension surface: single sign-on, role-based access control, and an audit
// trail, in a module that can only use ext/.
//
// It is the shape a commercial extension takes, with the identity provider
// replaced by something testable. Everything else — the capability model, the
// challenge flow, the audit record — is exactly what a real one does.
//
// Not for production. Sessions are in memory and unsigned, and the "identity
// provider" trusts a header.
package adminauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

const sessionCookie = "optictrace_session"

// --- authentication ---------------------------------------------------------

// SSO authenticates browsers by session cookie and redirects to an identity
// provider when there is none. It stands in for OIDC: the callback trusts an
// X-Auth-User header instead of validating an ID token, but the flow — no
// session, redirect, callback, set cookie — is the real one.
type SSO struct {
	// LoginURL is where an unauthenticated browser is sent.
	LoginURL string
	// Directory maps a subject to the groups it belongs to. A real
	// implementation reads groups from the ID token's claims.
	Directory map[string][]string

	mu       sync.RWMutex
	sessions map[string]*ext.Identity
}

func NewSSO(loginURL string, directory map[string][]string) *SSO {
	return &SSO{
		LoginURL:  loginURL,
		Directory: directory,
		sessions:  map[string]*ext.Identity{},
	}
}

func (s *SSO) Name() string { return "sso" }

// Authenticate resolves a session cookie.
//
// Returning ErrNoCredentials — rather than an error — when the cookie is
// absent is what lets the built-in bearer token still work for CI and SDKs.
// Getting this wrong locks out every machine client.
func (s *SSO) Authenticate(_ http.ResponseWriter, r *http.Request) (*ext.Identity, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, ext.ErrNoCredentials
	}
	s.mu.RLock()
	id, ok := s.sessions[c.Value]
	s.mu.RUnlock()
	if !ok {
		// A cookie we don't recognise is a stale session, not a hostile one.
		// Deferring lets the token authenticator have a go, and the challenge
		// below will start a fresh login.
		return nil, ext.ErrNoCredentials
	}
	return id, nil
}

// Challenge sends a browser to the identity provider. It runs only after every
// authenticator declined, which is why an API client presenting a valid bearer
// token never sees a redirect.
func (s *SSO) Challenge(w http.ResponseWriter, r *http.Request) bool {
	// Don't redirect API clients: a 302 to an HTML login page is a confusing
	// answer to a fetch(). Browsers ask for HTML; scripts do not.
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return false
	}
	http.Redirect(w, r, s.LoginURL+"?redirect_uri="+r.URL.Path, http.StatusFound)
	return true
}

// CallbackHandler completes the login. Registered at CapPublic, because it
// necessarily runs before the caller has a session.
func (s *SSO) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real implementation exchanges ?code= for an ID token here and
		// validates its signature, issuer, audience and nonce.
		subject := r.Header.Get("X-Auth-User")
		if subject == "" {
			subject = r.URL.Query().Get("user")
		}
		groups, known := s.Directory[subject]
		if subject == "" || !known {
			http.Error(w, "unknown user", http.StatusForbidden)
			return
		}
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		token := hex.EncodeToString(raw)

		s.mu.Lock()
		s.sessions[token] = &ext.Identity{
			Subject: subject, Name: subject, Groups: groups, Method: "sso",
		}
		s.mu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: token, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
		redirect := r.URL.Query().Get("redirect_uri")
		if redirect == "" || !strings.HasPrefix(redirect, "/") {
			redirect = "/" // never bounce to an attacker-supplied absolute URL
		}
		http.Redirect(w, r, redirect, http.StatusFound)
	})
}

// --- authorization ----------------------------------------------------------

// RBAC grants capabilities to groups.
//
// Policy is written against capabilities, never URLs — so it stays correct
// when OpticTrace adds a route, and a reviewer can see what a role can reach
// without reading the router.
type RBAC struct {
	// Roles maps a group name to the capabilities it grants.
	Roles map[string][]ext.Capability
}

func (a *RBAC) Name() string { return "rbac" }

func (a *RBAC) Authorize(_ context.Context, id *ext.Identity, act ext.Action) error {
	if id == nil {
		return fmt.Errorf("%w: unauthenticated", ext.ErrForbidden)
	}
	for _, g := range id.Groups {
		for _, c := range a.Roles[g] {
			if c == act.Capability {
				return nil
			}
		}
	}
	// Naming the missing capability in the error is safe: it goes to the
	// audit trail and the log, and the core never returns it to the caller.
	return fmt.Errorf("%w: %s lacks %s", ext.ErrForbidden, id.Subject, act.Capability)
}

// DefaultRoles is a starting policy. The interesting line is `support`:
// read:payload without export. Someone debugging a customer's request does not
// thereby get to download the entire store, and separating those two is most
// of what an access review is checking.
var DefaultRoles = map[string][]ext.Capability{
	"admin": ext.Capabilities(),
	"sre": {
		ext.CapMetrics, ext.CapReadStats, ext.CapReadPayload,
		ext.CapAnalyse, ext.CapReadConfig, ext.CapUI, ext.CapPublic,
	},
	"support": {
		ext.CapReadStats, ext.CapReadPayload, ext.CapUI, ext.CapPublic,
	},
	"auditor": {
		ext.CapReadStats, ext.CapAnalyse, ext.CapReadConfig, ext.CapUI, ext.CapPublic,
	},
	"scraper": {ext.CapMetrics, ext.CapPublic},
}

// --- audit ------------------------------------------------------------------

// AuditLog writes one JSON object per decision.
//
// Only payload-touching capabilities are recorded by default. An audit trail
// that logs every dashboard poll buries the one line an investigator needs;
// "who read customer data" is the question this exists to answer.
type AuditLog struct {
	Out io.Writer
	// All records every decision rather than only payload access.
	All bool

	mu sync.Mutex
}

func (a *AuditLog) Name() string { return "audit-log" }

func (a *AuditLog) sensitive(c ext.Capability) bool {
	switch c {
	case ext.CapReadPayload, ext.CapExport, ext.CapAnalyse, ext.CapAdmin:
		return true
	}
	return false
}

func (a *AuditLog) Record(_ context.Context, e ext.AuditEvent) {
	// Denials are always worth keeping, whatever the capability: a series of
	// them is what an attempted escalation looks like.
	if !a.All && e.Outcome == ext.OutcomeAllowed && !a.sensitive(e.Action.Capability) {
		return
	}
	entry := map[string]any{
		"time":       e.Time.UTC().Format(time.RFC3339Nano),
		"outcome":    e.Outcome,
		"capability": e.Action.Capability,
		"method":     e.Action.Method,
		"path":       e.Action.Path,
		"status":     e.Status,
		"remote":     e.Remote,
	}
	if e.Identity != nil {
		entry["subject"] = e.Identity.Subject
		entry["auth_method"] = e.Identity.Method // "who" is incomplete without "how"
		if len(e.Identity.Groups) > 0 {
			entry["groups"] = e.Identity.Groups
		}
	} else {
		entry["subject"] = "(unauthenticated)"
	}
	if e.Reason != "" {
		entry["reason"] = e.Reason
	}
	// The part that makes this answer an auditor's question rather than just
	// prove someone visited a URL.
	if e.Accessed.Count > 0 {
		entry["records"] = e.Accessed.Count
	}
	if len(e.Accessed.RecordIDs) > 0 && len(e.Accessed.RecordIDs) <= 20 {
		entry["record_ids"] = e.Accessed.RecordIDs
	}
	if e.Accessed.Filter != "" {
		entry["filter"] = e.Accessed.Filter
	}
	if e.Accessed.Consumer != "" {
		entry["consumer"] = e.Accessed.Consumer
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = a.Out.Write(append(line, '\n'))
}

// --- wiring -----------------------------------------------------------------

// Install registers the whole set. A commercial build calls this from main
// after verifying its licence; the core needs no knowledge of any of it.
func Install(sso *SSO, roles map[string][]ext.Capability, auditTo io.Writer) {
	ext.RegisterAuthenticator(sso)
	ext.RegisterAuthorizer(&RBAC{Roles: roles})
	ext.RegisterAuditor(&AuditLog{Out: auditTo})
	ext.RegisterAdminRoutes(ext.AdminRoute{
		Pattern:    "GET /auth/callback",
		Capability: ext.CapPublic, // runs before a session exists
		Handler:    sso.CallbackHandler(),
	})
}
