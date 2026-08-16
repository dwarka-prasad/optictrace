package admin

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// accessControl is the per-request policy state, computed once when the
// server is built.
type accessControl struct {
	authns    []ext.Authenticator
	authzs    []ext.Authorizer
	auds      []ext.Auditor
	tokenAuth bool
}

// active reports whether anything needs enforcing. When nothing is configured
// and nothing registered, guard returns handlers untouched and the admin
// server behaves exactly as it did before this existed.
func (ac *accessControl) active() bool {
	return ac.tokenAuth || len(ac.authns) > 0 || len(ac.authzs) > 0 || len(ac.auds) > 0
}

// statusWriter records the status actually written, for the audit trail.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap keeps http.ResponseController working through this wrapper — the
// export handler streams and needs Flush.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// guard wraps one route with the authentication → authorization → audit
// chain, for a capability declared at registration.
//
// Per route rather than one outer middleware, because the capability has to be
// known before the mux routes and http.Request.Pattern is only populated
// after. Declaring it at the call site also makes it impossible to add a route
// without classifying it — there is no default to fall back to and forget.
func (s *Server) guard(capability ext.Capability, next http.Handler) http.Handler {
	ac := s.access
	if !ac.active() {
		return next
	}
	authns, authzs, auds, tokenAuth := ac.authns, ac.authzs, ac.auds, ac.tokenAuth

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		action := ext.Action{Capability: capability, Method: r.Method, Path: r.URL.Path}

		ctx, accessed := ext.WithAccessRecorder(r.Context())
		r = r.WithContext(ctx)

		emit := func(id *ext.Identity, outcome ext.Outcome, reason string) {
			if len(auds) == 0 {
				return
			}
			e := ext.AuditEvent{
				Time: time.Now(), Identity: id, Action: action,
				Outcome: outcome, Reason: reason,
				Status: sw.status, Remote: r.RemoteAddr,
				Accessed: accessed(),
			}
			for _, a := range auds {
				s.safeAudit(a, r.Context(), e)
			}
		}

		// Preflight carries no credentials by design and reveals nothing.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(sw, r)
			return
		}

		// --- authenticate ---------------------------------------------------
		id, err := s.authenticate(sw, r, authns, tokenAuth)
		switch {
		case err == ext.ErrResponseWritten:
			// An authenticator redirected or challenged; it owns the response.
			emit(nil, ext.OutcomeUnauthorized, "redirected to identity provider")
			return
		case err != nil:
			// A public route stays reachable without credentials — that is
			// what makes /healthz work for probes and a login callback work
			// at all.
			if capability == ext.CapPublic {
				break
			}
			for _, a := range authns {
				if c, ok := a.(ext.Challenger); ok && c.Challenge(sw, r) {
					emit(nil, ext.OutcomeUnauthorized, "challenged by "+a.Name())
					return
				}
			}
			sw.Header().Set("WWW-Authenticate", `Bearer realm="optictrace"`)
			httpError(sw, http.StatusUnauthorized, "missing or invalid credentials")
			emit(nil, ext.OutcomeUnauthorized, err.Error())
			return
		}

		if id != nil {
			r = r.WithContext(ext.WithIdentity(r.Context(), id))
		}

		// --- authorize ------------------------------------------------------
		// Public routes skip policy: a login callback cannot be authorized,
		// since being unauthenticated is the whole point of reaching it.
		if capability != ext.CapPublic {
			for _, az := range authzs {
				if err := s.safeAuthorize(az, r.Context(), id, action); err != nil {
					// The reason is audited and logged, never returned: a
					// denial explanation is itself information.
					httpError(sw, http.StatusForbidden, "forbidden")
					emit(id, ext.OutcomeDenied, az.Name()+": "+err.Error())
					return
				}
			}
		}

		next.ServeHTTP(sw, r)
		emit(id, ext.OutcomeAllowed, "")
	})
}

// authenticate walks the chain: registered authenticators first so an
// extension can take precedence, then the built-in bearer token.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request,
	authns []ext.Authenticator, tokenAuth bool) (*ext.Identity, error) {

	var lastErr error = ext.ErrNoCredentials
	for _, a := range authns {
		id, err := s.safeAuthenticate(a, w, r)
		switch {
		case err == nil:
			return id, nil
		case err == ext.ErrResponseWritten:
			return nil, err
		case err == ext.ErrNoCredentials:
			continue // not this one's request
		default:
			lastErr = err
		}
	}
	if tokenAuth {
		if id, ok := s.authenticateToken(r); ok {
			return id, nil
		}
		return nil, ext.ErrNoCredentials
	}
	if len(authns) == 0 {
		// No token configured and no authenticator registered, yet we are in
		// the chain — an Authorizer or Auditor is present. Proceed
		// unauthenticated and let policy decide.
		return nil, nil
	}
	return nil, lastErr
}

// safeAuthenticate isolates a plugin panic. An extension bug must not take
// down the admin API; it must fail closed for that request and be visible.
func (s *Server) safeAuthenticate(a ext.Authenticator, w http.ResponseWriter, r *http.Request) (id *ext.Identity, err error) {
	defer func() {
		if p := recover(); p != nil {
			s.logf("authenticator panicked", "authenticator", a.Name(), "panic", p)
			id, err = nil, ext.ErrForbidden
		}
	}()
	return a.Authenticate(w, r)
}

func (s *Server) safeAuthorize(az ext.Authorizer, ctx context.Context, id *ext.Identity, act ext.Action) (err error) {
	defer func() {
		if p := recover(); p != nil {
			s.logf("authorizer panicked", "authorizer", az.Name(), "panic", p)
			err = ext.ErrForbidden // fail closed
		}
	}()
	return az.Authorize(ctx, id, act)
}

func (s *Server) safeAudit(a ext.Auditor, ctx context.Context, e ext.AuditEvent) {
	defer func() {
		if p := recover(); p != nil {
			s.logf("auditor panicked", "auditor", a.Name(), "panic", p)
		}
	}()
	a.Record(ctx, e)
}

func (s *Server) logf(msg string, args ...any) {
	if s.Logger != nil {
		s.Logger.Error(msg, args...)
	} else {
		slog.Default().Error(msg, args...)
	}
}

// authenticateToken is the built-in bearer check, unchanged in behaviour:
// constant-time comparison, with a query fallback so a browser can load the
// dashboard.
func (s *Server) authenticateToken(r *http.Request) (*ext.Identity, bool) {
	got := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		got = strings.TrimPrefix(h, "Bearer ")
	} else if t := r.URL.Query().Get("token"); t != "" {
		got = t
	}
	if got == "" || !constantTimeEqual(got, s.AuthToken) {
		return nil, false
	}
	// A shared token names no person. Saying so explicitly keeps an audit
	// trail honest rather than implying an identity it does not have.
	return &ext.Identity{Subject: "shared-token", Name: "shared token", Method: "token"}, true
}
