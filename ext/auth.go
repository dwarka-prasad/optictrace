package ext

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// Identity is who made a request. Built by an Authenticator, carried on the
// request context, and recorded in every audit event.
type Identity struct {
	// Subject is the stable unique id — an OIDC `sub`, a service-account
	// name, a token id. Prefer something that survives a rename: an audit
	// trail keyed on an email address becomes ambiguous the day someone
	// changes theirs.
	Subject string
	Name    string
	Email   string
	// Groups carry the caller's roles, for an Authorizer to key on.
	Groups []string
	// Method names the authenticator that produced this, e.g. "token" or
	// "oidc". Recorded in the audit trail: "who" is incomplete without "how".
	Method string
	// Attrs is free-form, for claims an extension wants to keep.
	Attrs map[string]string
}

// InGroup reports whether the identity belongs to a group.
func (i *Identity) InGroup(name string) bool {
	if i == nil {
		return false
	}
	for _, g := range i.Groups {
		if g == name {
			return true
		}
	}
	return false
}

type identityKey struct{}

// IdentityFrom returns the authenticated caller, or nil when the request was
// not authenticated (which is the normal state with auth disabled).
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}

// WithIdentity attaches an identity to a context. The core calls this; an
// extension normally only needs IdentityFrom.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// ---------------------------------------------------------------------------
// Capabilities — what a request is trying to do
// ---------------------------------------------------------------------------

// Capability classifies a request by what it exposes, not by its URL.
//
// The split matters: the CORE owns the route→capability mapping, because only
// the core knows which handlers return captured payloads. An extension writes
// policy against capabilities. That means an RBAC plugin never has to track
// OpticTrace's URL structure, and — more importantly — a route added later
// cannot silently escape a policy that was written against URLs.
type Capability string

const (
	// CapPublic is reachable without authentication: /healthz, and any route
	// an extension registers for a login callback.
	CapPublic Capability = "public"
	// CapMetrics is the Prometheus endpoint. Separate because scrapers
	// authenticate differently from people, and it exposes no payloads.
	CapMetrics Capability = "metrics"
	// CapReadStats covers aggregates only — counts, latencies, route and
	// service summaries, usage totals. No captured payloads.
	CapReadStats Capability = "read:stats"
	// CapReadPayload returns captured request/response bodies to the caller.
	// This is the one that matters: it is the capability that lets someone
	// read customer data.
	CapReadPayload Capability = "read:payload"
	// CapExport is bulk payload egress — the whole store, streamed to a file.
	// Separated from CapReadPayload deliberately: "can look at one request
	// while debugging" and "can download everything" are different grants.
	CapExport Capability = "export"
	// CapAnalyse reads payloads server-side but returns only derived output
	// (leak findings with masked samples, an inferred spec). Lower risk than
	// CapReadPayload, higher than CapReadStats.
	CapAnalyse Capability = "analyse"
	// CapReadConfig returns the governance policy.
	CapReadConfig Capability = "read:config"
	// CapIngest accepts telemetry from SDKs — a machine-to-machine write.
	CapIngest Capability = "ingest"
	// CapAdmin changes agent state: reload.
	CapAdmin Capability = "admin"
	// CapUI serves the dashboard's static assets.
	CapUI Capability = "ui"
)

// Capabilities lists every capability the core defines, sorted — useful for an
// extension building a role editor, and for asserting a policy covers them all.
func Capabilities() []Capability {
	out := []Capability{
		CapPublic, CapMetrics, CapReadStats, CapReadPayload, CapExport,
		CapAnalyse, CapReadConfig, CapIngest, CapAdmin, CapUI,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Action is one authorization decision point.
type Action struct {
	Capability Capability
	Method     string
	Path       string
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

var (
	// ErrNoCredentials means "this request carries nothing I recognise" —
	// the chain moves on to the next authenticator. Return this rather than a
	// real error for an absent cookie or header, or you will lock out every
	// other authentication method.
	ErrNoCredentials = errors.New("ext: no credentials for this authenticator")

	// ErrResponseWritten means the authenticator has already written the
	// response — an OIDC redirect, a device-code page — and the core must
	// stop. Nothing further is written to the ResponseWriter.
	ErrResponseWritten = errors.New("ext: authenticator wrote the response")
)

// Authenticator resolves the caller's identity.
//
// Implementations must be safe for concurrent use and must not block: this
// runs on every admin request.
type Authenticator interface {
	Name() string
	// Authenticate returns the caller's identity, ErrNoCredentials to defer
	// to the next authenticator, ErrResponseWritten if it has responded, or
	// any other error to reject the request outright.
	//
	// The ResponseWriter is provided for flows that must respond (a redirect)
	// and for setting a session cookie on success. Do not write to it in the
	// ErrNoCredentials case.
	Authenticate(w http.ResponseWriter, r *http.Request) (*Identity, error)
}

// Challenger is an optional Authenticator extension. When no authenticator
// could identify the caller, each Challenger is offered the request before the
// core gives up with 401 — this is where an interactive login redirects to its
// identity provider.
//
// Kept separate from Authenticate so that a browser with no session still
// reaches the redirect even though a token authenticator ran first and simply
// found no bearer header.
type Challenger interface {
	// Challenge reports whether it handled the response.
	Challenge(w http.ResponseWriter, r *http.Request) bool
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

// Authorizer decides whether an identity may perform an action.
//
// Every registered Authorizer must allow, so composing two never widens
// access. Returning an error denies; the message is logged and audited but
// never returned to the caller, since a denial reason is itself information.
type Authorizer interface {
	Name() string
	Authorize(ctx context.Context, id *Identity, a Action) error
}

// ErrForbidden is the conventional denial. Any non-nil error denies; this one
// exists so the common case reads clearly.
var ErrForbidden = errors.New("ext: forbidden")

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// Outcome is how a request ended, from the access-control point of view.
type Outcome string

const (
	OutcomeAllowed      Outcome = "allowed"
	OutcomeDenied       Outcome = "denied"       // authorization refused
	OutcomeUnauthorized Outcome = "unauthorized" // no usable credentials
)

// Accessed describes WHAT a request touched. This is the difference between
// an audit trail that answers an auditor's question and one that does not:
// "alice listed logs" is close to useless, "alice exported 12,043 records
// filtered to tenant=acme" is the answer.
type Accessed struct {
	// Count is how many stored records the response covered.
	Count int
	// RecordIDs identifies specific records when the set is small enough to
	// be worth naming — a single-record fetch, not a 20,000-row export.
	RecordIDs []int64
	// Filter is a human-readable summary of the query used.
	Filter string
	// Consumer is the tenant/consumer label value when the request was scoped
	// to one, so "who looked at THIS customer's data" is answerable.
	Consumer string
}

// AuditEvent is one access-control decision plus what it reached.
type AuditEvent struct {
	Time     time.Time
	Identity *Identity // nil when unauthenticated
	Action   Action
	Outcome  Outcome
	// Reason carries the denial cause. Never sent to the caller.
	Reason   string
	Status   int    // HTTP status actually written
	Remote   string // client address
	Accessed Accessed
}

// Auditor receives every access-control decision on the admin surface.
//
// Record must not block: it runs in the request path. It returns no error on
// purpose. The core will not fail a request because an audit backend is
// unavailable — that would make the audit system an availability dependency of
// the dashboard, precisely when an incident is underway and someone needs it.
//
// If your compliance posture genuinely requires "no audit, no access", put
// that check in an Authorizer, not here: auditing a read happens after the
// read, so refusing at this point would record the access and deny the
// response, which is the worst of both.
type Auditor interface {
	Name() string
	Record(ctx context.Context, e AuditEvent)
}

// ---------------------------------------------------------------------------
// Per-request access notes
// ---------------------------------------------------------------------------

type accessKey struct{}

type accessRecorder struct {
	mu sync.Mutex
	a  Accessed
}

// NoteAccess records what a handler actually reached, for the audit trail.
// Safe to call more than once — counts accumulate, which is what a paged
// export needs. A no-op when nothing is auditing.
func NoteAccess(ctx context.Context, a Accessed) {
	rec, _ := ctx.Value(accessKey{}).(*accessRecorder)
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.a.Count += a.Count
	rec.a.RecordIDs = append(rec.a.RecordIDs, a.RecordIDs...)
	if a.Filter != "" {
		rec.a.Filter = a.Filter
	}
	if a.Consumer != "" {
		rec.a.Consumer = a.Consumer
	}
}

// WithAccessRecorder prepares a context to collect NoteAccess calls, returning
// the context and a getter for what accumulated. Called by the core.
func WithAccessRecorder(ctx context.Context) (context.Context, func() Accessed) {
	rec := &accessRecorder{}
	return context.WithValue(ctx, accessKey{}, rec), func() Accessed {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return rec.a
	}
}

// ---------------------------------------------------------------------------
// Extra admin routes
// ---------------------------------------------------------------------------

// AdminRoute is a handler an extension adds to the admin server — an OIDC
// callback, a role-management API, an audit-log viewer.
type AdminRoute struct {
	// Pattern is an http.ServeMux pattern, e.g. "GET /auth/callback".
	// It must not collide with a core route; registration panics if it does.
	Pattern string
	Handler http.Handler
	// Capability gates the route like any core route. A login callback needs
	// CapPublic, since it runs before the caller has a session.
	Capability Capability
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

var (
	authMu         sync.RWMutex
	authenticators []Authenticator
	authorizers    []Authorizer
	auditors       []Auditor
	adminRoutes    []AdminRoute
)

// RegisterAuthenticator adds an authentication method. Registered
// authenticators are tried in registration order, BEFORE the built-in bearer
// token, so an extension can take precedence over it.
func RegisterAuthenticator(a Authenticator) {
	if a == nil {
		panic("ext: RegisterAuthenticator(nil)")
	}
	authMu.Lock()
	defer authMu.Unlock()
	authenticators = append(authenticators, a)
}

// RegisterAuthorizer adds an authorization policy. ALL registered authorizers
// must allow, so adding one can only narrow access, never widen it.
func RegisterAuthorizer(a Authorizer) {
	if a == nil {
		panic("ext: RegisterAuthorizer(nil)")
	}
	authMu.Lock()
	defer authMu.Unlock()
	authorizers = append(authorizers, a)
}

// RegisterAuditor adds an audit sink. Every registered auditor sees every
// decision.
func RegisterAuditor(a Auditor) {
	if a == nil {
		panic("ext: RegisterAuditor(nil)")
	}
	authMu.Lock()
	defer authMu.Unlock()
	auditors = append(auditors, a)
}

// RegisterAdminRoutes adds handlers to the admin server. Call before the
// server is built — from init or from main.
func RegisterAdminRoutes(routes ...AdminRoute) {
	authMu.Lock()
	defer authMu.Unlock()
	for _, r := range routes {
		if r.Pattern == "" || r.Handler == nil {
			panic("ext: AdminRoute needs a Pattern and a Handler")
		}
		if r.Capability == "" {
			panic("ext: AdminRoute " + r.Pattern + " needs a Capability — " +
				"an unclassified route would be gated as admin-only")
		}
		adminRoutes = append(adminRoutes, r)
	}
}

// Authenticators, Authorizers, Auditors and AdminRoutes return the registered
// extensions. The core calls these when building the admin server.
func Authenticators() []Authenticator {
	authMu.RLock()
	defer authMu.RUnlock()
	return append([]Authenticator(nil), authenticators...)
}

func Authorizers() []Authorizer {
	authMu.RLock()
	defer authMu.RUnlock()
	return append([]Authorizer(nil), authorizers...)
}

func Auditors() []Auditor {
	authMu.RLock()
	defer authMu.RUnlock()
	return append([]Auditor(nil), auditors...)
}

func AdminRoutes() []AdminRoute {
	authMu.RLock()
	defer authMu.RUnlock()
	return append([]AdminRoute(nil), adminRoutes...)
}

// ResetRegistriesForTest clears every extension registry.
//
// Registration is process-wide by design — extensions register from init — so
// tests that register need a way back to a clean state. Exported because the
// core's own tests live in another package, and because an extension's tests
// need it too. Not for use outside tests.
func ResetRegistriesForTest() {
	authMu.Lock()
	authenticators, authorizers, auditors, adminRoutes = nil, nil, nil, nil
	authMu.Unlock()

	registryMu.Lock()
	stores = map[string]StoreOpener{}
	exporters = map[string]ExporterBuilder{}
	registryMu.Unlock()
}
