package tracectx

import "context"

// ctxKey is unexported so nothing outside this package can collide with it.
type ctxKey struct{}

// NewContext returns a context carrying the span for this hop.
//
// The proxy already puts this hop's span on the FORWARDED request header, which
// is enough for a separate downstream process. An application embedding the
// middleware is not a separate process: its handler runs inside this one, and
// reaching back into the request headers to find out which span it is serving
// is awkward and easy to get wrong. Carrying it on the context is the Go
// equivalent of the ContextVar, AsyncLocalStorage and ThreadLocal the other
// SDKs use, and it is what lets a log handler correlate a line without the
// call site passing anything.
func NewContext(parent context.Context, c Context) context.Context {
	return context.WithValue(parent, ctxKey{}, c)
}

// FromContext returns the span being served, and whether there is one. There
// is no span outside a request — startup and background work belong to no
// request, and inventing one for them would attribute their logs to whichever
// request happened to be in flight.
func FromContext(ctx context.Context) (Context, bool) {
	if ctx == nil {
		return Context{}, false
	}
	c, ok := ctx.Value(ctxKey{}).(Context)
	return c, ok
}
