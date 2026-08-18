package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/tracectx"
)

// upstreamEcho reports the traceparent the application actually received.
func upstreamEcho(seen *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Get(tracectx.Header)
		w.WriteHeader(http.StatusOK)
	}))
}

func TestTraceIDsAreRecorded(t *testing.T) {
	var seen string
	up := upstreamEcho(&seen)
	defer up.Close()
	base, rec := proxyTo(t, up, false)

	resp, err := http.Get(base + "/api/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	waitFor(t, func() bool { return rec.count(t) > 0 })

	r := rec.last(t)
	if len(r.TraceID) != 32 {
		t.Errorf("trace id = %q, want 32 hex chars", r.TraceID)
	}
	if len(r.SpanID) != 16 {
		t.Errorf("span id = %q, want 16 hex chars", r.SpanID)
	}
	if r.ParentSpanID != "" {
		t.Errorf("a request with no inbound traceparent is a root, got parent %q", r.ParentSpanID)
	}
}

// Joining a caller's trace is the point: their id must survive, and this hop
// must become a child of their span.
func TestInboundTraceIsJoined(t *testing.T) {
	const tid, caller = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	var seen string
	up := upstreamEcho(&seen)
	defer up.Close()
	base, rec := proxyTo(t, up, false)

	req, _ := http.NewRequest("GET", base+"/api/x", nil)
	req.Header.Set(tracectx.Header, "00-"+tid+"-"+caller+"-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	waitFor(t, func() bool { return rec.count(t) > 0 })

	r := rec.last(t)
	if r.TraceID != tid {
		t.Errorf("trace id = %q, want the caller's %q", r.TraceID, tid)
	}
	if r.ParentSpanID != caller {
		t.Errorf("parent = %q, want the caller's span %q", r.ParentSpanID, caller)
	}
	if r.SpanID == caller {
		t.Error("this hop must have its OWN span id, not the caller's")
	}
}

// The forwarded request carries THIS hop's span, so downstream calls nest
// under it. Passing the caller's header through unchanged would make every
// downstream hop a sibling and flatten the tree.
func TestForwardedRequestCarriesThisHopsSpan(t *testing.T) {
	const tid, caller = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	var seen string
	up := upstreamEcho(&seen)
	defer up.Close()
	base, rec := proxyTo(t, up, false)

	req, _ := http.NewRequest("GET", base+"/api/x", nil)
	req.Header.Set(tracectx.Header, "00-"+tid+"-"+caller+"-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	waitFor(t, func() bool { return rec.count(t) > 0 })
	r := rec.last(t)

	if !strings.Contains(seen, tid) {
		t.Errorf("upstream saw %q, which lost the trace id", seen)
	}
	if !strings.Contains(seen, r.SpanID) {
		t.Errorf("upstream saw %q, want this hop's span %s so downstream nests under it",
			seen, r.SpanID)
	}
	if strings.Contains(seen, caller) {
		t.Errorf("upstream saw the CALLER's span %q — downstream hops would become "+
			"siblings of this one and the tree would flatten", caller)
	}
	// The caller's sampling decision must survive, or OpticTrace exports spans
	// for traces the application already chose to drop.
	if !strings.HasSuffix(seen, "-01") {
		t.Errorf("upstream saw %q, want the sampled flag preserved", seen)
	}
}

func TestMalformedTraceparentStartsAFreshTrace(t *testing.T) {
	for _, bad := range []string{
		"garbage",
		"00-tooshort-00f067aa0ba902b7-01",
		"99-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-" + strings.Repeat("0", 32) + "-00f067aa0ba902b7-01",
	} {
		t.Run(bad, func(t *testing.T) {
			var seen string
			up := upstreamEcho(&seen)
			defer up.Close()
			b, rec := proxyTo(t, up, false)

			req, _ := http.NewRequest("GET", b+"/api/x", nil)
			req.Header.Set(tracectx.Header, bad)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("a bad header must not fail the request: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d — a malformed header must not break traffic", resp.StatusCode)
			}
			waitFor(t, func() bool { return rec.count(t) > 0 })
			r := rec.last(t)
			if len(r.TraceID) != 32 || r.ParentSpanID != "" {
				t.Errorf("want a fresh root trace, got trace=%q parent=%q", r.TraceID, r.ParentSpanID)
			}
		})
	}
}

func TestTraceContextRoundTrip(t *testing.T) {
	c := tracectx.FromHeader("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !c.Inherited || !c.Sampled {
		t.Fatalf("should be inherited and sampled: %+v", c)
	}
	back := tracectx.FromHeader(c.Header())
	if back.TraceID != c.TraceID {
		t.Errorf("trace id did not survive a round trip: %q vs %q", back.TraceID, c.TraceID)
	}
	if back.ParentSpanID != c.SpanID {
		t.Errorf("the rendered header should make our span the parent: %q vs %q",
			back.ParentSpanID, c.SpanID)
	}
	if !back.Sampled {
		t.Error("sampled flag lost in the round trip")
	}
}
