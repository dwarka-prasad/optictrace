package export

import (
	"strings"
	"testing"
)

// Every exported span used to be an orphan root: a fresh trace ID per record,
// so OpticTrace data could never be correlated with the application's own
// tracing. These are the W3C Trace Context cases that must now be honoured.
func TestTraceContext(t *testing.T) {
	const tid = "4bf92f3577b34da6a3ce929d0e0e4736"
	const pid = "00f067aa0ba902b7"

	t.Run("adopts a valid traceparent", func(t *testing.T) {
		got, parent, sampled := traceContext(map[string]string{
			"traceparent": "00-" + tid + "-" + pid + "-01",
		})
		if got != tid {
			t.Errorf("traceId = %q, want the inbound %q", got, tid)
		}
		if parent != pid {
			t.Errorf("parentSpanId = %q, want %q", parent, pid)
		}
		if !sampled {
			t.Error("flags 01 means sampled")
		}
	})

	t.Run("honours the unsampled flag", func(t *testing.T) {
		_, _, sampled := traceContext(map[string]string{
			"traceparent": "00-" + tid + "-" + pid + "-00",
		})
		if sampled {
			t.Error("flags 00 means not sampled")
		}
	})

	t.Run("header name is case-insensitive", func(t *testing.T) {
		got, _, _ := traceContext(map[string]string{
			"Traceparent": "00-" + tid + "-" + pid + "-01",
		})
		if got != tid {
			t.Errorf("traceId = %q — captured headers keep the client's casing", got)
		}
	})

	// A bad header must cost us a correlation, never the span itself.
	for _, tc := range []struct{ name, header string }{
		{"absent", ""},
		{"too few fields", "00-" + tid + "-" + pid},
		{"too many fields", "00-" + tid + "-" + pid + "-01-extra"},
		{"unknown version", "99-" + tid + "-" + pid + "-01"},
		{"forbidden version ff", "ff-" + tid + "-" + pid + "-01"},
		{"short trace id", "00-abcd-" + pid + "-01"},
		{"non-hex trace id", "00-" + strings.Repeat("z", 32) + "-" + pid + "-01"},
		{"all-zero trace id", "00-" + strings.Repeat("0", 32) + "-" + pid + "-01"},
		{"all-zero parent id", "00-" + tid + "-" + strings.Repeat("0", 16) + "-01"},
		{"garbage", "not a traceparent"},
	} {
		t.Run("falls back: "+tc.name, func(t *testing.T) {
			hdr := map[string]string{}
			if tc.header != "" {
				hdr["traceparent"] = tc.header
			}
			got, parent, _ := traceContext(hdr)
			if len(got) != 32 || !isHex(got, 32) {
				t.Errorf("fallback traceId = %q, want a fresh 32-hex id", got)
			}
			if got == tid {
				t.Error("must not adopt a trace id from a malformed header")
			}
			if parent != "" {
				t.Errorf("parentSpanId = %q, want empty for a root span", parent)
			}
		})
	}

	t.Run("fallback ids differ per record", func(t *testing.T) {
		a, _, _ := traceContext(nil)
		b, _, _ := traceContext(nil)
		if a == b {
			t.Error("orphan spans must not share a trace id")
		}
	})
}
