package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/metrics"
)

// These benchmarks exist because the README claims low overhead, and a claim
// with no measurement behind it is marketing. They compare a bare handler
// against the same handler wrapped by the interceptor under the policy shapes
// that matter:
//
//	Baseline    no OpticTrace at all
//	Restricted  a rule disables capture — should be near-free
//	Capture     bodies + headers recorded and redacted (the expensive path)
//	Metrics     capture plus Prometheus observation
//
// Run: go test ./internal/proxy -bench=. -benchmem -run='^$'

const benchPayload = `{"amount":4200,"currency":"USD","credit_card":{"number":"4111111111111111","cvv":"123"},` +
	`"customer":{"email":"ada@example.com","name":"Ada Lovelace"},"items":[{"sku":"A1","qty":2},{"sku":"B2","qty":1}]}`

func benchHandler() http.Handler {
	body := []byte(benchPayload)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}

func benchInterceptor(b *testing.B, yaml string, withMetrics bool) http.Handler {
	b.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		b.Fatal(err)
	}
	eng := engine.New(cfg)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	var opts []Option
	if withMetrics {
		opts = append(opts, WithMetrics(metrics.New("bench", cfg.Telemetry.Metrics.Buckets,
			eng.LabelKeys(), cfg.Telemetry.Metrics.LabelValueCap())))
	}
	// No store or exporters: those are async by design and would measure the
	// queue, not the request path.
	return NewInterceptor(cfg, eng, logger, opts...).Wrap(benchHandler())
}

func runBench(b *testing.B, h http.Handler) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/payments/charge",
				strings.NewReader(benchPayload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer token-value-here")
			req.Header.Set("X-Tenant-ID", "acme")
			h.ServeHTTP(httptest.NewRecorder(), req)
		}
	})
}

// BenchmarkBaseline is the floor: the handler with no interception at all.
func BenchmarkBaseline(b *testing.B) {
	runBench(b, benchHandler())
}

// BenchmarkRestricted measures a route whose rule disables capture. The
// policy resolves before any buffer is attached, so this should sit close to
// the baseline — that is the design claim being tested.
func BenchmarkRestricted(b *testing.B) {
	runBench(b, benchInterceptor(b, `
version: 1
service: { name: bench }
telemetry: { console_log: false, store: { driver: none }, metrics: { enabled: false } }
rules:
  - name: no-capture
    match: { path: "/api/**" }
    restrict: [request_body, response_body, headers, query]
`, false))
}

// BenchmarkCaptureRedact is the expensive path: both bodies buffered, parsed
// as JSON, redacted at depth, and headers sanitized.
func BenchmarkCaptureRedact(b *testing.B) {
	runBench(b, benchInterceptor(b, `
version: 1
service: { name: bench }
telemetry: { console_log: false, store: { driver: none }, metrics: { enabled: false } }
rules:
  - name: redact
    match: { path: "/api/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.credit_card.number", "$.**.credit_card.cvv", "$.**.customer.email"]
`, false))
}

// BenchmarkCaptureRedactMetrics adds Prometheus observation with a custom
// label dimension on top of full capture.
func BenchmarkCaptureRedactMetrics(b *testing.B) {
	runBench(b, benchInterceptor(b, `
version: 1
service: { name: bench }
telemetry: { console_log: false, store: { driver: none } }
rules:
  - name: redact
    match: { path: "/api/**" }
    redact:
      headers: [Authorization]
      json_fields: ["$.**.credit_card.number"]
    labels:
      tenant: "header:X-Tenant-ID"
`, true))
}

// BenchmarkRuleMatching isolates the hot-path cost of evaluating a policy
// against a realistic rule set, with no HTTP involved.
func BenchmarkRuleMatching(b *testing.B) {
	cfg, err := config.Parse([]byte(`
version: 1
service: { name: bench }
rules:
  - { name: r1, match: { path: "/api/v1/auth/**" }, restrict: [request_body] }
  - { name: r2, match: { path: "/api/v1/payments/**", methods: [POST] }, redact: { headers: [Authorization] } }
  - { name: r3, match: { path: "/api/v1/users/*" } }
  - { name: r4, match: { path: "/webhooks/*" }, restrict: [response_body] }
  - { name: r5, match: { path: "/api/**" }, labels: { tenant: "header:X-Tenant-ID" } }
`))
	if err != nil {
		b.Fatal(err)
	}
	eng := engine.New(cfg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.Evaluate("POST", "/api/v1/payments/charge")
	}
}
