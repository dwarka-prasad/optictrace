package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, c *Collector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func observeTenant(c *Collector, tenant string) {
	c.Observe(Observation{
		Method: "GET", Route: "/api/**", Status: 200, Duration: time.Millisecond,
		Labels: map[string]string{"tenant": tenant},
	})
}

// The guard exists because label values come from arbitrary request headers:
// one buggy client sending a unique tenant per request would otherwise create
// unbounded series and take down the Prometheus scraping this.
func TestCardinalityGuardCapsDistinctValues(t *testing.T) {
	c := New("svc", []float64{0.1, 1}, []string{"tenant"}, 3)

	for _, tenant := range []string{"acme", "globex", "initech"} {
		observeTenant(c, tenant)
	}
	body := scrape(t, c)
	for _, want := range []string{`tenant="acme"`, `tenant="globex"`, `tenant="initech"`} {
		if !strings.Contains(body, want) {
			t.Errorf("under the cap, %s should be its own series", want)
		}
	}
	if strings.Contains(body, OverLimit) {
		t.Error("cap should not have engaged yet")
	}

	// Past the cap: new values collapse into one bucket.
	for _, tenant := range []string{"d", "e", "f", "g"} {
		observeTenant(c, tenant)
	}
	body = scrape(t, c)
	if !strings.Contains(body, OverLimit) {
		t.Fatal("expected __over_limit__ series once the cap was exceeded")
	}
	for _, unwanted := range []string{`tenant="d"`, `tenant="e"`, `tenant="f"`, `tenant="g"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("%s should have been folded into __over_limit__", unwanted)
		}
	}
	if !strings.Contains(body, `optictrace_label_capped_total{label="tenant"`) {
		t.Error("capping should be visible as a metric")
	}
	// Already-known values keep their own series after the cap engages.
	observeTenant(c, "acme")
	if !strings.Contains(scrape(t, c), `tenant="acme"`) {
		t.Error("known values must keep their series after the cap engages")
	}
}

func TestGuardDisabledLetsEverythingThrough(t *testing.T) {
	c := New("svc", []float64{0.1}, []string{"tenant"}, 0)
	for _, tenant := range []string{"a", "b", "c", "d", "e", "f"} {
		observeTenant(c, tenant)
	}
	body := scrape(t, c)
	if strings.Contains(body, OverLimit) {
		t.Error("guard disabled (0) must not cap anything")
	}
	if !strings.Contains(body, `tenant="f"`) {
		t.Error("all values expected when the guard is off")
	}
}

// An absent header is one series, not unbounded — it must never consume cap.
func TestEmptyLabelValuesDoNotConsumeBudget(t *testing.T) {
	c := New("svc", []float64{0.1}, []string{"tenant"}, 2)
	for i := 0; i < 50; i++ {
		observeTenant(c, "")
	}
	observeTenant(c, "acme")
	observeTenant(c, "globex")
	body := scrape(t, c)
	if strings.Contains(body, OverLimit) {
		t.Error("empty values should not have exhausted the cap")
	}
	for _, want := range []string{`tenant="acme"`, `tenant="globex"`} {
		if !strings.Contains(body, want) {
			t.Errorf("%s missing — cap wrongly consumed by empty values", want)
		}
	}
}
