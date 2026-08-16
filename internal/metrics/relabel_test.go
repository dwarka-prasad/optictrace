package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// The reported symptom: adding a `labels:` key and reloading made the label
// appear in the dashboard but never in /metrics, because a Prometheus metric's
// label set is fixed at construction. A Grafana panel built on it returned no
// data with no error anywhere.
func TestSetLabelKeysMakesNewLabelsScrapable(t *testing.T) {
	c := New("svc", []float64{0.1, 1}, nil, 0)

	c.Observe(Observation{Method: "GET", Route: "/a", Status: 200, Duration: time.Millisecond})
	if body := scrape(t, c); strings.Contains(body, "tenant=") {
		t.Fatal("tenant should not be a dimension before it is configured")
	}

	if changed := c.SetLabelKeys([]string{"tenant"}); !changed {
		t.Fatal("adding a label key should report a change")
	}
	c.Observe(Observation{
		Method: "GET", Route: "/a", Status: 200, Duration: time.Millisecond,
		Labels: map[string]string{"tenant": "acme"},
	})

	body := scrape(t, c)
	if !strings.Contains(body, `tenant="acme"`) {
		t.Errorf("the new label never reached /metrics:\n%s", body)
	}
	// It must land on both vectors, not just the counter.
	for _, name := range []string{"optictrace_requests_total", "optictrace_request_duration_seconds"} {
		if !metricHasLabel(body, name, `tenant="acme"`) {
			t.Errorf("%s is missing the tenant dimension", name)
		}
	}
}

func TestSetLabelKeysIsANoOpWhenUnchanged(t *testing.T) {
	c := New("svc", []float64{0.1, 1}, []string{"tenant"}, 0)
	if c.SetLabelKeys([]string{"tenant"}) {
		t.Error("an identical schema should not report a change")
	}
	// Counters must survive a no-op reload; rebuilding would reset them.
	c.Observe(Observation{Method: "GET", Route: "/a", Status: 200,
		Duration: time.Millisecond, Labels: map[string]string{"tenant": "acme"}})
	c.SetLabelKeys([]string{"tenant"})
	if body := scrape(t, c); !strings.Contains(body, `tenant="acme"`) {
		t.Error("a no-op SetLabelKeys must not discard existing series")
	}
}

func TestSetLabelKeysRemovingALabel(t *testing.T) {
	c := New("svc", []float64{0.1, 1}, []string{"tenant", "region"}, 0)
	if !c.SetLabelKeys([]string{"tenant"}) {
		t.Fatal("removing a label is a change")
	}
	c.Observe(Observation{Method: "GET", Route: "/a", Status: 200,
		Duration: time.Millisecond, Labels: map[string]string{"tenant": "acme", "region": "eu"}})
	body := scrape(t, c)
	if strings.Contains(body, `region=`) {
		t.Errorf("removed label still exported:\n%s", body)
	}
	if !strings.Contains(body, `tenant="acme"`) {
		t.Error("remaining label should still be exported")
	}
	if got := c.LabelKeys(); len(got) != 1 || got[0] != "tenant" {
		t.Errorf("LabelKeys() = %v", got)
	}
}

// Reload happens while traffic is flowing. Observe must never see a counter
// from one schema and a histogram from another, and must not race.
func TestSetLabelKeysUnderConcurrentObserve(t *testing.T) {
	c := New("svc", []float64{0.1, 1}, []string{"tenant"}, 0)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					c.Observe(Observation{
						Method: "GET", Route: "/a", Status: 200, Duration: time.Millisecond,
						Labels: map[string]string{"tenant": "acme", "region": "eu"},
					})
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			c.SetLabelKeys([]string{"tenant", "region"})
		} else {
			c.SetLabelKeys([]string{"tenant"})
		}
	}
	close(stop)
	wg.Wait()

	// Observe once after the last swap before scraping. A CounterVec with no
	// child series exports nothing at all, so without this the assertion is
	// racing the schedule rather than testing the swap.
	c.Observe(Observation{Method: "GET", Route: "/a", Status: 200,
		Duration: time.Millisecond, Labels: map[string]string{"tenant": "acme"}})

	body := scrape(t, c)
	if !strings.Contains(body, "optictrace_requests_total") {
		t.Error("metric disappeared after repeated relabeling")
	}
	if !strings.Contains(body, `tenant="acme"`) {
		t.Error("the final label schema is not being exported")
	}
	// The stable registry must be untouched by relabeling.
	if !strings.Contains(body, "optictrace_inflight_requests") {
		t.Error("relabeling should not disturb config-independent metrics")
	}
}

// metricHasLabel reports whether any sample line for the named metric carries
// the given label pair.
func metricHasLabel(body, metric, label string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, metric) && strings.Contains(line, label) {
			return true
		}
	}
	return false
}
