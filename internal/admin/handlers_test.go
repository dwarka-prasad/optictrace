package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

// withStore builds a Server backed by a real SQLite store seeded with n
// records, plus an optic.yaml on disk for the handlers that re-read config.
func withStore(t *testing.T, n int, configYAML string) (http.Handler, store.LogStore) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewSQLite(filepath.Join(dir, "a.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ctx := context.Background()
	for i := 0; i < n; i++ {
		tenant := "acme"
		if i%2 == 1 {
			tenant = "globex"
		}
		status := 200
		if i%10 == 9 {
			status = 500
		}
		if err := st.Save(ctx, &store.Record{
			Time: time.Now(), Service: "svc", Method: "POST",
			Path: fmt.Sprintf("/api/v1/things/%d", i), Route: "/api/v1/things/*",
			Status: status, DurationMS: float64(i),
			RequestBody: `{"n":` + fmt.Sprint(i) + `}`,
			// A field containing a comma and a quote, to prove CSV quoting.
			ResponseBody: `{"note":"a,b \"c\""}`,
			Labels:       map[string]string{"tenant": tenant},
			ReqBytes:     1 << 20, RespBytes: 1 << 20, // 1 MiB each
			Meters: map[string]float64{"tokens": 1000},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	cfgPath := filepath.Join(dir, "optic.yaml")
	if err := os.WriteFile(cfgPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Reader: st, ConfigPath: cfgPath, HealthOpen: true, Version: "test"}
	return s.Handler(), st
}

const billingYAML = `
version: 1
service: {name: svc}
telemetry:
  billing:
    consumer_label: tenant
    currency: EUR
    prices:
      per_request: 0.001
      per_gb: 2
      per_meter_unit:
        tokens: 0.000002
`

// The export loop pages through the store 500 at a time. Seeding more than
// one page is the point: an off-by-one in the loop silently truncates an
// export, which looks like "that's all the traffic there was".
func TestExportPagesThroughEveryRecord(t *testing.T) {
	const n = 1201 // spans three pages, with a partial last one
	h, _ := withStore(t, n, "version: 1\nservice: {name: svc}\n")

	t.Run("jsonl", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/export?format=jsonl", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
		if len(lines) != n {
			t.Errorf("exported %d records, want %d", len(lines), n)
		}
		var first store.Record
		if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
			t.Errorf("line 1 is not valid JSON: %v", err)
		}
		if first.Service != "svc" {
			t.Errorf("unexpected record: %+v", first)
		}
	})

	t.Run("csv", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/export?format=csv", nil))
		rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("export is not valid CSV: %v", err)
		}
		if len(rows) != n+1 { // +1 header
			t.Errorf("exported %d rows (incl. header), want %d", len(rows), n+1)
		}
		if rows[0][0] != "time" {
			t.Errorf("missing header row: %v", rows[0])
		}
		// A body containing a comma and an escaped quote must survive the
		// round trip byte for byte; broken quoting would shift every later
		// column on that row.
		const wantBody = `{"note":"a,b \"c\""}`
		if rows[1][16] != wantBody {
			t.Errorf("CSV round trip changed the body:\n got %q\nwant %q", rows[1][16], wantBody)
		}
	})

	t.Run("unknown format is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/export?format=xml", nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

func TestExportRespectsFilters(t *testing.T) {
	h, _ := withStore(t, 100, "version: 1\nservice: {name: svc}\n")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/export?format=jsonl&status_min=500", nil))
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 10 { // every tenth record is a 500
		t.Errorf("filtered export returned %d records, want 10", len(lines))
	}
}

// Billing arithmetic decides what a consumer is charged, so the components
// need to be checkable rather than trusted.
func TestUsageCostArithmetic(t *testing.T) {
	// 10 records: 5 per tenant, 1 MiB request + 1 MiB response each,
	// 1000 metered tokens each.
	h, _ := withStore(t, 10, billingYAML)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/usage", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	var got struct {
		Currency  string `json:"currency"`
		Consumers []struct {
			Consumer string             `json:"consumer"`
			Requests int64              `json:"requests"`
			Cost     map[string]float64 `json:"cost"`
		} `json:"consumers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v — body %s", err, rec.Body.String())
	}
	if got.Currency != "EUR" {
		t.Errorf("currency = %q, want the configured EUR", got.Currency)
	}
	if len(got.Consumers) != 2 {
		t.Fatalf("want 2 consumers, got %d: %+v", len(got.Consumers), got.Consumers)
	}

	for _, c := range got.Consumers {
		if c.Requests != 5 {
			t.Errorf("%s: %d requests, want 5", c.Consumer, c.Requests)
		}
		// 5 requests x 0.001
		assertClose(t, c.Consumer+" requests", c.Cost["requests"], 0.005)
		// 5 x 2 MiB = 10 MiB = 10/1024 GiB, x 2.00
		assertClose(t, c.Consumer+" data", c.Cost["data"], 10.0/1024*2)
		// 5 x 1000 tokens x 0.000002
		assertClose(t, c.Consumer+" tokens", c.Cost["tokens"], 0.01)
		assertClose(t, c.Consumer+" total",
			c.Cost["total"], 0.005+10.0/1024*2+0.01)
	}
}

// With no billing block configured, usage still reports traffic but must not
// invent costs.
func TestUsageWithoutBillingReportsNoCost(t *testing.T) {
	h, _ := withStore(t, 4, "version: 1\nservice: {name: svc}\n")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/usage", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"cost"`) {
		t.Errorf("no prices configured, so no cost should be reported: %s", rec.Body.String())
	}
}

func TestStoreDisabledReturns501(t *testing.T) {
	s := &Server{Version: "test"} // no Reader
	h := s.Handler()
	for _, path := range []string{"/api/logs", "/api/stats", "/api/usage", "/api/scan", "/api/export"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s returned %d, want 501 when the store is disabled", path, rec.Code)
		}
	}
}

func assertClose(t *testing.T, what string, got, want float64) {
	t.Helper()
	const eps = 1e-9
	if d := got - want; d > eps || d < -eps {
		t.Errorf("%s = %.10f, want %.10f", what, got, want)
	}
}
