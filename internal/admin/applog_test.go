package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/applog"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

func appLogServer(t *testing.T, cfg *config.AppLogsCfg) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	g, err := applog.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Reader: st, AppLogs: g, HealthOpen: true, Version: "test"}
	if g.Enabled() {
		s.AppLogStore = st
	}
	return s.Handler(), st
}

func post(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// Log shippers disagree about whether they send one object or an array.
// Refusing either is a support burden with no upside.
func TestIngestAcceptsSingleAndBatch(t *testing.T) {
	h, _ := appLogServer(t, &config.AppLogsCfg{Enabled: true})

	rr := post(t, h, "/api/applogs/ingest", `{"span_id":"s1","message":"single"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("single line: status %d body %s", rr.Code, rr.Body)
	}
	rr = post(t, h, "/api/applogs/ingest",
		`[{"span_id":"s1","message":"a"},{"span_id":"s1","message":"b"}]`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("batch: status %d body %s", rr.Code, rr.Body)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/applogs?span=s1", nil)
	got := httptest.NewRecorder()
	h.ServeHTTP(got, req)
	var out struct {
		Total int64 `json:"total"`
	}
	json.Unmarshal(got.Body.Bytes(), &out)
	if out.Total != 3 {
		t.Errorf("stored %d lines, want 3", out.Total)
	}
}

// The response tells the caller what was discarded and why. A shipper that
// cannot see its lines being dropped will keep sending them forever.
func TestIngestReportsDropsWithReasons(t *testing.T) {
	h, _ := appLogServer(t, &config.AppLogsCfg{Enabled: true, LevelMin: "warn"})
	rr := post(t, h, "/api/applogs/ingest", `[
		{"span_id":"s1","level":"error","message":"kept"},
		{"span_id":"s1","level":"debug","message":"too quiet"},
		{"level":"error","message":"no span"}
	]`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status %d", rr.Code)
	}
	var out struct {
		Stored  int            `json:"stored"`
		Dropped map[string]int `json:"dropped"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Stored != 1 {
		t.Errorf("stored %d, want 1", out.Stored)
	}
	if out.Dropped["level"] != 1 || out.Dropped["orphan"] != 1 {
		t.Errorf("drop reasons = %v, want level:1 orphan:1", out.Dropped)
	}
}

// Two different problems that look identical from the caller's side: the
// policy is off, or the driver cannot store lines. Reporting them the same way
// sends people to the wrong file.
func TestUnavailabilityReasonsAreDistinct(t *testing.T) {
	off, _ := appLogServer(t, &config.AppLogsCfg{Enabled: false})
	rr := post(t, off, "/api/applogs/ingest", `{"span_id":"s","message":"x"}`)
	if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "app_logs.enabled") {
		t.Errorf("feature-off should name the config key: %d %s", rr.Code, rr.Body)
	}

	// Enabled, but the server has no AppLogStore wired (driver without support).
	g, _ := applog.New(&config.AppLogsCfg{Enabled: true})
	s := &Server{AppLogs: g, HealthOpen: true, Version: "test"} // AppLogStore nil
	rr = post(t, s.Handler(), "/api/applogs/ingest", `{"span_id":"s","message":"x"}`)
	if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "driver") {
		t.Errorf("driver-unsupported should name the driver: %d %s", rr.Code, rr.Body)
	}
}

func TestIngestRejectsOversizedBatch(t *testing.T) {
	h, _ := appLogServer(t, &config.AppLogsCfg{Enabled: true})
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxAppLogBatch+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"span_id":"s","message":"x"}`)
	}
	b.WriteByte(']')
	rr := post(t, h, "/api/applogs/ingest", b.String())
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", rr.Code)
	}
}

// Reading a log line returns application text, which can contain anything a
// captured body can. It must sit behind the payload grant, not the stats one.
func TestReadingLinesRequiresPayloadCapability(t *testing.T) {
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	g, _ := applog.New(&config.AppLogsCfg{Enabled: true})
	s := &Server{Reader: st, AppLogs: g, AppLogStore: st, AuthToken: "tok", Version: "test"}
	h := s.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/applogs?span=s1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req) // no credential
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated read got %d, want 401", rr.Code)
	}
}
