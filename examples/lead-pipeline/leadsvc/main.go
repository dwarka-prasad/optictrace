// Command leadsvc is the entry point of the demo lead pipeline: it accepts a
// lead, asks the scoring service to grade it, and returns a decision.
//
// Deliberately un-instrumented apart from one thing: it forwards the inbound
// traceparent to its downstream call. That is the application's job in any
// tracing setup, and it is all the pipeline needs for OpticTrace to reassemble
// the tree — an OTel SDK would do it for you.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	scoring := envOr("SCORING_URL", "http://127.0.0.1:8002")
	http.HandleFunc("/api/v1/leads", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		var lead struct {
			Lead struct {
				Source  string `json:"source"`
				Product string `json:"product"`
				PAN     string `json:"pan"`
				Phone   string `json:"phone"`
				Email   string `json:"email"`
			} `json:"lead"`
		}
		if err := json.Unmarshal(body, &lead); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}

		req, _ := http.NewRequest("POST", scoring+"/api/v1/score", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		// Propagate the trace. Everything else about correlation is the
		// sidecar's problem; this one line is the application's.
		if tp := r.Header.Get("traceparent"); tp != "" {
			req.Header.Set("traceparent", tp)
		}
		req.Header.Set("X-Tenant-ID", r.Header.Get("X-Tenant-ID"))

		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			log.Printf("scoring unreachable: %v", err)
			http.Error(w, `{"error":"scoring unavailable"}`, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		scored, _ := io.ReadAll(resp.Body)

		var s struct {
			Score int `json:"score"`
		}
		_ = json.Unmarshal(scored, &s)

		decision := "declined"
		if s.Score >= 700 {
			decision = "approved"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"lead_id":  "LD-" + lead.Lead.Source + "-" + time.Now().Format("150405.000"),
			"decision": decision,
			"score":    s.Score,
			// Echoed back on purpose: the demo needs a case where the RESPONSE
			// also carries PII, so redaction has to cover both directions.
			"applicant": map[string]string{
				"pan":   lead.Lead.PAN,
				"phone": lead.Lead.Phone,
				"email": lead.Lead.Email,
			},
		})
	})
	log.Println("leadsvc on :7001")
	log.Fatal(http.ListenAndServe("127.0.0.1:7001", nil))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
