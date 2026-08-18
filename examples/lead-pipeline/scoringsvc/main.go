// Command scoringsvc grades a lead, calling the bureau for credit history.
// Third hop in the demo pipeline, and the one that sometimes fails — an error
// rate makes the dashboard and the tail-sampling rule do something.
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
	bureau := envOr("BUREAU_URL", "http://127.0.0.1:8003")
	var n int
	http.HandleFunc("/api/v1/score", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n++

		// Every seventh request fails, so error rate, 5xx status classes and
		// the keep_errors rule all have something real to act on.
		if n%7 == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"scoring model timeout"}`))
			return
		}

		req, _ := http.NewRequest("POST", bureau+"/api/v1/history", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if tp := r.Header.Get("traceparent"); tp != "" {
			req.Header.Set("traceparent", tp)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		score := 640
		if err == nil {
			defer resp.Body.Close()
			var h struct {
				Bands int `json:"bands"`
			}
			raw, _ := io.ReadAll(resp.Body)
			_ = json.Unmarshal(raw, &h)
			score = 600 + h.Bands*20
		} else {
			log.Printf("bureau unreachable: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score": score,
			"model": "v3",
			// Token counts, so the metering and cost-attribution path is
			// exercised end to end rather than described.
			"usage": map[string]int{"total_tokens": 120 + n%40},
		})
	})
	log.Println("scoringsvc on :7002")
	log.Fatal(http.ListenAndServe("127.0.0.1:7002", nil))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
