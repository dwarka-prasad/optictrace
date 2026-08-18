// Command bureausvc stands in for a credit bureau — the leaf of the pipeline
// and a third-party in real life, which is why its response deliberately
// contains data you would not want in your telemetry.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/api/v1/history", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		time.Sleep(3 * time.Millisecond) // a downstream is never free
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bands": 5,
			// A Luhn-valid card and an Aadhaar-shaped number, so `scan` has a
			// real leak to find if no rule covers this route.
			"accounts": []map[string]string{
				{"card": "4111111111111111", "status": "current"},
			},
			"aadhaar": "999941057058",
		})
	})
	log.Println("bureausvc on :7003")
	log.Fatal(http.ListenAndServe("127.0.0.1:7003", nil))
}
