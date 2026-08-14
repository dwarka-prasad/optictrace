// mocktarget is a throwaway upstream used to exercise the OpticTrace proxy
// locally. It echoes request payloads back inside realistic JSON responses.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	flag.Parse()

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/payments/charge", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		writeJSON(w, http.StatusCreated, map[string]any{
			"charge_id": "ch_12345",
			"status":    "succeeded",
			"echo":      payload,
		})
	})

	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"token": "super-secret-session-token",
		})
	})

	// LLM-proxy-style endpoint: reports token usage like OpenAI/Anthropic
	// APIs do — exercises OpticTrace's metering rules.
	mux.HandleFunc("POST /api/v1/ai/complete", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		writeJSON(w, http.StatusOK, map[string]any{
			"completion": "This is a mock completion.",
			"usage": map[string]any{
				"prompt_tokens":     len(body) / 4,
				"completion_tokens": 42,
				"total_tokens":      len(body)/4 + 42,
			},
		})
	})

	mux.HandleFunc("GET /api/v1/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":    r.PathValue("id"),
			"name":  "Ada Lovelace",
			"email": "ada@example.com",
		})
	})

	log.Printf("mock target listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
