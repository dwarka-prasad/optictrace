// mocktarget is a throwaway upstream used to exercise the OpticTrace proxy
// locally. It echoes request payloads back inside realistic JSON responses.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", ":9000", "listen address")
	applogs := flag.String("applogs", "", "OpticTrace admin base URL to ship application logs to (e.g. http://localhost:9095)")
	flag.Parse()

	if *applogs != "" {
		startShipper(strings.TrimSuffix(*applogs, "/") + "/api/applogs/ingest")
		log.Printf("shipping application logs to %s", *applogs)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/payments/charge", knobs(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		applog(r, "info", "charge received", map[string]string{
			"tenant": r.Header.Get("X-Tenant-ID"),
			"plan":   r.Header.Get("X-Plan"),
		})
		// Deliberately careless: a real service logs the auth header while
		// debugging and forgets to take it out. The line is stored redacted,
		// which is the point of running logs through the policy.
		applog(r, "debug", "calling gateway with "+r.Header.Get("Authorization"), nil)

		outcome := r.URL.Query().Get("outcome")
		if outcome == "" {
			outcome = "succeeded"
		}
		if outcome == "declined" {
			applog(r, "error", "gateway declined the charge", map[string]string{"reason": "insufficient_funds"})
		} else {
			applog(r, "info", "charge captured", map[string]string{"charge_id": "ch_12345"})
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"charge_id": "ch_12345",
			"status":    outcome,
			"echo":      payload,
		})
	}))

	// A route deliberately NOT covered by the example optic.yaml rules —
	// the "someone shipped an endpoint and forgot the governance" case that
	// `optictrace scan` exists to catch.
	mux.HandleFunc("POST /api/v1/orders", knobs(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		writeJSON(w, http.StatusCreated, map[string]any{
			"order_id": "ord_9001",
			"echo":     payload,
		})
	}))

	mux.HandleFunc("POST /api/v1/auth/login", knobs(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"token": "super-secret-session-token",
		})
	}))

	// LLM-proxy-style endpoint: reports token usage like OpenAI/Anthropic
	// APIs do — exercises OpticTrace's metering rules.
	mux.HandleFunc("POST /api/v1/ai/complete", knobs(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		writeJSON(w, http.StatusOK, map[string]any{
			"completion": "This is a mock completion.",
			"usage": map[string]any{
				"prompt_tokens":     len(body) / 4,
				"completion_tokens": 42,
				"total_tokens":      len(body)/4 + 42,
			},
		})
	}))

	mux.HandleFunc("GET /api/v1/users/{id}", knobs(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":    r.PathValue("id"),
			"name":  "Ada Lovelace",
			"email": "ada@example.com",
		})
	}))

	log.Printf("mock target listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// --- application logs --------------------------------------------------------
//
// A real service logs while it serves a request. This mock does the same, so
// the correlation is demonstrable end to end without anyone having to write an
// application first.
//
// The correlation key is NOT guessed from timing: OpticTrace rewrites the
// forwarded traceparent with the span it recorded, so the span-id field of the
// INBOUND header is exactly the span this request belongs to. Reading it back
// out is the whole contract.

type appLogLine struct {
	Time    time.Time         `json:"time"`
	TraceID string            `json:"trace_id"`
	SpanID  string            `json:"span_id"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
	Source  string            `json:"source"`
}

var shipper struct {
	mu    sync.Mutex
	url   string
	queue []appLogLine
}

func startShipper(url string) {
	shipper.url = url
	go func() {
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for range tick.C {
			shipper.mu.Lock()
			batch := shipper.queue
			shipper.queue = nil
			shipper.mu.Unlock()
			if len(batch) == 0 {
				continue
			}
			body, err := json.Marshal(batch)
			if err != nil {
				continue
			}
			// Best effort by design: an application must never fail a request
			// because its telemetry sink is unhappy.
			resp, err := http.Post(shipper.url, "application/json", bytes.NewReader(body))
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}()
}

// traceOf pulls the trace and span this request belongs to out of the inbound
// traceparent: 00-<32 hex trace>-<16 hex span>-<flags>.
func traceOf(r *http.Request) (trace, span string) {
	parts := strings.Split(r.Header.Get("traceparent"), "-")
	if len(parts) != 4 {
		return "", ""
	}
	return parts[1], parts[2]
}

// applog queues one line against the request's span.
func applog(r *http.Request, level, msg string, fields map[string]string) {
	if shipper.url == "" {
		return
	}
	trace, span := traceOf(r)
	shipper.mu.Lock()
	defer shipper.mu.Unlock()
	// Bounded: a mock that OOMs while the agent is down teaches the wrong
	// lesson about what telemetry may cost.
	if len(shipper.queue) > 5000 {
		return
	}
	shipper.queue = append(shipper.queue, appLogLine{
		Time: time.Now(), TraceID: trace, SpanID: span,
		Level: level, Message: msg, Fields: fields, Source: "demo-upstream",
	})
}

// knobs lets a caller force a slow or failing response with ?delay=250ms and
// ?status=503. Without them a local run can only ever produce fast 2xx
// traffic, so the rules that exist for the bad cases — keep_errors,
// keep_slower_than — are never actually exercised by the demo or by the
// traffic fixture CI reviews against.
func knobs(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d := r.URL.Query().Get("delay"); d != "" {
			if dur, err := time.ParseDuration(d); err == nil && dur > 0 && dur <= 10*time.Second {
				time.Sleep(dur)
			}
		}
		if s := r.URL.Query().Get("status"); s != "" {
			if code, err := strconv.Atoi(s); err == nil && code >= 400 && code <= 599 {
				// Still a JSON body: an error response that telemetry cannot
				// parse would hide whether redaction ran on the error path.
				applog(r, "error", "upstream failure: "+http.StatusText(code),
					map[string]string{"status": strconv.Itoa(code)})
				writeJSON(w, code, map[string]any{
					"error":   http.StatusText(code),
					"code":    code,
					"message": "injected by mocktarget",
				})
				return
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
