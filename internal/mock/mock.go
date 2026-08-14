// Package mock turns an OpenAPI spec into a running, STATEFUL mock server:
//
//	optictrace mock -spec openapi.yaml -listen :7070
//
// Three layers, in order of preference per request:
//
//  1. State: collection/item routes (POST /cart then GET /cart/{id} returns
//     what you posted) backed by an in-memory store. This is what makes the
//     mock believable for frontend flows — state, not canned JSON.
//  2. AI (optional, -ai + ANTHROPIC_API_KEY): non-CRUD operations ask Claude
//     for a context-aware response conforming to the response schema.
//  3. Deterministic generation: realistic values from schema + field-name
//     heuristics (emails look like emails, prices look like prices).
//
// Any failure in layer 2 falls back to layer 3 — the mock never depends on
// network access to function.
package mock

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/dwarka-prasad/optictrace/internal/spec"
)

type Options struct {
	AI bool // enable Claude-generated responses when ANTHROPIC_API_KEY is set
}

type Server struct {
	spec   *spec.Spec
	logger *slog.Logger
	ai     *aiClient // nil when disabled

	mu          sync.Mutex
	collections map[string]map[string]map[string]any // collection tmpl -> id -> object
	nextID      map[string]int
}

func New(s *spec.Spec, logger *slog.Logger, opts Options) *Server {
	srv := &Server{
		spec:        s,
		logger:      logger,
		collections: map[string]map[string]map[string]any{},
		nextID:      map[string]int{},
	}
	if opts.AI {
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			srv.ai = newAIClient(key, logger)
		} else {
			logger.Warn("-ai requested but ANTHROPIC_API_KEY is not set; using deterministic generation")
		}
	}
	return srv
}

func (s *Server) AIEnabled() bool { return s.ai != nil }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tmpl, ok := s.spec.MatchPath(r.URL.Path)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such path in spec", "path": r.URL.Path})
		return
	}
	op := s.spec.Paths[tmpl][strings.ToLower(r.Method)]
	if op == nil {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not in spec", "path": tmpl})
		return
	}

	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)

	status, payload := s.handle(r, tmpl, op, body)
	s.logger.Info("mock", "method", r.Method, "path", r.URL.Path, "template", tmpl, "status", status)
	writeJSON(w, status, payload)
}

// handle routes between stateful CRUD and pure generation. The state lock
// is never held across generation (which may call the AI layer).
func (s *Server) handle(r *http.Request, tmpl string, op *spec.Operation, body map[string]any) (int, any) {
	if status, payload, done := s.tryStateful(r.Method, tmpl, r.URL.Path, op, body); done {
		return status, payload
	}
	return s.generateResponse(r, tmpl, op, body)
}

// tryStateful serves CRUD routes from the in-memory store; done=false means
// the request is not stateful (or an empty first GET) and should fall
// through to generation.
func (s *Server) tryStateful(method, tmpl, concrete string, op *spec.Operation, body map[string]any) (int, any, bool) {
	itemColl, id, isItem := s.itemRoute(tmpl, concrete)
	isColl := s.collectionRoute(tmpl)

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case isItem:
		if status, payload := s.handleItem(method, itemColl, id, op, body); status != 0 {
			return status, payload, true
		}
	case isColl && method == http.MethodPost:
		coll := s.coll(tmpl)
		newID := s.idFor(tmpl, body)
		obj := body
		if obj == nil {
			obj = map[string]any{}
		}
		obj["id"] = newID
		coll[newID] = obj
		return successStatus(op, http.StatusCreated), obj, true
	case isColl && method == http.MethodGet:
		coll := s.coll(tmpl)
		if len(coll) > 0 {
			items := make([]any, 0, len(coll))
			for _, v := range coll {
				items = append(items, v)
			}
			return http.StatusOK, items, true
		}
		// Empty store: generation gives the first paint some data.
	}
	return 0, nil, false
}

func (s *Server) handleItem(method, collTmpl, id string, op *spec.Operation, body map[string]any) (int, any) {
	coll := s.coll(collTmpl)
	existing, found := coll[id]
	switch method {
	case http.MethodGet:
		if found {
			return http.StatusOK, existing
		}
		return http.StatusNotFound, map[string]any{"error": "not found", "id": id}
	case http.MethodPut:
		obj := body
		if obj == nil {
			obj = map[string]any{}
		}
		obj["id"] = id
		coll[id] = obj
		if found {
			return http.StatusOK, obj
		}
		return successStatus(op, http.StatusCreated), obj
	case http.MethodPatch:
		if !found {
			return http.StatusNotFound, map[string]any{"error": "not found", "id": id}
		}
		for k, v := range body {
			existing[k] = v
		}
		return http.StatusOK, existing
	case http.MethodDelete:
		if !found {
			return http.StatusNotFound, map[string]any{"error": "not found", "id": id}
		}
		delete(coll, id)
		return http.StatusNoContent, nil
	}
	return 0, nil // non-CRUD verb on an item route -> generation path
}

// generateResponse produces a schema-conforming payload: AI first (when
// enabled), deterministic generator as the always-available fallback.
func (s *Server) generateResponse(r *http.Request, tmpl string, op *spec.Operation, body map[string]any) (int, any) {
	status := successStatus(op, http.StatusOK)
	schema := s.responseSchemaFor(op)

	if s.ai != nil {
		if payload, err := s.ai.generate(r, tmpl, op, schema, body, s.spec); err == nil {
			return status, payload
		} else {
			s.logger.Warn("ai generation failed; using deterministic fallback", "error", err)
		}
	}
	if schema == nil {
		return status, map[string]any{"ok": true}
	}
	return status, Generate(s.spec, schema, "")
}

// --- route classification -----------------------------------------------

// itemRoute reports whether tmpl is a /collection/{id} route and extracts
// the live id from the concrete path.
func (s *Server) itemRoute(tmpl, concrete string) (collTmpl, id string, ok bool) {
	segs := strings.Split(strings.Trim(tmpl, "/"), "/")
	if len(segs) < 2 {
		return "", "", false
	}
	last := segs[len(segs)-1]
	if !strings.HasPrefix(last, "{") || !strings.HasSuffix(last, "}") {
		return "", "", false
	}
	concSegs := strings.Split(strings.Trim(concrete, "/"), "/")
	if len(concSegs) != len(segs) {
		return "", "", false
	}
	return "/" + strings.Join(segs[:len(segs)-1], "/"), concSegs[len(segs)-1], true
}

// collectionRoute reports whether the spec also defines tmpl + "/{param}" —
// the signature of a stateful collection.
func (s *Server) collectionRoute(tmpl string) bool {
	prefix := strings.TrimSuffix(tmpl, "/") + "/"
	for p := range s.spec.Paths {
		if strings.HasPrefix(p, prefix) {
			rest := strings.TrimPrefix(p, prefix)
			if strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") && !strings.Contains(rest, "/") {
				return true
			}
		}
	}
	return false
}

func (s *Server) coll(tmpl string) map[string]map[string]any {
	key := strings.TrimSuffix(tmpl, "/")
	if s.collections[key] == nil {
		s.collections[key] = map[string]map[string]any{}
	}
	return s.collections[key]
}

func (s *Server) idFor(tmpl string, body map[string]any) string {
	if body != nil {
		if v, ok := body["id"]; ok {
			return fmt.Sprint(v)
		}
	}
	s.nextID[tmpl]++
	segs := strings.Split(strings.Trim(tmpl, "/"), "/")
	prefix := "item"
	if len(segs) > 0 {
		prefix = strings.TrimSuffix(segs[len(segs)-1], "s")
	}
	return fmt.Sprintf("%s_%04d", prefix, s.nextID[tmpl])
}

func (s *Server) responseSchemaFor(op *spec.Operation) *spec.Schema {
	for code, resp := range op.Responses {
		if strings.HasPrefix(code, "2") && resp.Content != nil {
			if m := resp.Content["application/json"]; m != nil {
				return s.spec.Resolve(m.Schema)
			}
		}
	}
	if resp := op.Responses["default"]; resp != nil && resp.Content != nil {
		if m := resp.Content["application/json"]; m != nil {
			return s.spec.Resolve(m.Schema)
		}
	}
	return nil
}

func successStatus(op *spec.Operation, fallback int) int {
	best := 0
	for code := range op.Responses {
		if strings.HasPrefix(code, "2") {
			var n int
			fmt.Sscanf(code, "%d", &n)
			if best == 0 || n < best {
				best = n
			}
		}
	}
	if best == 0 {
		return fallback
	}
	return best
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	if status == http.StatusNoContent || v == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- deterministic generation ------------------------------------------

var nameHints = []struct {
	contains string
	gen      func() any
}{
	{"email", func() any { return pick([]any{"ada@example.com", "grace@example.com", "alan@example.com"}) }},
	{"phone", func() any { return "+1-555-0142" }},
	{"first_name", func() any { return pick([]any{"Ada", "Grace", "Alan", "Edsger"}) }},
	{"last_name", func() any { return pick([]any{"Lovelace", "Hopper", "Turing", "Dijkstra"}) }},
	{"name", func() any { return pick([]any{"Ada Lovelace", "Grace Hopper", "Alan Turing"}) }},
	{"city", func() any { return pick([]any{"Bengaluru", "Berlin", "Austin", "Tokyo"}) }},
	{"country", func() any { return pick([]any{"IN", "DE", "US", "JP"}) }},
	{"currency", func() any { return pick([]any{"USD", "EUR", "INR"}) }},
	{"amount", func() any { return rand.IntN(9000) + 100 }},
	{"price", func() any { return float64(rand.IntN(90000)+1000) / 100 }},
	{"total", func() any { return rand.IntN(9000) + 100 }},
	{"count", func() any { return rand.IntN(40) + 1 }},
	{"quantity", func() any { return rand.IntN(9) + 1 }},
	{"url", func() any { return "https://example.com/resource" }},
	{"description", func() any { return "Generated by the OpticTrace mock server." }},
	{"status", func() any { return pick([]any{"active", "pending", "succeeded"}) }},
	{"token", func() any { return "mock_tok_" + hexn(12) }},
	{"id", func() any { return "mock_" + hexn(8) }},
	{"date", func() any { return "2026-08-15" }},
	{"time", func() any { return "2026-08-15T10:30:00Z" }},
}

// Generate produces a realistic value for a schema; fieldName drives the
// heuristics ("email" fields get emails).
func Generate(s *spec.Spec, sc *spec.Schema, fieldName string) any {
	sc = s.Resolve(sc)
	if sc == nil {
		return nil
	}
	if sc.Example != nil {
		return sc.Example
	}
	if len(sc.Enum) > 0 {
		return sc.Enum[rand.IntN(len(sc.Enum))]
	}
	switch sc.Type {
	case "object":
		out := map[string]any{}
		for name, child := range sc.Properties {
			out[name] = Generate(s, child, name)
		}
		return out
	case "array":
		n := rand.IntN(2) + 2
		items := make([]any, n)
		for i := range items {
			items[i] = Generate(s, sc.Items, strings.TrimSuffix(fieldName, "s"))
		}
		return items
	case "string":
		switch sc.Format {
		case "date-time":
			return "2026-08-15T10:30:00Z"
		case "date":
			return "2026-08-15"
		case "email":
			return "ada@example.com"
		case "uuid":
			return "8f14e45f-ea4c-4c3e-9b2b-0d5c8a1f6e2d"
		case "uri":
			return "https://example.com/resource"
		}
		lower := strings.ToLower(fieldName)
		for _, h := range nameHints {
			if strings.Contains(lower, h.contains) {
				return h.gen()
			}
		}
		return "sample-" + hexn(4)
	case "integer":
		return rand.IntN(1000) + 1
	case "number":
		return float64(rand.IntN(100000)) / 100
	case "boolean":
		return rand.IntN(2) == 0
	default:
		return nil
	}
}

func pick(vals []any) any { return vals[rand.IntN(len(vals))] }

func hexn(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.IntN(16)]
	}
	return string(b)
}
