package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

func TestGraphQLOperationExtraction(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"operationName field", `{"operationName":"CreatePayment","query":"mutation CreatePayment {x}"}`, "CreatePayment"},
		{"parsed from query", `{"query":"mutation CreatePayment($a:Int) { x }"}`, "CreatePayment"},
		{"parsed query keyword", `{"query":"query Viewer { me { id } }"}`, "Viewer"},
		{"subscription", `{"query":"subscription OnTick { tick }"}`, "OnTick"},
		{"leading whitespace and newlines", "{\"query\":\"\\n\\n  query  Viewer {\\n me \\n}\"}", "Viewer"},
		{"comment before the operation", "{\"query\":\"# a note\\nquery Viewer { me }\"}", "Viewer"},
		{"operationName wins over query", `{"operationName":"Explicit","query":"query Other {x}"}`, "Explicit"},

		// Cases that must NOT produce a name.
		{"anonymous operation", `{"query":"{ me { id } }"}`, ""},
		{"anonymous with keyword", `{"query":"query { me }"}`, ""},
		{"not json", `query Viewer { me }`, ""},
		{"empty", ``, ""},
		{"no query or name", `{"variables":{}}`, ""},
		{"batched", `[{"query":"query A {x}"},{"query":"query B {y}"}]`, "batch"},

		// Client-supplied, so hostile input must not become a metric label.
		{"name with a quote", `{"operationName":"ev\"il"}`, ""},
		{"name with a space", `{"operationName":"two words"}`, ""},
		{"name starting with a digit", `{"operationName":"1bad"}`, ""},
		{"name with a newline", "{\"operationName\":\"a\\nb\"}", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := graphQLOperation([]byte(tc.body)); got != tc.want {
				t.Errorf("graphQLOperation(%s) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestOperationNameLengthIsCapped(t *testing.T) {
	long := strings.Repeat("a", maxOperationNameLen+1)
	body := fmt.Sprintf(`{"operationName":%q}`, long)
	if got := graphQLOperation([]byte(body)); got != "" {
		t.Errorf("an over-long operation name must not become a label, got %q", got)
	}
}

// The end-to-end claim: two operations on one path produce two routes, and a
// rule can target one of them without touching the other.
func TestGraphQLRoutesAndRulesPerOperation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"ok":true}}`)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Version: 1,
		Service: config.Service{
			Name: "gql", Upstream: upstream.URL,
			GraphQLPaths: []string{"/graphql"},
		},
		Rules: []config.Rule{{
			Name:  "redact-payment-mutation",
			Match: config.Match{Path: "/graphql", GraphQLOperation: "CreatePayment"},
			Redact: &config.Redact{
				JSONFields: []string{"$.**.cardNumber"},
			},
		}},
	}
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	writer := store.NewAsyncWriter(st, 64, slog.New(slog.DiscardHandler))
	defer writer.Close()

	handler, _, err := NewReverseProxy(cfg, engine.New(cfg),
		slog.New(slog.DiscardHandler), WithStore(writer))
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(handler)
	defer front.Close()

	post := func(body string) {
		t.Helper()
		resp, err := http.Post(front.URL+"/graphql", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	post(`{"operationName":"CreatePayment","query":"mutation CreatePayment {x}","variables":{"cardNumber":"4111111111111111"}}`)
	post(`{"operationName":"Viewer","query":"query Viewer {me}","variables":{"cardNumber":"4111111111111111"}}`)

	rec := &recorder{st: st}
	waitFor(t, func() bool { return rec.count(t) == 2 })
	recs, _, err := st.Query(t.Context(), store.Filter{})
	if err != nil {
		t.Fatal(err)
	}

	byRoute := map[string]store.Record{}
	for _, r := range recs {
		byRoute[r.Route] = r
	}
	if len(byRoute) != 2 {
		t.Fatalf("want one route per operation, got %v", byRoute)
	}
	pay, ok := byRoute["/graphql:CreatePayment"]
	if !ok {
		t.Fatalf("missing per-operation route, have %v", byRoute)
	}
	if _, ok := byRoute["/graphql:Viewer"]; !ok {
		t.Fatalf("missing per-operation route, have %v", byRoute)
	}

	// The rule targeted one operation, so only that record is redacted.
	if !strings.Contains(pay.RequestBody, "[REDACTED]") {
		t.Errorf("CreatePayment body should be redacted: %s", pay.RequestBody)
	}
	if len(pay.MatchedRules) == 0 || pay.MatchedRules[0] != "redact-payment-mutation" {
		t.Errorf("rule did not match the targeted operation: %v", pay.MatchedRules)
	}
	other := byRoute["/graphql:Viewer"]
	if len(other.MatchedRules) != 0 {
		t.Errorf("the rule leaked onto another operation: %v", other.MatchedRules)
	}
	if strings.Contains(other.RequestBody, "[REDACTED]") {
		t.Errorf("Viewer must not be redacted by a CreatePayment rule: %s", other.RequestBody)
	}
}

// Paths not listed in graphql_paths must not pay the buffering cost or gain a
// suffixed route.
func TestNonGraphQLPathsUnaffected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	base, rec := proxyTo(t, upstream, false)

	resp, err := http.Post(base+"/api/x", "application/json",
		strings.NewReader(`{"operationName":"Viewer","query":"query Viewer {me}"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	waitFor(t, func() bool { return rec.count(t) > 0 })
	if got := rec.last(t).Route; strings.Contains(got, ":") {
		t.Errorf("route %q gained an operation suffix on a non-GraphQL path", got)
	}
}
