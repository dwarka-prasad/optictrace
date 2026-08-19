package scaffold

import (
	"strings"
	"testing"
	"time"
)

const openapi3 = `
openapi: 3.0.3
info: { title: Acme Payments API, version: "2.1" }
components:
  securitySchemes:
    apiKey: { type: apiKey, in: header, name: X-Api-Key }
    sessionQuery: { type: apiKey, in: query, name: session }
    bearer: { type: http, scheme: bearer }
  schemas:
    Card:
      type: object
      properties:
        number: { type: string }
        cvv: { type: string }
        expiry: { type: string }
    Charge:
      type: object
      properties:
        amount: { type: integer }
        card: { $ref: '#/components/schemas/Card' }
paths:
  /api/v1/payments/charge:
    post:
      requestBody:
        content:
          application/json:
            schema: { $ref: '#/components/schemas/Charge' }
      responses: { "201": { description: ok } }
  /api/v1/auth/login:
    post:
      responses: { "200": { description: ok } }
  /api/v1/users/{id}/orders/{orderId}:
    get:
      responses: { "200": { description: ok } }
`

const swagger2 = `
swagger: "2.0"
info: { title: Legacy API, version: "1.0" }
securityDefinitions:
  key: { type: apiKey, in: header, name: X-Legacy-Key }
definitions:
  Payment:
    type: object
    properties:
      card_number: { type: string }
      customer:
        type: object
        properties:
          email: { type: string }
paths:
  /v1/pay:
    post:
      parameters:
        - { name: body, in: body, schema: { $ref: '#/definitions/Payment' } }
        - { name: X-Trace, in: header, type: string }
      responses:
        "200": { schema: { $ref: '#/definitions/Payment' } }
`

func parse(t *testing.T, doc string) *Document {
	t.Helper()
	d, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func TestParsesOpenAPI3(t *testing.T) {
	d := parse(t, openapi3)
	if d.Title != "Acme Payments API" || d.Swagger {
		t.Errorf("title/version detection: %+v", d)
	}
	if len(d.Paths) != 3 {
		t.Fatalf("paths = %d, want 3", len(d.Paths))
	}
	// Declared security schemes are the highest-quality signal a spec offers:
	// they NAME the credential rather than leaving it to a heuristic.
	if !contains(d.SecurityHeaders, "X-Api-Key") || !contains(d.SecurityHeaders, "Authorization") {
		t.Errorf("security headers = %v", d.SecurityHeaders)
	}
	if !contains(d.SecurityQueries, "session") {
		t.Errorf("security query params = %v", d.SecurityQueries)
	}
}

// Path templates become globs, or a rule matches nothing: /users/{id} is not a
// literal route any request has.
func TestPathTemplatesBecomeGlobs(t *testing.T) {
	d := parse(t, openapi3)
	var found string
	for _, p := range d.Paths {
		if strings.Contains(p.Raw, "{id}") {
			found = p.Glob
		}
	}
	if found != "/api/v1/users/*/orders/*" {
		t.Errorf("glob = %q, want /api/v1/users/*/orders/*", found)
	}
}

// $ref must be followed, or every field behind one is invisible — which is
// most fields in any real specification.
func TestRefsAreResolvedIntoDottedPaths(t *testing.T) {
	d := parse(t, openapi3)
	var fields []string
	for _, p := range d.Paths {
		if p.Raw == "/api/v1/payments/charge" {
			fields = p.RequestFields
		}
	}
	for _, want := range []string{"amount", "card.number", "card.cvv"} {
		if !contains(fields, want) {
			t.Errorf("field %q not reached through $ref: %v", want, fields)
		}
	}
	// A branch must contribute its leaves, not itself: emitting `card` too
	// would generate a rule masking the whole object when one field is
	// sensitive.
	if contains(fields, "card") {
		t.Errorf("intermediate object emitted as a leaf: %v", fields)
	}
}

func TestParsesSwagger2(t *testing.T) {
	d := parse(t, swagger2)
	if !d.Swagger {
		t.Error("not detected as Swagger 2.0")
	}
	if !contains(d.SecurityHeaders, "X-Legacy-Key") {
		t.Errorf("securityDefinitions not read: %v", d.SecurityHeaders)
	}
	p := d.Paths[0]
	// Swagger 2.0 puts the request body in `parameters` with in: body, and the
	// response schema directly on the response.
	if !contains(p.RequestFields, "card_number") || !contains(p.RequestFields, "customer.email") {
		t.Errorf("body parameter not walked: %v", p.RequestFields)
	}
	if !contains(p.ResponseFields, "card_number") {
		t.Errorf("response schema not walked: %v", p.ResponseFields)
	}
	if !contains(p.HeaderParams, "X-Trace") {
		t.Errorf("header parameter missed: %v", p.HeaderParams)
	}
}

// A self-referencing schema is common (a tree, a comment thread). Walking it
// must terminate rather than hang the tool.
func TestRecursiveSchemasTerminate(t *testing.T) {
	const recursive = `
openapi: 3.0.0
info: { title: T, version: "1" }
components:
  schemas:
    Node:
      type: object
      properties:
        email: { type: string }
        child: { $ref: '#/components/schemas/Node' }
paths:
  /tree:
    post:
      requestBody:
        content:
          application/json:
            schema: { $ref: '#/components/schemas/Node' }
      responses: { "200": { description: ok } }
`
	done := make(chan *Document, 1)
	go func() { done <- parse(t, recursive) }()
	select {
	case d := <-done:
		if len(d.Paths) != 1 {
			t.Fatal("no paths")
		}
		if !contains(d.Paths[0].RequestFields, "email") {
			t.Errorf("fields = %v", d.Paths[0].RequestFields)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parsing a self-referencing schema did not terminate")
	}
}

func TestCompositionKeywordsAreWalked(t *testing.T) {
	const composed = `
openapi: 3.0.0
info: { title: T, version: "1" }
components:
  schemas:
    Base: { type: object, properties: { id: { type: string } } }
    WithSecret: { type: object, properties: { password: { type: string } } }
paths:
  /x:
    post:
      requestBody:
        content:
          application/json:
            schema:
              allOf:
                - { $ref: '#/components/schemas/Base' }
                - { $ref: '#/components/schemas/WithSecret' }
      responses: { "200": { description: ok } }
`
	d := parse(t, composed)
	// A field reachable through any branch is reachable, so missing one leaves
	// a documented field unmasked.
	if !contains(d.Paths[0].RequestFields, "password") {
		t.Errorf("allOf branch not walked: %v", d.Paths[0].RequestFields)
	}
}

func TestArraysDoNotAddIndexesToPaths(t *testing.T) {
	const arr = `
openapi: 3.0.0
info: { title: T, version: "1" }
paths:
  /orders:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                items:
                  type: array
                  items:
                    type: object
                    properties: { card_number: { type: string } }
      responses: { "200": { description: ok } }
`
	d := parse(t, arr)
	// optic.yaml traverses lists implicitly, so `items.card_number` masks the
	// field in every element. An index in the path would match nothing.
	if !contains(d.Paths[0].RequestFields, "items.card_number") {
		t.Errorf("array element fields = %v", d.Paths[0].RequestFields)
	}
}

func TestBadDocumentsAreRejectedClearly(t *testing.T) {
	cases := map[string]string{
		"not a spec at all": "just: some: yaml\n",
		"empty":             "",
		"no paths":          "openapi: 3.0.0\ninfo: { title: T, version: '1' }\n",
		"paths with no ops": "openapi: 3.0.0\ninfo: { title: T, version: '1' }\npaths: { /x: {} }\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted a document it cannot generate from", name)
		}
	}
}

// Remote refs are not fetched: a scaffolding tool that reaches out to read a
// URL in a file it was handed is a tool that can be pointed at anything.
func TestRemoteRefsAreNotFetched(t *testing.T) {
	const remote = `
openapi: 3.0.0
info: { title: T, version: "1" }
paths:
  /x:
    post:
      requestBody:
        content:
          application/json:
            schema: { $ref: 'https://evil.example/schema.json#/Secret' }
      responses: { "200": { description: ok } }
`
	d := parse(t, remote)
	if len(d.Paths[0].RequestFields) != 0 {
		t.Errorf("a remote ref produced fields: %v", d.Paths[0].RequestFields)
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
