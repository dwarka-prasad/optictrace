package spec

import (
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

func traffic() []store.Record {
	now := time.Now()
	return []store.Record{
		{Method: "POST", Path: "/api/v1/payments/charge", Status: 201, Time: now,
			RequestBody:  `{"amount": 42, "currency": "USD", "credit_card": {"number": "[REDACTED]"}}`,
			ResponseBody: `{"charge_id": "ch_1", "status": "succeeded"}`},
		{Method: "POST", Path: "/api/v1/payments/charge", Status: 201, Time: now,
			RequestBody:  `{"amount": 10.5, "currency": "EUR", "coupon": "SAVE10"}`,
			ResponseBody: `{"charge_id": "ch_2", "status": "succeeded"}`},
		{Method: "GET", Path: "/api/v1/users/42", Status: 200, Time: now,
			ResponseBody: `{"id": "42", "email": "ada@example.com"}`},
		{Method: "GET", Path: "/api/v1/users/97", Status: 200, Time: now,
			ResponseBody: `{"id": "97", "email": "grace@example.com"}`},
	}
}

func TestInfer(t *testing.T) {
	doc := Infer("test-api", traffic())

	if doc.Paths["/api/v1/payments/charge"] == nil {
		t.Fatalf("missing charge path: %v", keys(doc.Paths))
	}
	// ID segments collapse into one templated path.
	if doc.Paths["/api/v1/users/{userId}"] == nil {
		t.Fatalf("expected /api/v1/users/{userId}, got %v", keys(doc.Paths))
	}

	op := doc.Paths["/api/v1/payments/charge"]["post"]
	if op == nil {
		t.Fatal("missing post op")
	}
	req := doc.requestSchema(op)
	if req == nil || req.Type != "object" {
		t.Fatalf("bad request schema: %+v", req)
	}
	// Union of observed fields...
	for _, f := range []string{"amount", "currency", "credit_card", "coupon"} {
		if req.Properties[f] == nil {
			t.Errorf("request schema missing observed field %q", f)
		}
	}
	// ...but required = fields present in EVERY request.
	reqd := strings.Join(req.Required, ",")
	if strings.Contains(reqd, "coupon") || strings.Contains(reqd, "credit_card") {
		t.Errorf("optional fields marked required: %v", req.Required)
	}
	if !strings.Contains(reqd, "amount") {
		t.Errorf("amount should be required: %v", req.Required)
	}
	// integer merged with float widens to number.
	if req.Properties["amount"].Type != "number" {
		t.Errorf("amount should widen to number, got %q", req.Properties["amount"].Type)
	}
	// Redacted values still contribute structure.
	cc := req.Properties["credit_card"]
	if cc == nil || cc.Properties["number"] == nil || cc.Properties["number"].Type != "string" {
		t.Errorf("redacted field lost structure: %+v", cc)
	}
	if op.Responses["201"] == nil {
		t.Errorf("missing 201 response: %v", keys(op.Responses))
	}

	userOp := doc.Paths["/api/v1/users/{userId}"]["get"]
	if len(userOp.Parameters) != 1 || userOp.Parameters[0].Name != "userId" {
		t.Errorf("expected userId path param, got %+v", userOp.Parameters)
	}
}

const handSpec = `
openapi: 3.0.3
info: {title: Test, version: "1"}
paths:
  /api/v1/payments/charge:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Charge'
      responses:
        "201":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  charge_id: {type: string}
  /api/v1/refunds:
    post:
      responses:
        "201": {description: ok}
components:
  schemas:
    Charge:
      type: object
      properties:
        amount: {type: number}
        currency: {type: string}
`

func TestCheckFindsDivergence(t *testing.T) {
	doc, err := Parse([]byte(handSpec))
	if err != nil {
		t.Fatal(err)
	}
	findings := Check(doc, traffic())

	if !HasBreaking(findings) {
		t.Fatalf("expected breaking findings, got %+v", findings)
	}
	assertFinding := func(kind, substr string) {
		t.Helper()
		for _, f := range findings {
			if f.Kind == kind && strings.Contains(f.Message, substr) {
				return
			}
		}
		t.Errorf("missing finding kind=%s containing %q in %+v", kind, substr, findings)
	}
	// GET /users/{id} carries traffic but is not in the spec at all.
	assertFinding("endpoint-missing-from-spec", "/api/v1/users/{userId}")
	// Clients send credit_card + coupon; spec's Charge schema omits them.
	assertFinding("request-field-missing-from-spec", "credit_card")
	assertFinding("request-field-missing-from-spec", "coupon")
	// Responses include status; spec only documents charge_id.
	assertFinding("response-field-undocumented", "status")
	// Spec's /refunds has no observed traffic.
	assertFinding("endpoint-unused", "/api/v1/refunds")

	// Nested children of a missing parent are not double-reported.
	for _, f := range findings {
		if f.Field == "credit_card.number" {
			t.Errorf("child of missing parent should be collapsed: %+v", f)
		}
	}
}

func TestCheckCleanSpecPasses(t *testing.T) {
	// A spec inferred from the same traffic must produce no breaking findings.
	doc := Infer("test-api", traffic())
	findings := Check(doc, traffic())
	if HasBreaking(findings) {
		t.Fatalf("self-inferred spec should never be breaking: %+v", findings)
	}
}

func TestGenerateTypeScript(t *testing.T) {
	doc := Infer("payments-api", traffic())
	ts := GenerateTypeScript(doc)

	for _, want := range []string{
		"export class PaymentsApiClient",
		"async postApiV1PaymentsCharge(",
		"PostApiV1PaymentsChargeRequest",
		"amount: number;",  // required, widened
		"coupon?: string;", // optional
		"async getApiV1UsersByUserId(userId: string | number)",
		"`/api/v1/users/${userId}`",
		"export class ApiError",
	} {
		if !strings.Contains(ts, want) {
			t.Errorf("generated TS missing %q", want)
		}
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
