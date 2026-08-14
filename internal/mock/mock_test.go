package mock

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/spec"
)

const cartSpec = `
openapi: 3.0.3
info: {title: Shop, version: "1"}
paths:
  /cart:
    get:
      responses:
        "200": {description: ok}
    post:
      responses:
        "201": {description: created}
  /cart/{itemId}:
    get:
      responses:
        "200": {description: ok}
    patch:
      responses:
        "200": {description: ok}
    delete:
      responses:
        "204": {description: gone}
  /checkout:
    post:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  order_id: {type: string}
                  total_price: {type: number}
                  customer_email: {type: string}
                  status: {type: string, enum: [confirmed, pending]}
`

func newMock(t *testing.T) *httptest.Server {
	t.Helper()
	doc, err := spec.Parse([]byte(cartSpec))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(doc, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, method, url string, body string) (int, map[string]any, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, reader)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, raw
}

// The headline behavior: POST /cart, then GET /cart actually returns the item.
func TestStatefulCartFlow(t *testing.T) {
	ts := newMock(t)

	status, created, _ := do(t, "POST", ts.URL+"/cart", `{"sku": "TSHIRT-L", "qty": 2}`)
	if status != 201 {
		t.Fatalf("POST status %d", status)
	}
	id, _ := created["id"].(string)
	if id == "" || created["sku"] != "TSHIRT-L" {
		t.Fatalf("created item malformed: %v", created)
	}

	// GET the collection: our item is in it.
	status, _, raw := do(t, "GET", ts.URL+"/cart", "")
	if status != 200 || !bytes.Contains(raw, []byte("TSHIRT-L")) {
		t.Fatalf("GET /cart should list the posted item: %d %s", status, raw)
	}

	// GET the item by the id the server assigned.
	status, item, _ := do(t, "GET", ts.URL+"/cart/"+id, "")
	if status != 200 || item["sku"] != "TSHIRT-L" || item["qty"] != float64(2) {
		t.Fatalf("GET item mismatch: %d %v", status, item)
	}

	// PATCH updates in place.
	status, item, _ = do(t, "PATCH", ts.URL+"/cart/"+id, `{"qty": 5}`)
	if status != 200 || item["qty"] != float64(5) || item["sku"] != "TSHIRT-L" {
		t.Fatalf("PATCH mismatch: %d %v", status, item)
	}

	// DELETE, then GET is a 404.
	status, _, _ = do(t, "DELETE", ts.URL+"/cart/"+id, "")
	if status != 204 {
		t.Fatalf("DELETE status %d", status)
	}
	status, _, _ = do(t, "GET", ts.URL+"/cart/"+id, "")
	if status != 404 {
		t.Fatalf("deleted item should 404, got %d", status)
	}
}

func TestSchemaDrivenGeneration(t *testing.T) {
	ts := newMock(t)
	status, resp, _ := do(t, "POST", ts.URL+"/checkout", `{"cart_id": "c1"}`)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if _, ok := resp["order_id"].(string); !ok {
		t.Errorf("order_id should be a string: %v", resp)
	}
	if _, ok := resp["total_price"].(float64); !ok {
		t.Errorf("total_price should be a number: %v", resp)
	}
	email, _ := resp["customer_email"].(string)
	if !strings.Contains(email, "@") {
		t.Errorf("field-name heuristic should produce an email: %q", email)
	}
	if s := resp["status"]; s != "confirmed" && s != "pending" {
		t.Errorf("enum not respected: %v", s)
	}
}

func TestUnknownPathAndMethod(t *testing.T) {
	ts := newMock(t)
	if status, _, _ := do(t, "GET", ts.URL+"/nope", ""); status != 404 {
		t.Errorf("unknown path should 404, got %d", status)
	}
	if status, _, _ := do(t, "DELETE", ts.URL+"/checkout", ""); status != 405 {
		t.Errorf("unknown method should 405, got %d", status)
	}
}
