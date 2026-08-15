package spec

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The generators are only useful if their output actually compiles. These
// tests parse the Go output with the real Go parser and assert on the
// structural markers of the Python output; a full compile of both is done in
// scripts/e2e-generators (and manually verified against the live store).

func TestGenerateGoParses(t *testing.T) {
	doc := Infer("payments-api", traffic())
	src := GenerateGo(doc, "apiclient")

	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "client.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated Go does not parse: %v\n\n%s", err, numbered(src))
	}
	for _, want := range []string{
		"package apiclient",
		"type Client struct",
		"func NewClient(baseURL string) *Client",
		"type APIError struct",
		"func (c *Client) PostApiV1PaymentsCharge(ctx context.Context, body PostApiV1PaymentsChargeRequest)",
		"func (c *Client) GetApiV1UsersByUserId(ctx context.Context, userId string)",
		`fmt.Sprintf("/api/v1/users/%s", userId)`,
		"`json:\"amount\"`",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated Go missing %q", want)
		}
	}
	// Optional fields must be omitempty; required ones must not be.
	if !strings.Contains(src, "`json:\"coupon,omitempty\"`") {
		t.Error("optional field should carry omitempty")
	}
}

func TestGeneratePythonStructure(t *testing.T) {
	doc := Infer("payments-api", traffic())
	src := GeneratePython(doc)

	for _, want := range []string{
		"class PaymentsApiClient:",
		"class ApiError(Exception):",
		"def post_api_v1_payments_charge(self, body: PostApiV1PaymentsChargeRequest)",
		"def get_api_v1_users_by_user_id(self, user_id: str)",
		`path = f"/api/v1/users/{user_id}"`,
		"TypedDict",
		"amount: float",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("generated Python missing %q", want)
		}
	}
	// Required vs optional split via the Required base class + total=False.
	if !strings.Contains(src, "class PostApiV1PaymentsChargeRequestRequired(TypedDict):") {
		t.Error("required keys should live in a Required base class")
	}
	if !strings.Contains(src, "total=False") {
		t.Error("optional keys need total=False")
	}
	// Indentation must be consistent — Python is whitespace-sensitive, so a
	// stray tab would be a silent syntax error at import time.
	if strings.Contains(src, "\t") {
		t.Error("generated Python must not contain tabs")
	}
}

func TestIdentifierSafety(t *testing.T) {
	cases := map[string]string{
		"user-id": "user_id",
		"UserID":  "user_id",
		"class":   "class_",
		"2fa":     "p2fa",
		"a.b.c":   "a_b_c",
	}
	for in, want := range cases {
		if got := pyIdent(in); got != want {
			t.Errorf("pyIdent(%q) = %q, want %q", in, got, want)
		}
	}
	// Go identifiers must dodge keywords and stay lowerCamel.
	if got := goIdent("type"); got != "typeParam" {
		t.Errorf("goIdent(type) = %q, want typeParam", got)
	}
	if got := goIdent("user-id"); got != "userId" {
		t.Errorf("goIdent(user-id) = %q, want userId", got)
	}
}

func numbered(s string) string {
	var b strings.Builder
	for i, line := range strings.Split(s, "\n") {
		b.WriteString(strings.TrimRight(line, " ") + "\n")
		if i > 60 {
			b.WriteString("...\n")
			break
		}
	}
	return b.String()
}
