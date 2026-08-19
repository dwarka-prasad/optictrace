package scaffold

import (
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/internal/config"
)

// The generated file must be one the agent accepts. A scaffolding tool that
// emits config the agent then refuses is worse than no tool: it teaches people
// the format is unreliable.
func mustValidate(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("generated config does not parse: %v\n%s", err, yaml)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("generated config does not validate: %v\n%s", err, yaml)
	}
	return cfg
}

func TestGeneratedConfigIsValid(t *testing.T) {
	res := Generate(parse(t, openapi3), Options{})
	cfg := mustValidate(t, res.YAML)
	if cfg.Service.Name != "acme-payments-api" {
		t.Errorf("service name = %q", cfg.Service.Name)
	}
	if res.Rules < 3 {
		t.Errorf("only %d rule(s) generated", res.Rules)
	}
}

// The single most important field in any payment API, reached the way every
// payment API actually models it.
func TestCardNumberIsMasked(t *testing.T) {
	res := Generate(parse(t, openapi3), Options{})
	if !strings.Contains(res.YAML, "card.number") {
		t.Errorf("a nested card number was not masked:\n%s", res.YAML)
	}
	if !strings.Contains(res.YAML, "card.cvv") {
		t.Error("cvv not masked")
	}
}

// Redaction paths use `$.**.` because the document describes one shape, but the
// same object routinely appears nested in a wrapper or echoed in a response.
func TestRedactionPathsUseRecursiveDescent(t *testing.T) {
	res := Generate(parse(t, openapi3), Options{})
	for _, line := range strings.Split(res.YAML, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, `- "$.`) && !strings.HasPrefix(l, `- "$.**.`) {
			t.Errorf("redaction path is not recursive: %s", l)
		}
	}
}

// A credential exchange is the one place where no redaction rule beats not
// recording the body at all.
func TestAuthRoutesAreRestrictedNotRedacted(t *testing.T) {
	res := Generate(parse(t, openapi3), Options{})
	cfg := mustValidate(t, res.YAML)

	var found bool
	for _, r := range cfg.Rules {
		if strings.Contains(r.Match.Path, "/auth/login") {
			found = true
			if len(r.Restrict) == 0 {
				t.Errorf("the login route is not restricted: %+v", r)
			}
		}
	}
	if !found {
		t.Error("no rule was generated for the login route")
	}
}

// Declared schemes are the part a spec STATES; guessing over them would throw
// away the only reliable signal in the document.
func TestDeclaredSecuritySchemesBecomeRedactions(t *testing.T) {
	res := Generate(parse(t, openapi3), Options{})
	for _, want := range []string{"X-Api-Key", "Authorization", "Cookie", "session"} {
		if !strings.Contains(res.YAML, want) {
			t.Errorf("declared credential %q is not redacted:\n%s", want, res.YAML)
		}
	}
}

// Masking every `name` field produces telemetry nobody can debug with, and a
// rule people delete in week one protects nothing afterwards.
func TestLowConfidenceNamesAreOptIn(t *testing.T) {
	const withName = `
openapi: 3.0.0
info: { title: T, version: "1" }
paths:
  /people:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                first_name: { type: string }
                email: { type: string }
      responses: { "200": { description: ok } }
`
	doc := parse(t, withName)

	off := Generate(doc, Options{})
	if strings.Contains(off.YAML, "first_name") {
		t.Error("a low-confidence name was masked by default")
	}
	if !strings.Contains(off.YAML, "email") {
		t.Error("a medium-confidence field should be masked by default")
	}
	if !mentions(off.Notes, "Low-confidence") {
		t.Errorf("the skip must be disclosed: %v", off.Notes)
	}

	on := Generate(doc, Options{IncludeLow: true})
	if !strings.Contains(on.YAML, "first_name") {
		t.Error("-include-low did not mask low-confidence names")
	}
}

// A scaffolded config that looks finished is worse than one that admits what it
// left out.
func TestNotesDiscloseWhatCouldNotBeDetermined(t *testing.T) {
	const bare = `
openapi: 3.0.0
info: { title: Bare, version: "1" }
paths:
  /things:
    get:
      responses: { "200": { description: ok } }
`
	res := Generate(parse(t, bare), Options{})
	if !mentions(res.Notes, "no security schemes") {
		t.Errorf("a document with no declared schemes must say the headers were guessed: %v", res.Notes)
	}
	if !mentions(res.Notes, "No payload field matched") {
		t.Errorf("finding nothing must be reported, not left to look like completeness: %v", res.Notes)
	}
	if !mentions(res.Notes, "optictrace scan") {
		t.Errorf("the notes must point at value-based scanning: %v", res.Notes)
	}
	// And the file itself carries the caveat, because notes go to stderr and a
	// redirect keeps only the file.
	if !strings.Contains(res.YAML, "starting point") {
		t.Error("the generated file does not say what it is")
	}
}

// Regenerating must produce an identical file, or every run makes a diff and a
// noisy diff is one nobody reads.
func TestGenerationIsDeterministic(t *testing.T) {
	doc := parse(t, openapi3)
	first := Generate(doc, Options{}).YAML
	for i := 0; i < 5; i++ {
		if got := Generate(parse(t, openapi3), Options{}).YAML; got != first {
			t.Fatal("generation is not stable across runs")
		}
	}
}

func TestSwagger2GeneratesTheSameShape(t *testing.T) {
	res := Generate(parse(t, swagger2), Options{})
	mustValidate(t, res.YAML)
	if !strings.Contains(res.YAML, "card_number") {
		t.Errorf("swagger body field not masked:\n%s", res.YAML)
	}
	if !strings.Contains(res.YAML, "X-Legacy-Key") {
		t.Error("swagger securityDefinitions not honoured")
	}
	if !strings.Contains(res.YAML, "Swagger 2.0") {
		t.Error("the header should name the document kind it came from")
	}
}

func TestServiceListenAndUpstreamOverrides(t *testing.T) {
	res := Generate(parse(t, openapi3), Options{
		ServiceName: "custom", Listen: ":8080", Upstream: "http://localhost:9000",
	})
	cfg := mustValidate(t, res.YAML)
	if cfg.Service.Name != "custom" || cfg.Service.Listen != ":8080" ||
		cfg.Service.Upstream != "http://localhost:9000" {
		t.Errorf("overrides not applied: %+v", cfg.Service)
	}
}

func mentions(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
