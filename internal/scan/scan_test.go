package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

func TestLuhnPrecision(t *testing.T) {
	// Real, publicly-documented test card numbers (Luhn-valid by design).
	for _, valid := range []string{"4111111111111111", "5500005555555559", "4012 8888 8888 1881"} {
		if !luhnValid(valid) {
			t.Errorf("%q should pass Luhn", valid)
		}
	}
	// The precision cases: long digit strings that must NOT be flagged.
	for _, invalid := range []string{
		"4111111111111112", // one digit off — checksum fails
		"1234567890123456", // sequential order id
		"0000000000000000", // uniform
		"1699999999999999", // timestamp-ish
	} {
		if luhnValid(invalid) {
			t.Errorf("%q should NOT pass Luhn", invalid)
		}
	}
}

func TestDetectorsFindRealSecrets(t *testing.T) {
	cases := map[string]string{
		"credit-card":       `{"pan":"4111111111111111"}`,
		"jwt":               `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
		"aws-access-key-id": `AKIAIOSFODNN7EXAMPLE`,
		"github-token":      `ghp_1234567890abcdefghijklmnopqrstuvwxyz`,
		"private-key":       "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
		"email":             `ada@example.com`,
		"us-ssn":            `078-05-1120`,
	}
	for wantKind, input := range cases {
		found := false
		for _, m := range Find(input) {
			if m.Kind == wantKind {
				found = true
				if strings.Contains(m.Masked, "1111111111") || strings.Contains(m.Masked, "EXAMPLE") {
					t.Errorf("%s: masked sample leaks the raw value: %q", wantKind, m.Masked)
				}
			}
		}
		if !found {
			t.Errorf("detector %q did not fire on %q", wantKind, input)
		}
	}
}

func TestNoFalsePositivesOnOrdinaryPayloads(t *testing.T) {
	benign := []string{
		`{"order_id":"ORD-2024-0001","qty":3,"total":149.99}`,
		`{"status":"succeeded","charge_id":"ch_12345"}`,
		`{"timestamp":1699999999999,"duration_ms":42}`,
		`{"description":"Standard shipping to warehouse 12"}`,
	}
	for _, b := range benign {
		if m := Find(b); len(m) > 0 {
			t.Errorf("false positive on %q: %+v", b, m)
		}
	}
}

func TestRedactedValuesAreNotFlagged(t *testing.T) {
	// Governance already worked here — the scanner must stay quiet.
	if m := Find("[REDACTED]"); len(m) > 0 {
		t.Errorf("redacted placeholder should not be flagged: %+v", m)
	}
}

func TestRecordsAggregatesAndSuggests(t *testing.T) {
	now := time.Now()
	recs := []store.Record{
		{Method: "POST", Route: "/api/v1/orders/**", Time: now,
			RequestBody: `{"payment":{"pan":"4111111111111111"},"qty":1}`},
		{Method: "POST", Route: "/api/v1/orders/**", Time: now.Add(time.Minute),
			RequestBody: `{"payment":{"pan":"5500005555555559"},"qty":2}`},
		{Method: "GET", Route: "/api/v1/users/:id", Time: now,
			ResponseHeaders: map[string]string{"X-Debug-Token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"}},
	}
	rep := Records(recs, now.Add(-time.Hour))

	if rep.Scanned != 3 {
		t.Errorf("scanned = %d, want 3", rep.Scanned)
	}
	var card, token *Finding
	for i := range rep.Findings {
		switch rep.Findings[i].Kind {
		case "credit-card":
			card = &rep.Findings[i]
		case "github-token":
			token = &rep.Findings[i]
		}
	}
	if card == nil {
		t.Fatalf("no credit-card finding: %+v", rep.Findings)
	}
	// Two different cards at the same field on the same route = one finding.
	if card.Count != 2 {
		t.Errorf("card count = %d, want 2 (aggregated)", card.Count)
	}
	if card.Field != "$.payment.pan" {
		t.Errorf("card field = %q, want $.payment.pan", card.Field)
	}
	if !strings.Contains(card.Suggest, `json_fields: ["$.payment.pan"]`) {
		t.Errorf("suggestion should be copy-pasteable, got %q", card.Suggest)
	}
	if token == nil {
		t.Fatal("header token not detected")
	}
	if !strings.Contains(token.Suggest, "headers: [X-Debug-Token]") {
		t.Errorf("header suggestion wrong: %q", token.Suggest)
	}
	// Critical sorts above high.
	if rep.Findings[0].Severity != SevCritical {
		t.Errorf("expected critical first, got %s", rep.Findings[0].Severity)
	}
	if !rep.HasAtLeast(SevHigh) || !rep.HasAtLeast(SevCritical) {
		t.Error("severity gate should trip")
	}
	// Nothing anywhere in the report may contain a raw secret.
	all := ""
	for _, f := range rep.Findings {
		all += f.Sample + f.Field + f.Suggest + f.Why
	}
	for _, secret := range []string{"4111111111111111", "5500005555555559", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"} {
		if strings.Contains(all, secret) {
			t.Errorf("report leaks raw secret %q", secret)
		}
	}
}

func TestCleanTrafficProducesNoFindings(t *testing.T) {
	recs := []store.Record{
		{Method: "POST", Route: "/api/v1/payments/**", Time: time.Now(),
			RequestBody: `{"amount":42,"credit_card":{"number":"[REDACTED]"}}`},
	}
	rep := Records(recs, time.Now().Add(-time.Hour))
	if len(rep.Findings) != 0 {
		t.Errorf("properly redacted traffic should be clean, got %+v", rep.Findings)
	}
	if rep.HasAtLeast(SevMedium) {
		t.Error("gate should not trip on clean traffic")
	}
}

// A statement is free text a driver assembled, and the parameter it
// interpolated is the customer's. The leak detector reported CLEAN on exactly
// that surface until it looked there — and since `scan -fail-on high` is the CI
// gate, a team got a green build over a stored card number.
func TestScannerFindsSecretsInSpanAttributes(t *testing.T) {
	sc := NewScanner(time.Now().Add(-time.Hour))
	sc.AddSpan(&ext.Span{
		Start: time.Now(), Service: "shop", Name: "db.query", Kind: "db",
		Attrs: map[string]string{
			"db.statement": "SELECT * FROM cards WHERE number = '4111111111111111'",
			"db.rows":      "1",
		},
	})
	sc.AddSpan(&ext.Span{
		Start: time.Now(), Service: "shop", Name: "db.insert", Kind: "db",
		// A driver error quotes the statement that failed, parameters included.
		Error: "duplicate key for a@b.com",
	})

	rep := sc.Report()
	if rep.SpansScanned != 2 {
		t.Errorf("spans scanned = %d, want 2 — the count is what distinguishes "+
			"'nothing found' from 'nothing looked at'", rep.SpansScanned)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings: a Luhn-valid card number in db.statement must be caught")
	}

	var card, email *Finding
	for i := range rep.Findings {
		f := &rep.Findings[i]
		if f.Location != "span_attr" {
			t.Errorf("finding located in %q, want span_attr", f.Location)
		}
		switch f.Field {
		case "db.statement":
			card = f
		case "error":
			email = f
		}
	}
	if card == nil {
		t.Fatal("the card number in db.statement was not found")
	}
	if card.Severity != SevHigh && card.Severity != SevCritical {
		t.Errorf("card severity = %q, want high or above", card.Severity)
	}
	if !strings.Contains(card.Sample, "••") {
		t.Errorf("the sample must be masked, got %q", card.Sample)
	}
	if strings.Contains(card.Sample, "4111111111111111") {
		t.Errorf("a finding must never quote the value it found: %q", card.Sample)
	}
	// The fix has to be one that can actually work. Suggesting json_fields for
	// a span attribute is advice that silently does nothing.
	if !strings.Contains(card.Suggest, "spans:") || !strings.Contains(card.Suggest, "redact") {
		t.Errorf("suggestion does not point at telemetry.spans.redact: %q", card.Suggest)
	}
	if strings.Contains(card.Suggest, "json_fields") {
		t.Errorf("a span attribute has no JSON path; suggestion was %q", card.Suggest)
	}
	if card.Route != "span:db.query" {
		t.Errorf("route = %q, want the operation name so the fix is locatable", card.Route)
	}
	if email == nil {
		t.Error("an email quoted in a driver error was not found")
	}
}
