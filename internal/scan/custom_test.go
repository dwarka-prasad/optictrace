package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

func TestVerhoeffKnownVectors(t *testing.T) {
	// Published Verhoeff test vectors.
	valid := []string{"2363", "758722", "1428570", "123451"}
	invalid := []string{"2364", "758723", "1428571", "123456"}
	for _, v := range valid {
		if !verhoeffValid(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	for _, v := range invalid {
		if verhoeffValid(v) {
			t.Errorf("%s should be invalid", v)
		}
	}
}

func TestNewDetectorRejects(t *testing.T) {
	ok := `\bAC-\d{6}\b`
	for _, tc := range []struct{ name, kind, sev, pattern, verify, want string }{
		{"no kind", "", SevHigh, ok, "", "kind is required"},
		{"kind with a space", "my kind", SevHigh, ok, "", "must not contain whitespace"},
		{"no severity", "k", "", ok, "", "severity is required"},
		{"bad severity", "k", "urgent", ok, "", "must be critical"},
		{"no pattern", "k", SevHigh, "", "", "pattern is required"},
		{"uncompilable pattern", "k", SevHigh, `(unclosed`, "", "pattern:"},
		// The important one: a pattern matching "" matches every value, so
		// every field in every payload would be reported as a finding.
		{"matches the empty string", "k", SevHigh, `\d*`, "", "matches the empty string"},
		{"unknown verifier", "k", SevHigh, ok, "sha256", "not a known checksum"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDetector(tc.kind, tc.sev, "why", tc.pattern, tc.verify)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestNewDetectorRejectsOversizedPattern(t *testing.T) {
	if _, err := NewDetector("k", SevHigh, "w", "a"+strings.Repeat("b?", MaxPatternLength), ""); err == nil {
		t.Error("an oversized pattern should be rejected — scan runs over every body")
	}
}

// A custom detector with a checksum must behave like a built-in: precise
// enough that ordinary data does not trip it.
func TestCustomDetectorWithVerhoeff(t *testing.T) {
	d, err := NewDetector("aadhaar", SevHigh, "an Aadhaar number",
		`\b\d{4}\s?\d{4}\s?\d{4}\b`, "verhoeff")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	dets := append(append([]Detector{}, Detectors...), d)

	// A Verhoeff-valid 12-digit number.
	valid := "999941057058"
	if !verhoeffValid(valid) {
		t.Fatalf("test vector %s is not Verhoeff-valid", valid)
	}
	if got := FindWith(dets, valid); len(got) == 0 {
		t.Error("a checksum-valid Aadhaar number should be detected")
	} else if got[0].Masked == valid {
		t.Error("findings must never carry the raw value")
	}

	// The precision claim: a 12-digit number that fails the checksum is not
	// reported. Without `verify` this pattern would match any 12 digits.
	if got := FindWith(dets, "999941057059"); len(got) != 0 {
		t.Errorf("checksum should reject this: %+v", got)
	}
}

// Custom detectors add to the built-ins rather than replacing them.
func TestCustomDetectorsAugmentBuiltins(t *testing.T) {
	d, _ := NewDetector("emp-id", SevMedium, "internal employee id", `\bEMP-\d{5}\b`, "")
	sc := NewScannerWith(time.Time{}, []Detector{d})
	sc.Add(&store.Record{
		Method: "POST", Route: "/x",
		RequestBody: `{"who":"EMP-12345","key":"AKIAIOSFODNN7EXAMPLE"}`,
	})
	kinds := map[string]bool{}
	for _, f := range sc.Report().Findings {
		kinds[f.Kind] = true
	}
	if !kinds["emp-id"] {
		t.Error("the custom detector did not fire")
	}
	if !kinds["aws-access-key-id"] {
		t.Error("built-in detectors must still run alongside custom ones")
	}
}

func TestMaskNeverLeaksTheValue(t *testing.T) {
	for _, v := range []string{"AKIAIOSFODNN7EXAMPLE", "4111111111111111", "short", ""} {
		if m := Mask(v); len(v) > 8 && strings.Contains(m, v) {
			t.Errorf("Mask(%q) = %q leaks the value", v, m)
		}
	}
}
