package scan

import (
	"fmt"
	"regexp"
	"strings"
)

// Verifiers are the named checksum routines a user-defined detector can borrow
// with `verify:`.
//
// This registry exists because of the design rule the built-in set follows:
// every pattern is anchored on structure a real credential has — an issuer
// prefix, a checksum, a framing line — so ordinary prose does not trip it. A
// user-supplied regex cannot be trusted to hold that line on its own, and a
// scanner that cries wolf gets switched off. Exposing the checksums by name
// lets an org-specific detector be as precise as the built-ins.
var Verifiers = map[string]func(string) bool{
	"luhn":     luhnValid,     // payment cards
	"iban":     ibanPlausible, // mod-97 bank accounts
	"us_ssn":   ssnPlausible,
	"verhoeff": verhoeffValid, // Aadhaar and other national IDs
}

// KnownVerifier reports whether name is a registered verifier, so a bad name
// fails `optictrace validate` rather than at scan time in production.
func KnownVerifier(name string) bool {
	_, ok := Verifiers[name]
	return ok
}

// VerifierNames lists the registered verifiers, sorted, for error messages.
func VerifierNames() []string {
	out := make([]string, 0, len(Verifiers))
	for k := range Verifiers {
		out = append(out, k)
	}
	// Small fixed set; a simple insertion sort keeps this dependency-free.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// MaxPatternLength bounds a user-supplied pattern. scan runs over every
// recorded body, so a pathological regex is an availability problem rather
// than merely a noisy one.
const MaxPatternLength = 512

// NewDetector builds a user-defined detector, validating everything that can
// be validated ahead of time. verify may be empty for no checksum.
func NewDetector(kind, severity, why, pattern, verify string) (Detector, error) {
	var d Detector
	switch {
	case kind == "":
		return d, fmt.Errorf("kind is required")
	case strings.ContainsAny(kind, " \t"):
		return d, fmt.Errorf("kind %q must not contain whitespace", kind)
	}
	switch severity {
	case SevCritical, SevHigh, SevMedium:
	case "":
		return d, fmt.Errorf("severity is required (%s, %s or %s)", SevCritical, SevHigh, SevMedium)
	default:
		return d, fmt.Errorf("severity %q must be %s, %s or %s",
			severity, SevCritical, SevHigh, SevMedium)
	}
	if pattern == "" {
		return d, fmt.Errorf("pattern is required")
	}
	if len(pattern) > MaxPatternLength {
		return d, fmt.Errorf("pattern is %d bytes, over the %d limit", len(pattern), MaxPatternLength)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return d, fmt.Errorf("pattern: %w", err)
	}
	// A pattern that matches the empty string matches everywhere, which would
	// report every value in every payload as a finding.
	if re.MatchString("") {
		return d, fmt.Errorf("pattern matches the empty string, so it would match every value")
	}
	if why == "" {
		why = "matched the user-defined detector " + kind
	}
	d = Detector{Kind: kind, Severity: severity, Why: why, re: re}
	if verify != "" {
		fn, ok := Verifiers[verify]
		if !ok {
			return d, fmt.Errorf("verify %q is not a known checksum (%s)",
				verify, strings.Join(VerifierNames(), ", "))
		}
		d.verify = fn
	}
	return d, nil
}

// verhoeffValid implements the Verhoeff checksum, which India's Aadhaar and
// several other national identifiers use. Included because a bare 12-digit
// regex would match timestamps, order numbers and phone numbers — exactly the
// false-positive problem the built-in detectors are designed to avoid.
func verhoeffValid(s string) bool {
	digits := make([]int, 0, 16)
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits = append(digits, int(r-'0'))
		case r == ' ' || r == '-':
			// separators are common in printed form
		default:
			return false
		}
	}
	if len(digits) < 2 {
		return false
	}
	c := 0
	// Process right to left, position 0 being the check digit itself.
	for i, n := 0, len(digits); i < n; i++ {
		c = verhoeffD[c][verhoeffP[i%8][digits[n-i-1]]]
	}
	return c == 0
}

// The dihedral group D5 multiplication table.
var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// The permutation table.
var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}
