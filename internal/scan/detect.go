// Package scan is OpticTrace's safety net.
//
// The rest of the system masks what you NAME: a redaction rule covers
// $.credit_card.number because you wrote it down. The failure that actually
// bites in production is the field you FORGOT — a new endpoint ships, nobody
// adds a rule, and secrets land in the payload store.
//
// scan inverts the model. It reads records that already passed governance
// and looks for values that LOOK sensitive regardless of what the rules say,
// then tells you which redaction rule would have caught them.
//
// Design constraints, in priority order:
//
//  1. Never print a secret. Findings carry a masked sample only — a scanner
//     that echoes the credential it found has just leaked it again, into
//     your CI logs this time.
//  2. Prefer precision over recall. A detector that cries wolf gets muted,
//     and a muted detector protects nothing. Patterns here are structural
//     (issuer prefixes, checksums, framing) rather than "looks random".
package scan

import (
	"regexp"
	"strings"
)

// Severity ranks how urgently a finding should be acted on.
const (
	SevCritical = "critical" // a credential: exploitable as-is if leaked
	SevHigh     = "high"     // regulated personal data (PCI, national IDs)
	SevMedium   = "medium"   // personal data, lower blast radius
)

// Detector recognizes one class of sensitive value.
type Detector struct {
	Kind     string
	Severity string
	Why      string // what a reader should understand about the risk
	re       *regexp.Regexp
	// verify optionally confirms a regex hit, keeping precision high.
	verify func(string) bool
}

// Detectors is the built-in set, ordered most to least severe. Every pattern
// is anchored on structure a real credential has — an issuer prefix, a
// checksum, a framing line — so ordinary prose does not trip them.
var Detectors = []Detector{
	{
		Kind: "private-key", Severity: SevCritical,
		Why: "a PEM private key block was stored verbatim",
		re:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----`),
	},
	{
		Kind: "aws-access-key-id", Severity: SevCritical,
		Why: "an AWS access key ID, usually paired with a secret nearby",
		re:  regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
	},
	{
		Kind: "github-token", Severity: SevCritical,
		Why: "a GitHub personal access / app token",
		re:  regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
	},
	{
		Kind: "slack-token", Severity: SevCritical,
		Why: "a Slack API token",
		re:  regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
	},
	{
		Kind: "stripe-secret-key", Severity: SevCritical,
		Why: "a live Stripe secret key",
		re:  regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{16,}\b`),
	},
	{
		Kind: "google-api-key", Severity: SevCritical,
		Why: "a Google API key",
		re:  regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	},
	{
		Kind: "jwt", Severity: SevCritical,
		Why: "a JSON Web Token — bearer credentials are replayable until they expire",
		re:  regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`),
	},
	{
		Kind: "credit-card", Severity: SevHigh,
		Why:    "a Luhn-valid card number — PCI-DSS scope",
		re:     regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
		verify: luhnValid,
	},
	{
		Kind: "iban", Severity: SevHigh,
		Why:    "an IBAN bank account number",
		re:     regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`),
		verify: ibanPlausible,
	},
	{
		Kind: "us-ssn", Severity: SevHigh,
		Why:    "a US Social Security Number",
		re:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		verify: ssnPlausible,
	},
	{
		Kind: "email", Severity: SevMedium,
		Why: "an email address — personal data under GDPR and similar regimes",
		re:  regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
	},
}

// Match is one detector hit inside a single value.
type Match struct {
	Kind     string
	Severity string
	Why      string
	Masked   string // safe to print: never the raw value
}

// Find runs every detector over a string. A value already replaced by the
// redaction placeholder is skipped — that one worked as intended.
func Find(s string) []Match {
	if s == "" || strings.Contains(s, "[REDACTED]") && len(s) < 24 {
		return nil
	}
	var out []Match
	for i := range Detectors {
		d := &Detectors[i]
		for _, hit := range d.re.FindAllString(s, 4) {
			if d.verify != nil && !d.verify(hit) {
				continue
			}
			out = append(out, Match{
				Kind: d.Kind, Severity: d.Severity, Why: d.Why, Masked: Mask(hit),
			})
			break // one hit per detector per value is enough to report
		}
	}
	return out
}

// Mask renders a value safe to display: first and last two characters with
// the middle replaced, and long values truncated. The point of a finding is
// "there is a card number in this field", never the number itself.
func Mask(v string) string {
	v = strings.TrimSpace(v)
	if len(v) <= 6 {
		return strings.Repeat("•", len(v))
	}
	if len(v) > 40 {
		v = v[:40]
	}
	return v[:2] + strings.Repeat("•", len(v)-4) + v[len(v)-2:]
}

// --- verifiers --------------------------------------------------------------

// luhnValid implements the Luhn checksum, which every real payment card
// satisfies. It turns a loose "12-19 digits" pattern into a precise one:
// random order IDs and timestamps almost never pass.
func luhnValid(s string) bool {
	digits := make([]int, 0, 19)
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	// Reject trivially uniform sequences (0000..., 1111...) — valid by
	// checksum in some cases but never a real issued card.
	same := true
	for _, d := range digits[1:] {
		if d != digits[0] {
			same = false
			break
		}
	}
	if same {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// ibanPlausible checks the ISO 7064 mod-97 checksum.
func ibanPlausible(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, r := range rearranged {
		var v int
		switch {
		case r >= '0' && r <= '9':
			v = int(r - '0')
			rem = (rem*10 + v) % 97
		case r >= 'A' && r <= 'Z':
			v = int(r-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// ssnPlausible rejects the ranges the US SSA never issues, which removes most
// look-alike IDs and obvious test data.
func ssnPlausible(s string) bool {
	area, group, serial := s[0:3], s[4:6], s[7:11]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}
