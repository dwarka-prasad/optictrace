// Redaction utilities. IMPORTANT ARCHITECTURAL NOTE: redaction applies only
// to the telemetry OpticTrace records — the proxied request/response bytes
// are forwarded untouched. Governance is about what we *store*, not about
// mutating live traffic.
package engine

import (
	"encoding/json"
	"net/http"
)

const RedactedPlaceholder = "[REDACTED]"

// SanitizeHeaders returns a flattened, telemetry-safe copy of h with any
// policy-listed header values masked. Multi-value headers are joined.
func (p *Policy) SanitizeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, vals := range h {
		if _, redact := p.RedactHeaders[name]; redact {
			out[name] = RedactedPlaceholder
			continue
		}
		switch len(vals) {
		case 0:
			out[name] = ""
		case 1:
			out[name] = vals[0]
		default:
			joined := vals[0]
			for _, v := range vals[1:] {
				joined += ", " + v
			}
			out[name] = joined
		}
	}
	return out
}

// RedactJSONBody parses body as JSON, masks every field addressed by the
// policy's JSON paths, and re-serializes. Non-JSON input is returned as-is
// with ok=false so callers can decide how to represent it.
func (p *Policy) RedactJSONBody(body []byte) (redacted []byte, ok bool) {
	if len(body) == 0 || len(p.RedactJSONPaths) == 0 {
		if json.Valid(body) {
			return body, true
		}
		return body, false
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, false
	}
	for _, path := range p.RedactJSONPaths {
		doc = redactPath(doc, path)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body, false
	}
	return out, true
}

// ExtractMeters pulls numeric usage values out of a JSON response body per
// the policy's meter paths. Every numeric match on a path is summed (arrays
// traverse implicitly), so "$.usage.total_tokens" works for single objects
// and "$.items.tokens" sums across list responses.
func (p *Policy) ExtractMeters(body []byte) map[string]float64 {
	if len(p.Meters) == 0 || len(body) == 0 {
		return nil
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	out := make(map[string]float64, len(p.Meters))
	for name, paths := range p.Meters {
		var sum float64
		var found bool
		for _, path := range paths {
			sumNumeric(doc, path, &sum, &found)
		}
		if found {
			out[name] = sum
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sumNumeric(node any, path []string, sum *float64, found *bool) {
	if len(path) == 0 {
		if n, ok := node.(float64); ok {
			*sum += n
			*found = true
		}
		return
	}
	switch v := node.(type) {
	case map[string]any:
		seg, rest := path[0], path[1:]
		if seg == "**" {
			if len(rest) > 0 {
				sumNumeric(v, rest, sum, found)
			}
			for _, child := range v {
				sumNumeric(child, path, sum, found)
			}
			return
		}
		if seg == "*" {
			for _, child := range v {
				sumNumeric(child, rest, sum, found)
			}
			return
		}
		if child, ok := v[seg]; ok {
			sumNumeric(child, rest, sum, found)
		}
	case []any:
		for _, child := range v {
			sumNumeric(child, path, sum, found)
		}
	}
}

// redactPath walks one pre-split dotted path (["credit_card","number"]) and
// replaces the addressed value with RedactedPlaceholder.
//
// Semantics:
//   - "*" in a segment matches any object key.
//   - "**" matches zero or more levels of nesting (recursive descent), so
//     "$.**.credit_card.number" redacts the field wherever it appears.
//   - Arrays are traversed implicitly: the same remaining path is applied to
//     every element, so "$.items.price" also covers {"items": [{...}, {...}]}.
func redactPath(node any, path []string) any {
	if len(path) == 0 {
		return node
	}
	switch v := node.(type) {
	case map[string]any:
		seg, rest := path[0], path[1:]
		if seg == "**" {
			if len(rest) > 0 {
				redactPath(v, rest) // the remainder may match at this level...
			}
			for key, child := range v {
				v[key] = redactPath(child, path) // ...and at any deeper level
			}
			return v
		}
		if seg == "*" {
			for key, child := range v {
				if len(rest) == 0 {
					v[key] = RedactedPlaceholder
				} else {
					v[key] = redactPath(child, rest)
				}
			}
			return v
		}
		if child, exists := v[seg]; exists {
			if len(rest) == 0 {
				v[seg] = RedactedPlaceholder
			} else {
				v[seg] = redactPath(child, rest)
			}
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = redactPath(child, path)
		}
		return v
	default:
		return node
	}
}
