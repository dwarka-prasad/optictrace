package proxy

import (
	"encoding/json"
	"strings"
	"unicode"
)

// maxGraphQLBodyPeek bounds how much of a request body is parsed looking for
// an operation name. Real GraphQL documents can be large; the operation name
// is near the front, and this runs on the hot path.
const maxGraphQLBodyPeek = 64 * 1024

// graphQLOperation extracts the operation name from a GraphQL request body.
//
// GraphQL POSTs everything to one path, so without this every operation
// collapses into a single route: latency percentiles average a 2ms viewer
// query with a 4s report, rules cannot target one mutation, and inferred
// specs produce one endpoint whose schema is the union of everything.
//
// Returns "" when the body is not a recognisable GraphQL request, when the
// operation cannot be named, or for a batched request — guessing there would
// attribute a batch to whichever operation happened to be first.
func graphQLOperation(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > maxGraphQLBodyPeek {
		body = body[:maxGraphQLBodyPeek]
	}
	if t := strings.TrimLeft(string(body[:min(8, len(body))]), " \t\r\n"); strings.HasPrefix(t, "[") {
		return "batch" // an array of operations; not attributable to one name
	}

	var req struct {
		OperationName string `json:"operationName"`
		Query         string `json:"query"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	// The cheap path: clients that name their operation, which most do.
	if n := sanitizeOperationName(req.OperationName); n != "" {
		return n
	}
	if req.Query == "" {
		return ""
	}
	return sanitizeOperationName(parseOperationName(req.Query))
}

// parseOperationName reads the name out of a GraphQL document's first
// executable definition: `query Foo {`, `mutation Foo(` or `subscription Foo`.
// An anonymous operation (`{ ... }` or `query {`) has no name to report.
func parseOperationName(doc string) string {
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, kw := range []string{"query", "mutation", "subscription"} {
			rest, ok := strings.CutPrefix(line, kw)
			if !ok || rest == "" {
				continue
			}
			// The keyword must be a whole word.
			if r := rune(rest[0]); !unicode.IsSpace(r) {
				continue
			}
			rest = strings.TrimSpace(rest)
			end := strings.IndexFunc(rest, func(r rune) bool {
				return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_')
			})
			if end < 0 {
				end = len(rest)
			}
			return rest[:end]
		}
		// Only the first executable definition matters; anything else means
		// this is an anonymous operation or a fragment-first document.
		return ""
	}
	return ""
}

// maxOperationNameLen bounds the label an operation name can contribute.
const maxOperationNameLen = 64

// sanitizeOperationName keeps only names that are safe as a metric label.
// Operation names are client-supplied, so this refuses anything that is not a
// plain GraphQL identifier rather than trusting the input.
func sanitizeOperationName(name string) string {
	if name == "" || len(name) > maxOperationNameLen {
		return ""
	}
	for i, r := range name {
		switch {
		case unicode.IsLetter(r) || r == '_':
		case unicode.IsDigit(r) && i > 0:
		default:
			return ""
		}
	}
	return name
}
