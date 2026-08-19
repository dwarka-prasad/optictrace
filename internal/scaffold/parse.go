// Package scaffold turns an OpenAPI or Swagger document into a starting
// optic.yaml.
//
// It exists for the bootstrap problem. Today you write governance by hand
// against an API you may not have written, and you find out what you missed
// only once traffic flows and `scan` reports it. A spec already lists the
// routes and the shape of every payload, so most of that first draft can be
// derived rather than guessed.
//
// # What a generated config is, and is not
//
// It is a STARTING POINT, and the generated file says so in its own header.
// A spec describes what an API claims; traffic shows what it does. The two
// disagree in ways that matter here:
//
//   - Undocumented fields are invisible. A payload with `additionalProperties`
//     or an unmodelled extra key has no entry to match on, and a rule cannot
//     mask a field the document never mentions.
//   - Specs drift. A field added last month may not be in the document.
//   - Names lie. A field called `ref` can hold a card number, which is exactly
//     what `optictrace scan` catches and a name heuristic cannot.
//
// So the output tells the operator to run against real traffic afterwards, and
// reports what it could not determine rather than quietly producing a
// confident-looking file.
package scaffold

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is the subset of OpenAPI/Swagger this needs, normalised across
// versions. Both are parsed into one shape so the generator has a single case
// to handle rather than a fork at every step.
type Document struct {
	Title   string
	Version string
	// Paths in document order, normalised.
	Paths []Path
	// SecurityHeaders are header and query credential names declared by the
	// document's security schemes — the most reliable signal in a spec,
	// because they are stated rather than inferred from a name.
	SecurityHeaders []string
	SecurityQueries []string
	// Swagger reports whether this was a 2.0 document, for the report.
	Swagger bool
}

// Path is one route with its methods and payload fields.
type Path struct {
	// Raw is the template as written, e.g. /users/{id}.
	Raw string
	// Glob is Raw with path parameters replaced by `*`, which is what an
	// optic.yaml rule matches on.
	Glob    string
	Methods []string
	// RequestFields and ResponseFields are dotted JSON paths into the payload
	// schemas, e.g. `customer.email`.
	RequestFields  []string
	ResponseFields []string
	// HeaderParams are header parameters declared for this path.
	HeaderParams []string
	// QueryParams likewise.
	QueryParams []string
}

// maxDepth bounds schema recursion. A self-referencing schema — a Node with
// children of type Node — would otherwise walk forever, and specs like that are
// common enough that a scaffolding tool must not be the thing that hangs.
const maxDepth = 6

// Parse reads an OpenAPI 3.x or Swagger 2.0 document, in YAML or JSON.
//
// JSON is a subset of YAML for these purposes, so one parser handles both and
// the caller does not have to know which they were handed.
func Parse(raw []byte) (*Document, error) {
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("not a readable OpenAPI or Swagger document: %w", err)
	}
	if len(root) == 0 {
		return nil, fmt.Errorf("document is empty")
	}

	doc := &Document{}
	switch {
	case root["openapi"] != nil:
		doc.Version = fmt.Sprint(root["openapi"])
	case root["swagger"] != nil:
		doc.Version = fmt.Sprint(root["swagger"])
		doc.Swagger = true
	default:
		return nil, fmt.Errorf("document has neither an `openapi` nor a `swagger` version key — " +
			"is this an API specification?")
	}

	if info := asMap(root["info"]); info != nil {
		doc.Title = str(info["title"])
	}

	p := &parser{root: root, swagger: doc.Swagger}
	doc.SecurityHeaders, doc.SecurityQueries = p.securityCredentials()

	paths := asMap(root["paths"])
	if len(paths) == 0 {
		return nil, fmt.Errorf("document declares no paths — nothing to generate rules for")
	}
	// Sorted, so the generated file is stable across runs: a config that
	// reorders itself produces a diff every time it is regenerated, and a noisy
	// diff is one nobody reads.
	for _, route := range sortedKeys(paths) {
		item := asMap(paths[route])
		if item == nil {
			continue
		}
		path := Path{Raw: route, Glob: toGlob(route)}
		for _, method := range []string{"get", "put", "post", "delete", "patch", "head", "options"} {
			op := asMap(item[method])
			if op == nil {
				continue
			}
			path.Methods = append(path.Methods, strings.ToUpper(method))
			p.collectOperation(op, item, &path)
		}
		if len(path.Methods) == 0 {
			continue
		}
		path.RequestFields = dedupe(path.RequestFields)
		path.ResponseFields = dedupe(path.ResponseFields)
		path.HeaderParams = dedupe(path.HeaderParams)
		path.QueryParams = dedupe(path.QueryParams)
		doc.Paths = append(doc.Paths, path)
	}
	if len(doc.Paths) == 0 {
		return nil, fmt.Errorf("document declares paths but none with operations")
	}
	return doc, nil
}

type parser struct {
	root    map[string]any
	swagger bool
	// seen guards against a $ref cycle within one resolution chain.
	seen map[string]bool
}

// securityCredentials reads declared security schemes.
//
// This is the highest-quality signal a spec offers: an apiKey scheme NAMES the
// header carrying the credential, so redacting it is a fact rather than a guess
// about what "x-token" might mean.
func (p *parser) securityCredentials() (headers, queries []string) {
	var schemes map[string]any
	if p.swagger {
		schemes = asMap(p.root["securityDefinitions"])
	} else {
		schemes = asMap(asMap(p.root["components"])["securitySchemes"])
	}
	for _, name := range sortedKeys(schemes) {
		s := asMap(schemes[name])
		switch strings.ToLower(str(s["type"])) {
		case "apikey":
			switch strings.ToLower(str(s["in"])) {
			case "header":
				headers = append(headers, str(s["name"]))
			case "query":
				queries = append(queries, str(s["name"]))
			}
		case "http", "oauth2", "basic":
			// All of these ride in Authorization.
			headers = append(headers, "Authorization")
		}
	}
	return dedupe(headers), dedupe(queries)
}

// collectOperation gathers payload fields and parameters for one operation.
func (p *parser) collectOperation(op, item map[string]any, out *Path) {
	// Parameters may be declared on the operation or shared on the path item.
	for _, src := range []any{op["parameters"], item["parameters"]} {
		for _, raw := range asSlice(src) {
			param := p.resolve(asMap(raw))
			name := str(param["name"])
			if name == "" {
				continue
			}
			switch strings.ToLower(str(param["in"])) {
			case "header":
				out.HeaderParams = append(out.HeaderParams, name)
			case "query":
				out.QueryParams = append(out.QueryParams, name)
			case "body":
				// Swagger 2.0 puts the request body here.
				out.RequestFields = append(out.RequestFields,
					p.fields(asMap(param["schema"]), "", 0)...)
			}
		}
	}

	if p.swagger {
		// Swagger 2.0 responses carry the schema directly.
		for _, resp := range asMap(op["responses"]) {
			r := asMap(resp)
			out.ResponseFields = append(out.ResponseFields, p.fields(asMap(r["schema"]), "", 0)...)
		}
		return
	}

	// OpenAPI 3.x: requestBody.content.<media>.schema
	if body := asMap(op["requestBody"]); body != nil {
		for _, media := range asMap(body["content"]) {
			m := asMap(media)
			out.RequestFields = append(out.RequestFields, p.fields(asMap(m["schema"]), "", 0)...)
		}
	}
	for _, resp := range asMap(op["responses"]) {
		r := asMap(resp)
		for _, media := range asMap(r["content"]) {
			m := asMap(media)
			out.ResponseFields = append(out.ResponseFields, p.fields(asMap(m["schema"]), "", 0)...)
		}
	}
}

// fields walks a schema and returns dotted paths to every leaf property.
//
// Arrays are traversed WITHOUT adding an index to the path, because optic.yaml's
// redaction grammar traverses lists implicitly: `$.items.card` masks the field
// in every element.
func (p *parser) fields(schema map[string]any, prefix string, depth int) []string {
	if schema == nil || depth > maxDepth {
		return nil
	}
	schema = p.resolve(schema)
	if schema == nil {
		return nil
	}

	// Composition keywords: a field is reachable through any branch, so all are
	// walked. Missing one would leave a documented field unmasked.
	var out []string
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		for _, sub := range asSlice(schema[key]) {
			out = append(out, p.fields(asMap(sub), prefix, depth+1)...)
		}
	}
	if items := asMap(schema["items"]); items != nil {
		out = append(out, p.fields(items, prefix, depth+1)...)
	}

	props := asMap(schema["properties"])
	for _, name := range sortedKeys(props) {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		child := p.resolve(asMap(props[name]))
		if child == nil {
			out = append(out, path)
			continue
		}
		nested := p.fields(child, path, depth+1)
		// A leaf contributes itself; a branch contributes its leaves. Emitting
		// both would produce a rule masking a whole object when only one field
		// inside it is sensitive.
		if len(nested) == 0 {
			out = append(out, path)
		} else {
			out = append(out, nested...)
		}
	}
	return out
}

// resolve follows a local $ref one or more hops.
func (p *parser) resolve(schema map[string]any) map[string]any {
	if p.seen == nil {
		p.seen = map[string]bool{}
	}
	for hops := 0; schema != nil && hops < 10; hops++ {
		ref := str(schema["$ref"])
		if ref == "" {
			return schema
		}
		if p.seen[ref] {
			// A cycle. Returning nil ends this branch rather than looping.
			return nil
		}
		p.seen[ref] = true
		target := p.lookup(ref)
		delete(p.seen, ref)
		if target == nil {
			return nil
		}
		schema = target
	}
	return schema
}

// lookup walks a local JSON pointer, e.g. #/components/schemas/Order.
//
// Remote refs are deliberately NOT fetched: a scaffolding tool that reaches out
// to the network to read a URL in a file it was handed is a tool that can be
// pointed at anything.
func (p *parser) lookup(ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	node := any(p.root)
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		m := asMap(node)
		if m == nil {
			return nil
		}
		node = m[seg]
	}
	return asMap(node)
}

// toGlob turns /users/{id}/orders into /users/*/orders.
func toGlob(route string) string {
	segments := strings.Split(route, "/")
	for i, s := range segments {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segments[i] = "*"
		}
	}
	return strings.Join(segments, "/")
}

// --- small helpers over the untyped document -------------------------------

func asMap(v any) map[string]any {
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[any]any:
		// yaml.v3 produces map[string]any, but a JSON document round-tripped
		// through some tools can still arrive this way.
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = val
		}
		return out
	}
	return nil
}

func asSlice(v any) []any {
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
