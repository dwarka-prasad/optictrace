// Package spec bridges static API contracts and runtime reality:
//
//   - Infer:  learn an OpenAPI 3 document from captured traffic (the store
//     already holds governed request/response payloads).
//   - Check:  lint a spec against live traffic — "is anyone actually using
//     the field you're about to remove?"
//   - tsgen:  emit a typed TypeScript client from a spec.
//
// The model is a deliberate OpenAPI 3.0 subset: paths, JSON media types,
// component schema refs. That covers inference output and everything Check
// needs; exotic spec features (oneOf, links, callbacks) pass through
// unparsed rather than erroring.
package spec

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Spec struct {
	OpenAPI    string                           `yaml:"openapi" json:"openapi"`
	Info       Info                             `yaml:"info" json:"info"`
	Paths      map[string]map[string]*Operation `yaml:"paths" json:"paths"`
	Components *Components                      `yaml:"components,omitempty" json:"components,omitempty"`
}

type Info struct {
	Title       string `yaml:"title" json:"title"`
	Version     string `yaml:"version" json:"version"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type Components struct {
	Schemas map[string]*Schema `yaml:"schemas,omitempty" json:"schemas,omitempty"`
}

type Operation struct {
	Summary     string               `yaml:"summary,omitempty" json:"summary,omitempty"`
	OperationID string               `yaml:"operationId,omitempty" json:"operationId,omitempty"`
	Parameters  []*Param             `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	RequestBody *RequestBody         `yaml:"requestBody,omitempty" json:"requestBody,omitempty"`
	Responses   map[string]*Response `yaml:"responses" json:"responses"`
}

type Param struct {
	Name     string  `yaml:"name" json:"name"`
	In       string  `yaml:"in" json:"in"` // path | query | header
	Required bool    `yaml:"required,omitempty" json:"required,omitempty"`
	Schema   *Schema `yaml:"schema,omitempty" json:"schema,omitempty"`
}

type RequestBody struct {
	Required bool              `yaml:"required,omitempty" json:"required,omitempty"`
	Content  map[string]*Media `yaml:"content" json:"content"`
}

type Response struct {
	Description string            `yaml:"description" json:"description"`
	Content     map[string]*Media `yaml:"content,omitempty" json:"content,omitempty"`
}

type Media struct {
	Schema *Schema `yaml:"schema,omitempty" json:"schema,omitempty"`
}

type Schema struct {
	Ref        string             `yaml:"$ref,omitempty" json:"$ref,omitempty"`
	Type       string             `yaml:"type,omitempty" json:"type,omitempty"`
	Format     string             `yaml:"format,omitempty" json:"format,omitempty"`
	Enum       []any              `yaml:"enum,omitempty" json:"enum,omitempty"`
	Properties map[string]*Schema `yaml:"properties,omitempty" json:"properties,omitempty"`
	Required   []string           `yaml:"required,omitempty" json:"required,omitempty"`
	Items      *Schema            `yaml:"items,omitempty" json:"items,omitempty"`
	Nullable   bool               `yaml:"nullable,omitempty" json:"nullable,omitempty"`
	Example    any                `yaml:"example,omitempty" json:"example,omitempty"`
}

// Parse reads an OpenAPI document (YAML or JSON — YAML is a superset).
func Parse(raw []byte) (*Spec, error) {
	var s Spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	if len(s.Paths) == 0 {
		return nil, fmt.Errorf("spec has no paths")
	}
	return &s, nil
}

// Resolve follows a local $ref chain to the concrete schema (nil-safe).
func (s *Spec) Resolve(sc *Schema) *Schema {
	for depth := 0; sc != nil && sc.Ref != "" && depth < 10; depth++ {
		name, ok := strings.CutPrefix(sc.Ref, "#/components/schemas/")
		if !ok || s.Components == nil {
			return sc
		}
		next, ok := s.Components.Schemas[name]
		if !ok {
			return sc
		}
		sc = next
	}
	return sc
}

// JSONSchema returns the application/json schema of a request body or
// response, resolved; nil when absent.
func (s *Spec) requestSchema(op *Operation) *Schema {
	if op.RequestBody == nil {
		return nil
	}
	if m := op.RequestBody.Content["application/json"]; m != nil {
		return s.Resolve(m.Schema)
	}
	return nil
}

func (s *Spec) responseSchema(op *Operation, status string) *Schema {
	r := op.Responses[status]
	if r == nil {
		// fall back to the first 2xx entry, then "default"
		for code, cand := range op.Responses {
			if strings.HasPrefix(code, "2") {
				r = cand
				break
			}
		}
		if r == nil {
			r = op.Responses["default"]
		}
	}
	if r == nil {
		return nil
	}
	if m := r.Content["application/json"]; m != nil {
		return s.Resolve(m.Schema)
	}
	return nil
}

// FieldPaths flattens a schema into dotted field paths ("a.b", arrays are
// traversed transparently) — the unit of comparison for Check.
func (s *Spec) FieldPaths(sc *Schema) map[string]bool {
	out := map[string]bool{}
	s.walkFields(sc, "", out, 0)
	return out
}

func (s *Spec) walkFields(sc *Schema, prefix string, out map[string]bool, depth int) {
	sc = s.Resolve(sc)
	if sc == nil || depth > 12 {
		return
	}
	switch {
	case len(sc.Properties) > 0:
		for name, child := range sc.Properties {
			p := name
			if prefix != "" {
				p = prefix + "." + name
			}
			out[p] = true
			s.walkFields(child, p, out, depth+1)
		}
	case sc.Items != nil:
		s.walkFields(sc.Items, prefix, out, depth+1)
	}
}

// MatchPath finds the spec path template matching a concrete/normalized
// path ("{param}" segments match anything, including ":id" placeholders).
func (s *Spec) MatchPath(path string) (string, bool) {
	if _, ok := s.Paths[path]; ok {
		return path, true
	}
	segs := splitSegs(path)
	for tmpl := range s.Paths {
		if templateMatches(splitSegs(tmpl), segs) {
			return tmpl, true
		}
	}
	return "", false
}

func splitSegs(p string) []string {
	t := strings.Trim(p, "/")
	if t == "" {
		return nil
	}
	return strings.Split(t, "/")
}

func templateMatches(tmpl, segs []string) bool {
	if len(tmpl) != len(segs) {
		return false
	}
	for i, t := range tmpl {
		isTmplParam := strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")
		isSegParam := strings.HasPrefix(segs[i], ":") || (strings.HasPrefix(segs[i], "{") && strings.HasSuffix(segs[i], "}"))
		if isTmplParam || isSegParam {
			continue
		}
		if t != segs[i] {
			return false
		}
	}
	return true
}

// YAML serializes the spec document.
func (s *Spec) YAML() ([]byte, error) { return yaml.Marshal(s) }
