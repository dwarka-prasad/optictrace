package spec

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Severity of a Check finding.
const (
	SevBreaking = "breaking" // spec change would break clients observed live
	SevWarn     = "warn"     // spec and reality disagree; probably stale docs
	SevInfo     = "info"     // hygiene signal, no action forced
)

// Finding is one divergence between the spec and observed traffic.
type Finding struct {
	Severity string    `json:"severity"`
	Kind     string    `json:"kind"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	Field    string    `json:"field,omitempty"`
	Count    int64     `json:"count,omitempty"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	Message  string    `json:"message"`
}

// Check lints a spec against captured traffic. This is the question static
// linters can't answer: not "is the schema valid?" but "does the schema
// match what clients are DOING right now?"
//
//   - breaking: an endpoint or request field carried live traffic but is
//     absent from the spec — shipping this spec breaks a real consumer.
//   - warn:     responses return fields the spec doesn't document.
//   - info:     spec surface with zero observed traffic (removal candidates,
//     or simply not exercised in this window).
func Check(s *Spec, records []store.Record) []Finding {
	type usage struct {
		count      int64
		lastSeen   time.Time
		reqFields  map[string]*fieldUse
		respFields map[string]*fieldUse
	}
	observed := map[string]*usage{} // METHOD + " " + template-path

	for i := range records {
		rec := &records[i]
		key := rec.Method + " " + openAPIPath(rec.Path)
		u := observed[key]
		if u == nil {
			u = &usage{reqFields: map[string]*fieldUse{}, respFields: map[string]*fieldUse{}}
			observed[key] = u
		}
		u.count++
		if rec.Time.After(u.lastSeen) {
			u.lastSeen = rec.Time
		}
		collectFieldUse(rec.RequestBody, u.reqFields, rec.Time)
		if rec.Status >= 200 && rec.Status < 300 {
			collectFieldUse(rec.ResponseBody, u.respFields, rec.Time)
		}
	}

	var findings []Finding

	// 1) Traffic -> spec: everything clients do must exist in the spec.
	keys := make([]string, 0, len(observed))
	for k := range observed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		u := observed[key]
		method, path, _ := strings.Cut(key, " ")
		tmpl, ok := s.MatchPath(path)
		var op *Operation
		if ok {
			op = s.Paths[tmpl][strings.ToLower(method)]
		}
		if op == nil {
			findings = append(findings, Finding{
				Severity: SevBreaking, Kind: "endpoint-missing-from-spec",
				Method: method, Path: path, Count: u.count, LastSeen: u.lastSeen,
				Message: fmt.Sprintf("%s %s carried %d request(s) (last %s ago) but is not in the spec — removing it breaks live consumers",
					method, path, u.count, ago(u.lastSeen)),
			})
			continue
		}

		specReq := s.FieldPaths(s.requestSchema(op))
		findings = append(findings, fieldFindings(u.reqFields, specReq, SevBreaking,
			"request-field-missing-from-spec", method, tmpl,
			"clients send request field %q (%d time(s), last %s ago) but the spec omits it")...)

		specResp := map[string]bool{}
		for status := range op.Responses {
			if strings.HasPrefix(status, "2") || status == "default" {
				for f := range s.FieldPaths(s.responseSchema(op, status)) {
					specResp[f] = true
				}
			}
		}
		if len(specResp) > 0 {
			findings = append(findings, fieldFindings(u.respFields, specResp, SevWarn,
				"response-field-undocumented", method, tmpl,
				"responses include field %q (%d time(s), last %s ago) that the spec doesn't document")...)
		}
	}

	// 2) Spec -> traffic: surface with no observed usage.
	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, tmpl := range paths {
		for method := range s.Paths[tmpl] {
			upper := strings.ToUpper(method)
			seen := false
			for key := range observed {
				m, p, _ := strings.Cut(key, " ")
				if m == upper && templateMatches(splitSegs(tmpl), splitSegs(p)) {
					seen = true
					break
				}
			}
			if !seen {
				findings = append(findings, Finding{
					Severity: SevInfo, Kind: "endpoint-unused",
					Method: upper, Path: tmpl,
					Message: fmt.Sprintf("%s %s has no observed traffic in this window", upper, tmpl),
				})
			}
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return sevRank(findings[i].Severity) < sevRank(findings[j].Severity)
	})
	return findings
}

// HasBreaking reports whether any finding is breaking (CI exit-code driver).
func HasBreaking(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SevBreaking {
			return true
		}
	}
	return false
}

type fieldUse struct {
	count    int64
	lastSeen time.Time
}

func collectFieldUse(body string, into map[string]*fieldUse, at time.Time) {
	if body == "" || (body[0] != '{' && body[0] != '[') {
		return
	}
	var v any
	if json.Unmarshal([]byte(body), &v) != nil {
		return
	}
	walkJSONFields(v, "", into, at, 0)
}

func walkJSONFields(v any, prefix string, into map[string]*fieldUse, at time.Time, depth int) {
	if depth > 12 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			u := into[p]
			if u == nil {
				u = &fieldUse{}
				into[p] = u
			}
			u.count++
			if at.After(u.lastSeen) {
				u.lastSeen = at
			}
			walkJSONFields(child, p, into, at, depth+1)
		}
	case []any:
		for _, item := range t {
			walkJSONFields(item, prefix, into, at, depth+1)
		}
	}
}

func fieldFindings(used map[string]*fieldUse, specFields map[string]bool,
	severity, kind, method, path, msgFmt string) []Finding {
	var out []Finding
	fields := make([]string, 0, len(used))
	for f := range used {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	for _, f := range fields {
		if specFields[f] {
			continue
		}
		// Skip children of already-missing parents — report the root cause.
		if parent, _, ok := lastCut(f); ok && !specFields[parent] {
			if _, parentUsed := used[parent]; parentUsed {
				continue
			}
		}
		u := used[f]
		out = append(out, Finding{
			Severity: severity, Kind: kind, Method: method, Path: path,
			Field: f, Count: u.count, LastSeen: u.lastSeen,
			Message: fmt.Sprintf("%s %s: ", method, path) + fmt.Sprintf(msgFmt, f, u.count, ago(u.lastSeen)),
		})
	}
	return out
}

func lastCut(s string) (before, after string, found bool) {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

func sevRank(s string) int {
	switch s {
	case SevBreaking:
		return 0
	case SevWarn:
		return 1
	default:
		return 2
	}
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}
