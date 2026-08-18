// Package memstore is a reference ext.Store implementation: an in-memory
// payload store, in its own Go module.
//
// It exists to prove and to demonstrate. To prove, because this module can
// import nothing but github.com/dwarka-prasad/optictrace/ext — it has no access
// to internal/, exactly like any third-party or commercial extension. If the
// extension surface were incomplete, this would not compile. To demonstrate,
// because it is the shortest complete answer to "how do I write a driver",
// and it passes the same conformance suite the built-in drivers run.
//
// It is not meant for production: everything lives in a slice, so memory grows
// until retention prunes it and the data is gone on restart. Useful for tests,
// demos, and as a starting template.
package memstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

func init() {
	// Registering here means `telemetry.store.driver: memory` becomes valid
	// the moment this package is linked in — no core changes, no config
	// schema changes.
	ext.RegisterStore("memory", func(_ string, s ext.Settings) (ext.Store, error) {
		return New(s.Int("max_records", 0)), nil
	})
}

// Store keeps records in a slice, newest last.
type Store struct {
	mu     sync.RWMutex
	recs   []ext.Record
	nextID int64
	// maxRecords trims on write; 0 means unbounded (retention still applies).
	maxRecords int
}

// New builds an in-memory store. maxRecords 0 means unbounded.
func New(maxRecords int) *Store { return &Store{maxRecords: maxRecords} }

func (s *Store) Save(_ context.Context, rec *ext.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	cp := *rec // copy: the caller reuses its record
	cp.ID = s.nextID
	s.recs = append(s.recs, cp)
	if s.maxRecords > 0 && len(s.recs) > s.maxRecords {
		s.recs = s.recs[len(s.recs)-s.maxRecords:]
	}
	return nil
}

// matches applies a Filter. Kept separate so Query and Count agree by
// construction rather than by two similar-looking conditions.
func matches(r *ext.Record, f ext.Filter) bool {
	if f.Method != "" && !strings.EqualFold(r.Method, f.Method) {
		return false
	}
	if f.PathPrefix != "" && !strings.HasPrefix(r.Path, f.PathPrefix) {
		return false
	}
	if f.Search != "" &&
		!strings.Contains(r.Path, f.Search) &&
		!strings.Contains(r.RequestBody, f.Search) &&
		!strings.Contains(r.ResponseBody, f.Search) {
		return false
	}
	if f.StatusMin > 0 && r.Status < f.StatusMin {
		return false
	}
	if f.StatusMax > 0 && r.Status > f.StatusMax {
		return false
	}
	if !f.Since.IsZero() && r.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && r.Time.After(f.Until) {
		return false
	}
	if f.TraceID != "" && r.TraceID != f.TraceID {
		return false
	}
	// Every listed label must match, compared literally — a tenant named
	// "acme_1" must never select "acmeX1". The conformance suite checks this
	// specifically, because getting it wrong shows one tenant another
	// tenant's traffic rather than returning an error anyone would notice.
	for k, v := range f.Labels {
		if r.Labels[k] != v {
			return false
		}
	}
	return true
}

func (s *Store) Query(_ context.Context, f ext.Filter) ([]ext.Record, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var hits []ext.Record
	for i := len(s.recs) - 1; i >= 0; i-- { // newest first
		if matches(&s.recs[i], f) {
			hits = append(hits, s.recs[i])
		}
	}
	total := int64(len(hits))

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if f.Offset >= len(hits) {
		return nil, total, nil
	}
	hits = hits[f.Offset:]
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits, total, nil
}

func (s *Store) Get(_ context.Context, id int64) (*ext.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.recs {
		if s.recs[i].ID == id {
			cp := s.recs[i]
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("record %d not found", id)
}

func (s *Store) Count(_ context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.recs)), nil
}

// since collects records at or after t. Callers hold the read lock.
func (s *Store) since(t time.Time) []ext.Record {
	var out []ext.Record
	for i := range s.recs {
		if !s.recs[i].Time.Before(t) {
			out = append(out, s.recs[i])
		}
	}
	return out
}

// percentile returns the q-quantile of durations, EXCLUDING streams: their
// duration is a connection lifetime, not a latency, and one long stream would
// otherwise define the window's p95.
func percentile(recs []ext.Record, q float64) float64 {
	var d []float64
	for i := range recs {
		if !recs[i].Stream {
			d = append(d, recs[i].DurationMS)
		}
	}
	if len(d) == 0 {
		return 0
	}
	sort.Float64s(d)
	idx := int(q * float64(len(d)))
	if idx >= len(d) {
		idx = len(d) - 1
	}
	return d[idx]
}

func (s *Store) Stats(_ context.Context, from time.Time, bucket time.Duration) (*ext.Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	recs := s.since(from)

	st := &ext.Stats{StatusCounts: map[string]int64{}}
	st.Total = int64(len(recs))
	for i := range recs {
		if recs[i].Status >= 500 {
			st.Errors++
		}
		st.StatusCounts[fmt.Sprintf("%dxx", recs[i].Status/100)]++
	}
	if st.Total > 0 {
		st.ErrorRate = float64(st.Errors) / float64(st.Total)
	}
	st.P50LatencyMS = percentile(recs, 0.50)
	st.P95LatencyMS = percentile(recs, 0.95)
	st.P99LatencyMS = percentile(recs, 0.99)

	if bucket <= 0 {
		bucket = time.Minute
	}
	type acc struct {
		count, errs int64
		sum         float64
	}
	buckets := map[int64]*acc{}
	for i := range recs {
		k := recs[i].Time.UnixMilli() / bucket.Milliseconds()
		a := buckets[k]
		if a == nil {
			a = &acc{}
			buckets[k] = a
		}
		a.count++
		a.sum += recs[i].DurationMS
		if recs[i].Status >= 500 {
			a.errs++
		}
	}
	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		a := buckets[k]
		st.Series = append(st.Series, ext.TimeBucket{
			Time:       time.UnixMilli(k * bucket.Milliseconds()),
			Count:      a.count,
			Errors:     a.errs,
			AvgLatency: a.sum / float64(a.count),
		})
	}

	for _, d := range s.routeDetails(recs) {
		st.TopRoutes = append(st.TopRoutes, d.RouteStat)
		if len(st.TopRoutes) == 10 {
			break
		}
	}
	return st, nil
}

// routeDetails aggregates per (route, method), busiest first.
func (s *Store) routeDetails(recs []ext.Record) []ext.RouteDetail {
	type key struct{ route, method string }
	groups := map[key][]ext.Record{}
	for i := range recs {
		k := key{recs[i].Route, recs[i].Method}
		groups[k] = append(groups[k], recs[i])
	}
	out := make([]ext.RouteDetail, 0, len(groups))
	for k, g := range groups {
		var errs int64
		var sum float64
		var reqB, respB int64
		for i := range g {
			if g[i].Status >= 500 {
				errs++
			}
			sum += g[i].DurationMS
			reqB += g[i].ReqBytes
			respB += g[i].RespBytes
		}
		out = append(out, ext.RouteDetail{
			RouteStat: ext.RouteStat{
				Route: k.route, Method: k.method,
				Count: int64(len(g)), Errors: errs,
				AvgLatency: sum / float64(len(g)),
				P95Latency: percentile(g, 0.95),
			},
			P50Latency: percentile(g, 0.50),
			P99Latency: percentile(g, 0.99),
			ReqBytes:   reqB, RespBytes: respB,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func (s *Store) RouteStats(_ context.Context, from time.Time) ([]ext.RouteDetail, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routeDetails(s.since(from)), nil
}

func (s *Store) ServiceStats(_ context.Context, from time.Time) ([]ext.ServiceStat, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := map[string][]ext.Record{}
	for _, r := range s.since(from) {
		name := r.Service
		if name == "" {
			name = "(unnamed)"
		}
		groups[name] = append(groups[name], r)
	}
	out := make([]ext.ServiceStat, 0, len(groups))
	for name, g := range groups {
		st := ext.ServiceStat{Service: name, Requests: int64(len(g))}
		routes, sources := map[string]bool{}, map[string]bool{}
		var sum float64
		for i := range g {
			if g[i].Status >= 500 {
				st.Errors++
			}
			sum += g[i].DurationMS
			routes[g[i].Route] = true
			if g[i].Source != "" {
				sources[g[i].Source] = true
			}
			if g[i].Time.After(st.LastSeen) {
				st.LastSeen = g[i].Time
			}
		}
		st.AvgLatency = sum / float64(len(g))
		st.P95Latency = percentile(g, 0.95)
		st.Routes = int64(len(routes))
		st.ErrorRate = float64(st.Errors) / float64(st.Requests)
		names := make([]string, 0, len(sources))
		for s := range sources {
			names = append(names, s)
		}
		sort.Strings(names)
		st.Sources = strings.Join(names, ", ")
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out, nil
}

func (s *Store) RuleMatchCounts(_ context.Context, from time.Time, ruleNames []string) ([]ext.RuleMatch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := map[string]int64{}
	for _, r := range s.since(from) {
		for _, name := range r.MatchedRules {
			counts[name]++
		}
	}
	// Report every requested rule, including those that never fired.
	out := make([]ext.RuleMatch, 0, len(ruleNames))
	for _, name := range ruleNames {
		out = append(out, ext.RuleMatch{Rule: name, Count: counts[name]})
	}
	return out, nil
}

func (s *Store) RecentFunc(_ context.Context, from time.Time, limit int, fn func(*ext.Record) error) error {
	s.mu.RLock()
	recs := s.since(from)
	s.mu.RUnlock()

	limit = ext.AnalysisLimit(limit)
	n := 0
	for i := len(recs) - 1; i >= 0 && n < limit; i-- { // newest first
		cp := recs[i]
		if err := fn(&cp); err != nil {
			return err
		}
		n++
	}
	return nil
}

func (s *Store) Recent(ctx context.Context, from time.Time, limit int) ([]ext.Record, error) {
	var out []ext.Record
	err := s.RecentFunc(ctx, from, limit, func(r *ext.Record) error {
		out = append(out, *r)
		return nil
	})
	return out, err
}

func (s *Store) UsageByLabel(_ context.Context, from time.Time, label string) ([]ext.Usage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agg := map[string]*ext.Usage{}
	for _, r := range s.since(from) {
		consumer := r.Labels[label]
		if consumer == "" {
			consumer = "(unattributed)"
		}
		u := agg[consumer]
		if u == nil {
			u = &ext.Usage{Consumer: consumer}
			agg[consumer] = u
		}
		u.Requests++
		if r.Status >= 500 {
			u.Errors++
		}
		u.ReqBytes += r.ReqBytes
		u.RespBytes += r.RespBytes
		u.DurationMS += r.DurationMS
		for k, v := range r.Meters {
			if u.Meters == nil {
				u.Meters = map[string]float64{}
			}
			u.Meters[k] += v
		}
	}
	out := make([]ext.Usage, 0, len(agg))
	for _, u := range agg {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requests > out[j].Requests })
	return out, nil
}

func (s *Store) Prune(_ context.Context, maxRows int64) (int64, error) {
	if maxRows <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if int64(len(s.recs)) <= maxRows {
		return 0, nil
	}
	removed := int64(len(s.recs)) - maxRows
	s.recs = append([]ext.Record(nil), s.recs[removed:]...) // keep the newest
	return removed, nil
}

func (s *Store) PruneBefore(_ context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.recs[:0]
	var removed int64
	for i := range s.recs {
		if s.recs[i].Time.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, s.recs[i])
	}
	s.recs = kept
	return removed, nil
}

// Purge implements erasure requests. The label value is compared with ==,
// never as a pattern: deleting a neighbouring tenant's data is the one mistake
// an erasure tool must never make, and exttest has the regression test for it.
func (s *Store) Purge(_ context.Context, label, value string, before time.Time) (int64, error) {
	if label == "" || value == "" {
		return 0, fmt.Errorf("purge requires both a label and a value")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.recs[:0]
	var removed int64
	for i := range s.recs {
		hit := s.recs[i].Labels[label] == value &&
			(before.IsZero() || s.recs[i].Time.Before(before))
		if hit {
			removed++
			continue
		}
		kept = append(kept, s.recs[i])
	}
	s.recs = kept
	return removed, nil
}

func (s *Store) Close() error { return nil }
