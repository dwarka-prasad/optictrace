package ext

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Store is the persistence contract. Implementations must be safe for
// concurrent use; Save is called from the async writer, never from the request
// hot path.
//
// Records arriving here are already governed — see the package doc. The two
// methods worth extra care are Purge, which backs erasure requests and must
// actually delete before it returns, and RecentFunc, which exists so an
// analysis pass costs one record of memory rather than the whole window.
//
// internal/store.LogStore is an alias of this type, so a driver that satisfies
// Store is usable everywhere the built-in drivers are.
type Store interface {
	Save(ctx context.Context, rec *Record) error
	Query(ctx context.Context, f Filter) (records []Record, total int64, err error)
	Get(ctx context.Context, id int64) (*Record, error)
	Stats(ctx context.Context, since time.Time, bucket time.Duration) (*Stats, error)
	// RouteStats aggregates every route seen since the given time.
	RouteStats(ctx context.Context, since time.Time) ([]RouteDetail, error)
	// RuleMatchCounts reports how often each named rule fired since the given
	// time. Report a zero for a requested rule that never fired — that is the
	// interesting answer for a rule someone expected to be matching.
	RuleMatchCounts(ctx context.Context, since time.Time, ruleNames []string) ([]RuleMatch, error)
	// Count returns total stored records.
	Count(ctx context.Context) (int64, error)
	// Recent returns up to limit full records since a time (newest first).
	// limit <= 0 means DefaultAnalysisMaxRows. Prefer RecentFunc for anything
	// that folds over the result.
	Recent(ctx context.Context, since time.Time, limit int) ([]Record, error)
	// RecentFunc streams the same records one at a time, so memory stays at
	// one record regardless of how many there are. A non-nil error from fn
	// stops the walk and is returned to the caller.
	RecentFunc(ctx context.Context, since time.Time, limit int, fn func(*Record) error) error
	// ServiceStats aggregates per service — the fleet view.
	ServiceStats(ctx context.Context, since time.Time) ([]ServiceStat, error)
	// UsageByLabel aggregates traffic per consumer (a label value, e.g.
	// tenant) — the cost-attribution view.
	UsageByLabel(ctx context.Context, since time.Time, label string) ([]Usage, error)
	Prune(ctx context.Context, maxRows int64) (removed int64, err error)
	// PruneBefore deletes everything older than cutoff — age-based retention,
	// which is how data-retention policies are actually written.
	PruneBefore(ctx context.Context, cutoff time.Time) (removed int64, err error)
	// Purge deletes records matching a consumer label (and optionally a time
	// bound): "delete everything you hold for tenant X".
	//
	// Match the label value LITERALLY. The built-in SQLite driver once matched
	// it as a LIKE pattern, so purging a tenant named "acme_1" also destroyed
	// "acmeX1" — deleting a bystander's data is the one mistake an erasure
	// tool must never make. ext/exttest has the regression test.
	Purge(ctx context.Context, label, value string, before time.Time) (removed int64, err error)
	Close() error
}

// Settings carries driver-specific configuration from optic.yaml's
// `telemetry.store.settings` map — the keys the core knows nothing about.
// Named keys (driver, dsn, retention) are validated by the core and passed
// separately; everything here is the extension's own business.
type Settings map[string]any

// String reads a string setting, returning def when absent or of another type.
func (s Settings) String(key, def string) string {
	if v, ok := s[key].(string); ok {
		return v
	}
	return def
}

// Int reads an integer setting. YAML decodes whole numbers as int, but a value
// that arrived through JSON is a float64, so both are accepted.
func (s Settings) Int(key string, def int) int {
	switch v := s[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return def
}

// Bool reads a boolean setting.
func (s Settings) Bool(key string, def bool) bool {
	if v, ok := s[key].(bool); ok {
		return v
	}
	return def
}

// StoreOpener constructs a Store from the configured DSN and settings.
type StoreOpener func(dsn string, settings Settings) (Store, error)

var (
	registryMu sync.RWMutex
	stores     = map[string]StoreOpener{}
	exporters  = map[string]ExporterBuilder{}
)

// RegisterStore makes a driver available as `telemetry.store.driver: <name>`.
//
// Call it from an init function or from main before starting the agent.
// Registering is what makes the name pass config validation, so a driver
// becomes configurable purely by being linked into the binary.
//
// Panics on a duplicate or reserved name: a silently ignored registration
// would show up much later as "unknown driver", pointing at the config rather
// than at the collision.
func RegisterStore(name string, open StoreOpener) {
	if name == "" || open == nil {
		panic("ext: RegisterStore needs a name and an opener")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := stores[name]; dup {
		panic(fmt.Sprintf("ext: store driver %q is already registered", name))
	}
	stores[name] = open
}

// LookupStore returns the opener registered for name.
func LookupStore(name string) (StoreOpener, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	open, ok := stores[name]
	return open, ok
}

// RegisteredStores lists registered driver names, sorted — used to build the
// "not supported (…)" message when a config names an unknown driver.
func RegisteredStores() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(stores))
	for k := range stores {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
