package ext_test

import (
	"strings"
	"testing"

	"github.com/dwarka-prasad/optictrace/ext"
)

func TestSettingsAccessors(t *testing.T) {
	// YAML decodes whole numbers as int; the same value arriving through JSON
	// is a float64. A plugin should not have to care which path it came by.
	s := ext.Settings{
		"bucket":  "optic-archive",
		"shards":  4,
		"shards2": float64(8),
		"shards3": int64(16),
		"compact": true,
	}
	if got := s.String("bucket", "x"); got != "optic-archive" {
		t.Errorf("String = %q", got)
	}
	if got := s.Int("shards", 0); got != 4 {
		t.Errorf("Int(int) = %d", got)
	}
	if got := s.Int("shards2", 0); got != 8 {
		t.Errorf("Int(float64) = %d", got)
	}
	if got := s.Int("shards3", 0); got != 16 {
		t.Errorf("Int(int64) = %d", got)
	}
	if !s.Bool("compact", false) {
		t.Error("Bool = false")
	}

	// A missing or wrongly-typed key falls back rather than panicking: config
	// is user input, and a plugin should degrade, not crash the agent.
	if got := s.String("absent", "fallback"); got != "fallback" {
		t.Errorf("missing String = %q", got)
	}
	if got := s.Int("bucket", 99); got != 99 {
		t.Errorf("wrongly-typed Int = %d, want the default", got)
	}
	if got := ext.Settings(nil).String("k", "d"); got != "d" {
		t.Errorf("nil Settings should be usable, got %q", got)
	}
}

func TestRegisterStoreRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		open ext.StoreOpener
	}{
		{"empty name", "", func(string, ext.Settings) (ext.Store, error) { return nil, nil }},
		{"nil opener", "somedriver", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected a panic — a silently ignored registration " +
						"surfaces much later as 'unknown driver'")
				}
			}()
			ext.RegisterStore(tc.key, tc.open)
		})
	}
}

func TestRegisterStoreRejectsDuplicates(t *testing.T) {
	ext.RegisterStore("dup-check", func(string, ext.Settings) (ext.Store, error) { return nil, nil })
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("registering the same name twice must panic")
		}
		if !strings.Contains(r.(string), "already registered") {
			t.Errorf("panic message %v should say what collided", r)
		}
	}()
	ext.RegisterStore("dup-check", func(string, ext.Settings) (ext.Store, error) { return nil, nil })
}

func TestLookupAndListing(t *testing.T) {
	ext.RegisterStore("listing-store", func(string, ext.Settings) (ext.Store, error) { return nil, nil })
	ext.RegisterExporter("listing-exporter", func(ext.ExporterOptions) (ext.Exporter, error) { return nil, nil })

	if _, ok := ext.LookupStore("listing-store"); !ok {
		t.Error("a registered store should be findable")
	}
	if _, ok := ext.LookupStore("never-registered"); ok {
		t.Error("an unregistered name should not resolve")
	}
	if _, ok := ext.LookupExporter("listing-exporter"); !ok {
		t.Error("a registered exporter should be findable")
	}

	// The listings feed the "not supported (…)" error message, so they must
	// actually contain what was registered.
	if !contains(ext.RegisteredStores(), "listing-store") {
		t.Errorf("RegisteredStores = %v", ext.RegisteredStores())
	}
	if !contains(ext.RegisteredExporters(), "listing-exporter") {
		t.Errorf("RegisteredExporters = %v", ext.RegisteredExporters())
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
