package memstore_test

import (
	"testing"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/ext/exttest"

	"github.com/dwarka-prasad/optictrace-example-memstore"
)

// The whole point of this module: a driver written entirely against ext/,
// with no access to internal/, passing the same suite the built-in drivers do.
// If this stops compiling, the extension surface has a hole.
func TestConformance(t *testing.T) {
	exttest.RunStoreSuite(t, func(t *testing.T) ext.Store {
		return memstore.New(0) // fresh and empty per sub-test
	})
}

// Registration is what makes `telemetry.store.driver: memory` valid, without
// the core knowing this package exists.
func TestRegisteredUnderItsName(t *testing.T) {
	open, ok := ext.LookupStore("memory")
	if !ok {
		t.Fatal("importing this package should register the driver")
	}
	s, err := open("", ext.Settings{"max_records": 5})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	for i := 0; i < 12; i++ {
		if err := s.Save(t.Context(), exttest.Record(200, 1, "/x", "acme")); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("max_records setting ignored: count = %d, want 5", n)
	}
}
