package telcap

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The whole point of two generations is that memory does not grow with the
// number of requests ever seen. Without the bound this map is a slow leak that
// only shows up in a long-running agent.
func TestCounterMemoryIsBounded(t *testing.T) {
	c := NewCounter(64)
	for i := 0; i < 10_000; i++ {
		c.Allow(fmt.Sprintf("span-%d", i), 5)
	}
	c.mu.Lock()
	total := len(c.cur) + len(c.prev)
	c.mu.Unlock()
	if total > 2*64 {
		t.Errorf("tracked %d keys, want <= 128", total)
	}
}

func TestCounterEnforcesTheCap(t *testing.T) {
	c := NewCounter(0)
	for i := 0; i < 3; i++ {
		if !c.Allow("k", 3) {
			t.Fatalf("contribution %d of 3 rejected", i+1)
		}
	}
	if c.Allow("k", 3) {
		t.Error("cap not enforced")
	}
	// A cap of zero or less means unlimited, and must not start tracking.
	for i := 0; i < 100; i++ {
		if !c.Allow("unlimited", 0) {
			t.Fatal("a zero cap must mean unlimited")
		}
	}
}

// Ingest is an HTTP handler: several requests land at once, and a counter that
// races would either over-admit or panic on the map.
func TestCounterIsConcurrencySafe(t *testing.T) {
	c := NewCounter(32)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c.Allow(fmt.Sprintf("k-%d", i%40), 10)
			}
		}(g)
	}
	wg.Wait()
}

func TestTruncateUTF8NeverSplitsARune(t *testing.T) {
	s := strings.Repeat("é", 20) // 2 bytes each
	got := TruncateUTF8(s, 9)
	if len(got) > 9 {
		t.Errorf("%d bytes, cap 9", len(got))
	}
	if strings.ContainsRune(got, '�') {
		t.Error("truncation split a rune")
	}
	if TruncateUTF8("short", 100) != "short" {
		t.Error("a string under the cap must be untouched")
	}
	if TruncateUTF8("anything", 0) != "anything" {
		t.Error("a cap of 0 must mean no truncation")
	}
}
