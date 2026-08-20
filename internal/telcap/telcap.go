// Package telcap holds the two mechanics every per-request telemetry stream
// needs: a memory-bounded per-key counter, and a truncation that respects
// UTF-8.
//
// Extracted rather than copied. App logs and inner spans both cap "how much
// one request may contribute" and both truncate free text, and two copies of
// that logic would drift — with the copy nobody exercises drifting first.
package telcap

import "sync"

// DefaultMaxTrackedKeys bounds how many spans are remembered at once.
const DefaultMaxTrackedKeys = 4096

// Counter counts contributions per key with bounded memory.
//
// An unbounded map keyed by span id is a slow leak: every request that ever
// contributed would be remembered forever. Two generations are kept and the
// older is dropped wholesale once the newer fills, so the count is exact for
// recent keys and forgotten for old ones — the right trade, since the cap
// exists to stop a burst rather than to be an audited total.
type Counter struct {
	mu      sync.Mutex
	cur     map[string]int
	prev    map[string]int
	maxKeys int
}

// NewCounter returns a counter tracking at most maxKeys keys per generation.
// maxKeys <= 0 uses DefaultMaxTrackedKeys.
func NewCounter(maxKeys int) *Counter {
	if maxKeys <= 0 {
		maxKeys = DefaultMaxTrackedKeys
	}
	return &Counter{cur: map[string]int{}, prev: map[string]int{}, maxKeys: maxKeys}
}

// Allow reports whether key may contribute once more, and records it if so.
// A max of 0 or less means unlimited, and nothing is tracked.
func (c *Counter) Allow(key string, max int) bool {
	if max <= 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	n, ok := c.cur[key]
	if !ok {
		if p, hit := c.prev[key]; hit {
			n = p
		}
	}
	if n >= max {
		return false
	}
	if len(c.cur) >= c.maxKeys && !ok {
		c.prev, c.cur = c.cur, make(map[string]int, c.maxKeys)
	}
	c.cur[key] = n + 1
	return true
}

// TruncateUTF8 cuts s to at most max bytes without splitting a rune, so a
// truncated stack trace or statement is still valid UTF-8 and still renders.
// A max of 0 or less leaves s alone.
func TruncateUTF8(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !runeStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func runeStart(b byte) bool { return b&0xC0 != 0x80 }
