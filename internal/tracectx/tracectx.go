// Package tracectx handles W3C Trace Context — the header that lets records
// from several services be recognised as one request.
//
// It lives in its own package because three places need it and they used to
// need it separately: the proxy stamps ids onto a record, the OTLP exporter
// emits them as spans, and the SDK ingest path preserves whatever a framework
// SDK already resolved. One parser means a record and the span exported from
// it cannot disagree about which trace they belong to.
//
//	traceparent: 00-<32 hex trace id>-<16 hex span id>-<2 hex flags>
package tracectx

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Header is the W3C header name.
const Header = "traceparent"

// StateHeader carries vendor-specific state alongside it.
const StateHeader = "tracestate"

// Context is one request's position in a trace.
type Context struct {
	// TraceID identifies the whole request across services (32 hex chars).
	TraceID string
	// SpanID identifies this hop (16 hex chars).
	SpanID string
	// ParentSpanID is the caller's span, empty when this hop is the root.
	ParentSpanID string
	// Sampled carries the caller's sampling decision, so OpticTrace does not
	// export spans for traces the application already decided to drop.
	Sampled bool
	// Route is the rule pattern this request matched, resolved by the engine.
	// Carried here because it is what a per-rule `logs:` block keys on, and a
	// log handler has the context but not the policy.
	Route string
	// Inherited reports whether a usable traceparent arrived. False means the
	// ids here were generated, and this hop is the root of a new trace.
	Inherited bool
}

// Header renders this context as a traceparent value, for propagating
// downstream.
func (c Context) Header() string {
	flags := "00"
	if c.Sampled {
		flags = "01"
	}
	return "00-" + c.TraceID + "-" + c.SpanID + "-" + flags
}

// FromHeader resolves trace context from an inbound traceparent value.
//
// A fresh span id is always generated: this hop is a new span even when it
// continues someone else's trace. A malformed or absent header yields a new
// root trace rather than an error — losing correlation is a nuisance, failing
// a request over a bad header would be a fault.
func FromHeader(raw string) Context {
	c := Context{SpanID: RandomHex(8)}
	parts := strings.Split(strings.TrimSpace(raw), "-")
	if len(parts) != 4 {
		c.TraceID = RandomHex(16)
		return c
	}
	version, tid, pid, flags := parts[0], parts[1], parts[2], parts[3]
	// Version ff is forbidden by the spec; 00 is the only layout defined
	// today, and an all-zero id is explicitly invalid.
	if version != "00" ||
		!isHex(tid, 32) || !isHex(pid, 16) || !isHex(flags, 2) ||
		tid == strings.Repeat("0", 32) || pid == strings.Repeat("0", 16) {
		c.TraceID = RandomHex(16)
		return c
	}
	f, err := strconv.ParseUint(flags, 16, 8)
	c.TraceID, c.ParentSpanID = tid, pid
	c.Sampled = err == nil && f&0x01 != 0
	c.Inherited = true
	return c
}

// FromMap resolves trace context from captured headers, matching the header
// name case-insensitively as HTTP requires.
func FromMap(headers map[string]string) Context {
	return FromHeader(Lookup(headers, Header))
}

// Lookup finds a header case-insensitively. Captured headers keep whatever
// casing the client sent.
func Lookup(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// RandomHex produces trace and span ids. n is the byte count: 16 for a trace
// id, 8 for a span id.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not recoverable here, and an all-zero id is
		// invalid — fall back to something time-derived so correlation
		// degrades rather than producing a rejected id.
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i % 8 * 8))
		}
	}
	return hex.EncodeToString(b)
}

// isHex reports whether s is exactly n hex digits.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
