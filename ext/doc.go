// Package ext is OpticTrace's extension surface: the contract another Go
// module implements to add a payload store or an output exporter.
//
// # Why this package exists
//
// Almost all of OpticTrace lives under internal/, which Go forbids other
// modules from importing. That is deliberate — it keeps the implementation
// free to change. But it also means an out-of-tree driver had nowhere to
// stand: it could not even name the types an interface method returns.
//
// ext is the narrow, deliberate exception. It holds the data types and the
// two plugin interfaces, and nothing else. The types here are the canonical
// definitions; internal/store and internal/export alias them, so there is one
// Record in the program, not two that happen to look alike.
//
// # Stability
//
// Everything in this package is a public API contract and follows semantic
// versioning: no breaking change within a major version. Nothing under
// internal/ carries that promise. If you are writing an extension and find
// yourself wanting something from internal/, open an issue rather than
// vendoring it — the gap is the bug.
//
// # What an extension can add
//
//	RegisterStore     a payload store (telemetry.store.driver: <name>)
//	RegisterExporter  an output plugin (telemetry.exporters[].type: <name>)
//
// Registration happens at init time or from main before the agent starts.
// Both registries are keyed by the name that appears in optic.yaml, so a
// driver becomes configurable simply by being linked into the binary:
//
//	package main
//
//	import (
//		"github.com/dwarka-prasad/optictrace"
//		"github.com/dwarka-prasad/optictrace/ext"
//	)
//
//	func init() {
//		ext.RegisterStore("s3", func(dsn string, _ ext.Settings) (ext.Store, error) {
//			return newS3Store(dsn)
//		})
//	}
//
// # The governance contract extensions inherit
//
// Records handed to a Store or an Exporter have ALREADY been through the
// rule engine: restricted fields are absent, redacted fields hold the
// placeholder. That is the whole design — governance sits upstream of every
// sink, so no extension can see raw sensitive data, and no extension has to
// be trusted with it.
//
// Two obligations follow, and an extension that breaks either is a governance
// hole even though the core did its job:
//
//   - Do not reconstruct what governance removed. Joining a redacted record
//     against another source to recover the original value defeats the point.
//   - Purge must actually delete. It backs erasure requests ("delete
//     everything you hold for tenant X"), so returning before the data is
//     gone is worse than not implementing it.
//
// # Verifying a Store
//
// The conformance suite that the built-in drivers run is exported from
// ext/exttest. A new Store should pass it unmodified — that suite is what
// stops two drivers quietly answering the same question differently.
package ext
