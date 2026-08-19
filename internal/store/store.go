// Package store persists governed telemetry records (what optic.yaml allowed
// through) and answers the dashboard's query/analytics needs.
//
// Contract: everything stored here is ALREADY restricted/redacted by the
// engine. The store is deliberately downstream of governance so no driver
// can ever see raw sensitive payloads.
package store

import (
	"github.com/dwarka-prasad/optictrace/ext"
)

// The record types and the store contract live in ext, the public extension
// surface, so an out-of-tree driver can name them. These aliases are not
// conversions — Record and ext.Record are the same type — so nothing in the
// rest of the codebase changes, and there is exactly one Record in the program.
type (
	Record      = ext.Record
	Filter      = ext.Filter
	TimeBucket  = ext.TimeBucket
	RouteStat   = ext.RouteStat
	Stats       = ext.Stats
	RouteDetail = ext.RouteDetail
	RuleMatch   = ext.RuleMatch
	Usage       = ext.Usage
	ServiceStat = ext.ServiceStat
	// AppLog is one application log line correlated to a span. AppLogStore is
	// OPTIONAL — a driver is complete without it; detect support with a type
	// assertion rather than assuming.
	AppLog        = ext.AppLog
	AppLogFilter  = ext.AppLogFilter
	AppLogStore   = ext.AppLogStore
	AppLogSummary = ext.AppLogSummary
	// TraceSummary rolls every hop of one request into a row. TraceStore is
	// OPTIONAL for the same reason AppLogStore is: Store is implemented
	// outside this module, so it cannot grow methods.
	TraceSummary = ext.TraceSummary
	TraceFilter  = ext.TraceFilter
	TraceStore   = ext.TraceStore
)

const (
	DefaultAnalysisMaxRows = ext.DefaultAnalysisMaxRows
	MaxAnalysisMaxRows     = ext.MaxAnalysisMaxRows
)

// AnalysisLimit resolves a requested limit against the defaults.
func AnalysisLimit(limit int) int { return ext.AnalysisLimit(limit) }

// LogStore is the persistence contract. Implementations must be safe for
// concurrent use. Save is called from the async writer, never from the
// request hot path.
type LogStore = ext.Store
