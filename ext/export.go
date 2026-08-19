package ext

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Exporter delivers batches of governed records to one destination.
//
// internal/export.Exporter is an alias of this type. The batching, retry and
// backpressure machinery stays in the core: an Exporter only has to deliver a
// batch and report whether it worked.
type Exporter interface {
	// Name is the configured exporter name; it becomes the `exporter` label
	// on optictrace_exported_total and friends.
	Name() string
	// Type is the registered kind, e.g. "file" or "s3".
	Type() string
	// Export delivers one batch. Returning an error marks the WHOLE batch
	// failed — the core counts it and moves on rather than retrying forever,
	// because blocking here would eventually apply backpressure to the
	// request path.
	//
	// Respect ctx: it is cancelled on shutdown.
	Export(ctx context.Context, batch []*Record) error
	Close() error
}

// AppLogExporter is an OPTIONAL companion to Exporter: an exporter may also
// accept application log lines.
//
// Separate interface rather than a second method on Exporter, for the same
// reason ext.AppLogStore is separate from ext.Store — Exporter is published and
// implemented outside this module, so adding a method to it would break every
// third-party exporter at compile time. Detect support with a type assertion:
//
//	if ale, ok := myExporter.(ext.AppLogExporter); ok { ... }
//
// An exporter without it still receives records; log lines simply do not fan
// out to it. That is reported at startup rather than left to be discovered,
// because an audit trail quietly missing the highest-risk surface is worse than
// one that says it is records-only.
type AppLogExporter interface {
	Exporter
	// ExportAppLogs delivers one batch of governed lines. Same contract as
	// Export: an error marks the whole batch failed, and ctx is cancelled on
	// shutdown.
	ExportAppLogs(ctx context.Context, batch []*AppLog) error
}

// ExporterOptions is one entry from `telemetry.exporters` as an extension
// sees it. The core owns batching, so BatchSize/FlushInterval/QueueSize are
// informational — useful for sizing an internal buffer, not something the
// exporter must implement.
type ExporterOptions struct {
	Name string
	Type string
	// Settings holds `telemetry.exporters[].settings` — the keys the core
	// knows nothing about. optic.yaml rejects unknown top-level keys, so this
	// map is where an extension's own configuration lives.
	Settings Settings

	BatchSize     int
	FlushInterval time.Duration
	QueueSize     int
	// ServiceName is service.name, for exporters that tag their output.
	ServiceName string
}

// ExporterBuilder constructs an Exporter from its configuration.
type ExporterBuilder func(opts ExporterOptions) (Exporter, error)

// RegisterExporter makes a plugin available as
// `telemetry.exporters[].type: <name>`.
//
// Panics on a duplicate name, for the same reason RegisterStore does.
func RegisterExporter(name string, build ExporterBuilder) {
	if name == "" || build == nil {
		panic("ext: RegisterExporter needs a name and a builder")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := exporters[name]; dup {
		panic(fmt.Sprintf("ext: exporter type %q is already registered", name))
	}
	exporters[name] = build
}

// LookupExporter returns the builder registered for name.
func LookupExporter(name string) (ExporterBuilder, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	build, ok := exporters[name]
	return build, ok
}

// RegisteredExporters lists registered exporter types, sorted.
func RegisteredExporters() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]string, 0, len(exporters))
	for k := range exporters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
