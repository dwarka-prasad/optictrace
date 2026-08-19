// Package export is OpticTrace's pluggable output layer: every governed
// telemetry record (post-restriction, post-redaction — exporters can never
// see raw sensitive data) fans out to the exporters declared under
// telemetry.exporters in optic.yaml.
//
// Built-in exporter types:
//
//	file     append JSONL to disk, size-based rotation
//	webhook  POST JSON batches to an HTTP endpoint
//	otlp     emit OpenTelemetry spans to a collector (OTLP/HTTP + JSON)
//	command  THE CUSTOM PLUGIN HOOK — spawn any executable and stream one
//	         JSON record per line to its stdin; write plugins in any
//	         language to ship data to Kafka, S3, a SIEM, anywhere.
//
// Delivery model: at-most-once, deliberately. Each exporter gets its own
// bounded queue and worker; a slow or dead exporter drops its own records
// (counted per exporter) and can never block the request path or starve
// other exporters.
package export

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Exporter delivers batches of governed records to one destination. The
// contract lives in ext so out-of-tree plugins can implement it; this is an
// alias, not a parallel definition.
type Exporter = ext.Exporter

// Stat is a point-in-time view of one exporter, for /api/system.
type Stat struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Delivered int64  `json:"delivered"`
	Failed    int64  `json:"failed"`
	Dropped   int64  `json:"dropped"`
	QueueLen  int    `json:"queue_len"`
}

// Metrics is the hook back into the Prometheus collector (nil-safe).
type Metrics interface {
	ExportDelivered(exporter string, n int)
	ExportFailed(exporter string, n int)
	ExportDropped(exporter string)
}

type worker struct {
	exp       Exporter
	queue     chan *store.Record
	batchSize int
	flushEach time.Duration
	delivered atomic.Int64
	failed    atomic.Int64
	dropped   atomic.Int64

	// logs is non-nil only when the exporter implements ext.AppLogExporter.
	// A separate queue rather than a shared one so a burst of log lines cannot
	// delay records, which are the lower-volume and higher-value stream.
	logs    chan *ext.AppLog
	logExp  ext.AppLogExporter
	logDrop atomic.Int64
}

// Dispatcher owns one worker per configured exporter.
type Dispatcher struct {
	workers []*worker
	logger  *slog.Logger
	metrics Metrics
	wg      sync.WaitGroup
}

// New builds exporters from config and starts their workers.
func New(cfgs []config.ExporterCfg, logger *slog.Logger, m Metrics, serviceName string) (*Dispatcher, error) {
	d := &Dispatcher{logger: logger, metrics: m}
	for i := range cfgs {
		c := &cfgs[i]
		var exp Exporter
		var err error
		switch c.Type {
		case "file":
			exp, err = newFileExporter(c)
		case "webhook":
			exp = newWebhookExporter(c)
		case "command":
			exp = newCommandExporter(c, logger)
		case "otlp":
			exp = newOTLPExporter(c, serviceName)
		default:
			// Not a built-in: an out-of-tree plugin may have registered it.
			// Config validation already accepted the name on that basis, so
			// reaching the error here means the registry changed after load.
			if build, ok := ext.LookupExporter(c.Type); ok {
				exp, err = build(ext.ExporterOptions{
					Name: c.Name, Type: c.Type, Settings: c.Settings,
					BatchSize: c.BatchSize, FlushInterval: c.FlushEvery(),
					QueueSize: c.QueueSize, ServiceName: serviceName,
				})
			} else {
				err = fmt.Errorf("unknown exporter type %q", c.Type)
			}
		}
		if err != nil {
			d.Shutdown()
			return nil, fmt.Errorf("exporter %s: %w", c.Name, err)
		}
		w := &worker{
			exp:       exp,
			queue:     make(chan *store.Record, c.QueueSize),
			batchSize: c.BatchSize,
			flushEach: c.FlushEvery(),
		}
		// App-log support is optional and discovered, not configured: an
		// exporter either accepts lines or it does not, and asking the operator
		// to declare it would just be a second place to get it wrong.
		if ale, ok := exp.(ext.AppLogExporter); ok {
			w.logExp = ale
			w.logs = make(chan *ext.AppLog, c.QueueSize)
		} else {
			logger.Info("exporter takes records only — application log lines will not "+
				"reach it (its type does not implement app-log export)",
				"exporter", c.Name, "type", c.Type)
		}
		d.workers = append(d.workers, w)
		d.wg.Add(1)
		go d.run(w)
	}
	return d, nil
}

// Enqueue hands a record to every exporter without ever blocking.
// EnqueueAppLog fans one governed log line out to every exporter that accepts
// them. Exporters without app-log support simply do not receive it.
func (d *Dispatcher) EnqueueAppLog(l *ext.AppLog) {
	for _, w := range d.workers {
		if w.logs == nil {
			continue
		}
		select {
		case w.logs <- l:
		default:
			// Same posture as records: drop rather than block, and count it.
			// Backpressure here would reach the request path eventually.
			w.logDrop.Add(1)
			if d.metrics != nil {
				d.metrics.ExportDropped(w.exp.Name())
			}
		}
	}
}

// AcceptsAppLogs reports whether any configured exporter takes log lines, so
// the caller can skip the work entirely when none do.
func (d *Dispatcher) AcceptsAppLogs() bool {
	for _, w := range d.workers {
		if w.logs != nil {
			return true
		}
	}
	return false
}

func (d *Dispatcher) Enqueue(rec *store.Record) {
	for _, w := range d.workers {
		select {
		case w.queue <- rec:
		default:
			w.dropped.Add(1)
			if d.metrics != nil {
				d.metrics.ExportDropped(w.exp.Name())
			}
		}
	}
}

// Stats reports per-exporter delivery counters.
func (d *Dispatcher) Stats() []Stat {
	out := make([]Stat, 0, len(d.workers))
	for _, w := range d.workers {
		out = append(out, Stat{
			Name:      w.exp.Name(),
			Type:      w.exp.Type(),
			Delivered: w.delivered.Load(),
			Failed:    w.failed.Load(),
			Dropped:   w.dropped.Load(),
			QueueLen:  len(w.queue),
		})
	}
	return out
}

func (d *Dispatcher) run(w *worker) {
	defer d.wg.Done()
	ticker := time.NewTicker(w.flushEach)
	defer ticker.Stop()

	batch := make([]*store.Record, 0, w.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := w.exp.Export(ctx, batch)
		cancel()
		if err != nil {
			w.failed.Add(int64(len(batch)))
			if d.metrics != nil {
				d.metrics.ExportFailed(w.exp.Name(), len(batch))
			}
			d.logger.Warn("export failed", "exporter", w.exp.Name(), "records", len(batch), "error", err)
		} else {
			w.delivered.Add(int64(len(batch)))
			if d.metrics != nil {
				d.metrics.ExportDelivered(w.exp.Name(), len(batch))
			}
		}
		batch = batch[:0]
	}

	logs := make([]*ext.AppLog, 0, w.batchSize)
	flushLogs := func() {
		if len(logs) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := w.logExp.ExportAppLogs(ctx, logs)
		cancel()
		if err != nil {
			w.failed.Add(int64(len(logs)))
			if d.metrics != nil {
				d.metrics.ExportFailed(w.exp.Name(), len(logs))
			}
			d.logger.Warn("app log export failed",
				"exporter", w.exp.Name(), "lines", len(logs), "error", err)
		} else {
			w.delivered.Add(int64(len(logs)))
			if d.metrics != nil {
				d.metrics.ExportDelivered(w.exp.Name(), len(logs))
			}
		}
		logs = logs[:0]
	}

	// A nil channel blocks forever in a select, so an exporter without app-log
	// support simply never wakes on that arm — no extra branching needed.
	logQueue := w.logs

	for {
		select {
		case rec, ok := <-w.queue:
			if !ok {
				flush()
				// Drain the log queue before closing the exporter. Shutdown
				// closes both channels, and select picks a ready arm at random,
				// so this arm can win while lines are still queued — relying on
				// close ORDER here would lose the last batch about half the time.
				//
				// The nil check is load-bearing: the log arm sets logQueue to
				// nil once it has drained, and ranging over a nil channel blocks
				// forever rather than returning.
				if logQueue != nil {
					for l := range logQueue {
						logs = append(logs, l)
						if len(logs) >= w.batchSize {
							flushLogs()
						}
					}
				}
				flushLogs()
				if err := w.exp.Close(); err != nil {
					d.logger.Warn("exporter close failed", "exporter", w.exp.Name(), "error", err)
				}
				return
			}
			batch = append(batch, rec)
			if len(batch) >= w.batchSize {
				flush()
			}
		case l, ok := <-logQueue:
			if !ok {
				// Records still arrive on their own queue; only stop selecting
				// on this one.
				logQueue = nil
				flushLogs()
				continue
			}
			logs = append(logs, l)
			if len(logs) >= w.batchSize {
				flushLogs()
			}
		case <-ticker.C:
			flush()
			flushLogs()
		}
	}
}

// Shutdown flushes pending batches and closes every exporter.
func (d *Dispatcher) Shutdown() {
	for _, w := range d.workers {
		if w.logs != nil {
			close(w.logs)
		}
		close(w.queue)
	}
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		d.logger.Warn("exporter shutdown timed out")
	}
}
