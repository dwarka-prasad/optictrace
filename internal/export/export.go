// Package export is OpticTrace's pluggable output layer: every governed
// telemetry record (post-restriction, post-redaction — exporters can never
// see raw sensitive data) fans out to the exporters declared under
// telemetry.exporters in optic.yaml.
//
// Built-in exporter types:
//
//	file     append JSONL to disk, size-based rotation
//	webhook  POST JSON batches to an HTTP endpoint
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

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Exporter delivers batches of governed records to one destination.
type Exporter interface {
	Name() string
	Type() string
	// Export delivers one batch. An error marks the whole batch failed.
	Export(ctx context.Context, batch []*store.Record) error
	Close() error
}

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
}

// Dispatcher owns one worker per configured exporter.
type Dispatcher struct {
	workers []*worker
	logger  *slog.Logger
	metrics Metrics
	wg      sync.WaitGroup
}

// New builds exporters from config and starts their workers.
func New(cfgs []config.ExporterCfg, logger *slog.Logger, m Metrics) (*Dispatcher, error) {
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
		default:
			err = fmt.Errorf("unknown exporter type %q", c.Type) // unreachable post-validation
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
		d.workers = append(d.workers, w)
		d.wg.Add(1)
		go d.run(w)
	}
	return d, nil
}

// Enqueue hands a record to every exporter without ever blocking.
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

	for {
		select {
		case rec, ok := <-w.queue:
			if !ok {
				flush()
				if err := w.exp.Close(); err != nil {
					d.logger.Warn("exporter close failed", "exporter", w.exp.Name(), "error", err)
				}
				return
			}
			batch = append(batch, rec)
			if len(batch) >= w.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Shutdown flushes pending batches and closes every exporter.
func (d *Dispatcher) Shutdown() {
	for _, w := range d.workers {
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
