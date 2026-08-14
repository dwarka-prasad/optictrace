package store

import (
	"context"
	"log/slog"
	"time"
)

// AsyncWriter decouples the request hot path from persistence: Enqueue is a
// non-blocking channel send, and a single background worker drains into the
// LogStore. Under backpressure records are DROPPED (and counted) — an
// observability tool must never become the bottleneck it measures.
type AsyncWriter struct {
	store     LogStore
	queue     chan *Record
	done      chan struct{}
	logger    *slog.Logger
	onDrop    func()
	maxRows   int64
	pruneTick time.Duration
}

type AsyncOption func(*AsyncWriter)

// WithDropCallback wires drop accounting into the metrics collector.
func WithDropCallback(fn func()) AsyncOption {
	return func(w *AsyncWriter) { w.onDrop = fn }
}

// WithRetention prunes the store down to maxRows periodically.
func WithRetention(maxRows int64) AsyncOption {
	return func(w *AsyncWriter) { w.maxRows = maxRows }
}

func NewAsyncWriter(s LogStore, queueSize int, logger *slog.Logger, opts ...AsyncOption) *AsyncWriter {
	w := &AsyncWriter{
		store:     s,
		queue:     make(chan *Record, queueSize),
		done:      make(chan struct{}),
		logger:    logger,
		pruneTick: time.Minute,
	}
	for _, o := range opts {
		o(w)
	}
	go w.run()
	return w
}

// Enqueue hands off a record without ever blocking the caller.
func (w *AsyncWriter) Enqueue(rec *Record) {
	select {
	case w.queue <- rec:
	default:
		if w.onDrop != nil {
			w.onDrop()
		}
	}
}

func (w *AsyncWriter) run() {
	prune := time.NewTicker(w.pruneTick)
	defer prune.Stop()
	for {
		select {
		case rec, ok := <-w.queue:
			if !ok {
				close(w.done)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := w.store.Save(ctx, rec); err != nil {
				w.logger.Warn("store save failed", "error", err)
			}
			cancel()
		case <-prune.C:
			if w.maxRows > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if n, err := w.store.Prune(ctx, w.maxRows); err != nil {
					w.logger.Warn("store prune failed", "error", err)
				} else if n > 0 {
					w.logger.Info("pruned old telemetry", "rows", n)
				}
				cancel()
			}
		}
	}
}

// Close drains outstanding records, then closes the underlying store.
func (w *AsyncWriter) Close() error {
	close(w.queue)
	select {
	case <-w.done:
	case <-time.After(10 * time.Second):
		w.logger.Warn("store drain timed out")
	}
	return w.store.Close()
}
