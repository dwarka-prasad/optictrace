package export

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// fileExporter appends one JSON record per line. When the file exceeds
// maxBytes it is rotated to <path>.1 (single-generation rotation — external
// log shippers are expected to pick files up from there).
type fileExporter struct {
	name     string
	path     string
	maxBytes int64
	f        *os.File
	written  int64
}

func newFileExporter(c *config.ExporterCfg) (*fileExporter, error) {
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return nil, err
	}
	// config.Parse defaults MaxSizeMB, but a caller constructing ExporterCfg
	// programmatically bypasses that — and maxBytes 0 means `written >= 0`,
	// which rotates after every single batch and leaves one line per file.
	// Defend here so the exporter is correct however it was built.
	sizeMB := c.MaxSizeMB
	if sizeMB <= 0 {
		sizeMB = 100
	}
	e := &fileExporter{name: c.Name, path: c.Path, maxBytes: int64(sizeMB) << 20}
	if err := e.open(); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *fileExporter) open() error {
	f, err := os.OpenFile(e.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	e.f, e.written = f, st.Size()
	return nil
}

func (e *fileExporter) Name() string { return e.name }
func (e *fileExporter) Type() string { return "file" }

func (e *fileExporter) Export(_ context.Context, batch []*store.Record) error {
	for _, rec := range batch {
		line, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal record: %w", err)
		}
		n, err := e.f.Write(append(line, '\n'))
		if err != nil {
			return err
		}
		e.written += int64(n)
	}
	if e.written >= e.maxBytes {
		return e.rotate()
	}
	return nil
}

// ExportAppLogs writes governed log lines to the same JSONL stream.
//
// One stream, with a discriminator, rather than a second file: a consumer
// reading an audit trail wants the request and the lines it wrote in one place
// and in order, and splitting them means reassembling by timestamp — which is
// the correlation problem this whole feature exists to avoid.
func (e *fileExporter) ExportAppLogs(_ context.Context, batch []*ext.AppLog) error {
	for _, l := range batch {
		// The wrapper marks what a line IS. Without it a consumer has to guess
		// from which fields happen to be present, and an app log and a record
		// share most of them.
		line, err := json.Marshal(struct {
			Kind string      `json:"kind"`
			Log  *ext.AppLog `json:"app_log"`
		}{Kind: "app_log", Log: l})
		if err != nil {
			return fmt.Errorf("marshal app log: %w", err)
		}
		n, err := e.f.Write(append(line, '\n'))
		if err != nil {
			return err
		}
		e.written += int64(n)
	}
	if e.written >= e.maxBytes {
		return e.rotate()
	}
	return nil
}

func (e *fileExporter) rotate() error {
	if err := e.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(e.path, e.path+".1"); err != nil {
		return err
	}
	return e.open()
}

func (e *fileExporter) Close() error { return e.f.Close() }
