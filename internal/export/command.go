package export

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// commandExporter is the custom-plugin mechanism: it spawns the configured
// executable once and streams one JSON record per line to its stdin. This is
// the same contract as classic exec plugins (Fluentd/Telegraf style), so a
// plugin is just:
//
//	#!/usr/bin/env python3
//	import sys, json
//	for line in sys.stdin:
//	    record = json.loads(line)   # governed: already restricted/redacted
//	    ship_somewhere(record)
//
// The child's stderr is forwarded to the agent log for debuggability. If the
// child exits it is restarted with backoff on the next batch; records sent
// while it is down count as failed.
type commandExporter struct {
	name   string
	argv   []string
	logger *slog.Logger

	mu    sync.Mutex
	cmd   *exec.Cmd
	stdin io.WriteCloser
	// exited is closed by the reaper goroutine when the child exits.
	// Liveness is tracked with this channel rather than by reading
	// cmd.ProcessState: that field is written by cmd.Wait() in the reaper,
	// so reading it from another goroutine is a data race (caught by
	// `go test -race`) even though the read looks harmless.
	exited    chan struct{}
	lastStart time.Time
}

func newCommandExporter(c *config.ExporterCfg, logger *slog.Logger) *commandExporter {
	return &commandExporter{name: c.Name, argv: c.Command, logger: logger}
}

func (e *commandExporter) Name() string { return e.name }
func (e *commandExporter) Type() string { return "command" }

// ensureRunning starts (or restarts) the plugin process. Callers hold e.mu.
func (e *commandExporter) ensureRunning() error {
	if e.cmd != nil {
		select {
		case <-e.exited: // child died — fall through and respawn
		default:
			return nil // still running
		}
	}
	// Backoff: never respawn a crash-looping plugin more than once per 3s.
	if since := time.Since(e.lastStart); since < 3*time.Second {
		return fmt.Errorf("plugin restart suppressed (last start %s ago)", since.Round(time.Millisecond))
	}
	e.lastStart = time.Now()

	cmd := exec.Command(e.argv[0], e.argv[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start plugin: %w", err)
	}
	go e.pipeStderr(stderr)
	exited := make(chan struct{})
	go func() {
		err := cmd.Wait() // reap the child
		close(exited)     // publishes liveness without touching ProcessState
		e.logger.Warn("export plugin exited", "exporter", e.name, "error", err)
	}()

	e.cmd, e.stdin, e.exited = cmd, stdin, exited
	e.logger.Info("export plugin started", "exporter", e.name, "command", e.argv[0], "pid", cmd.Process.Pid)
	return nil
}

func (e *commandExporter) pipeStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		e.logger.Info("export plugin stderr", "exporter", e.name, "line", sc.Text())
	}
}

func (e *commandExporter) Export(_ context.Context, batch []*store.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ensureRunning(); err != nil {
		return err
	}
	for _, rec := range batch {
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := e.stdin.Write(append(line, '\n')); err != nil {
			// Broken pipe: mark dead so the next batch respawns.
			e.cmd.Process.Kill() //nolint:errcheck
			return fmt.Errorf("write to plugin: %w", err)
		}
	}
	return nil
}

func (e *commandExporter) Close() error {
	// Snapshot under the lock, then wait outside it: holding e.mu across a
	// five-second wait would block any in-flight Export.
	e.mu.Lock()
	stdin, cmd, exited := e.stdin, e.cmd, e.exited
	e.mu.Unlock()

	if stdin != nil {
		stdin.Close() // EOF lets a well-behaved plugin drain and exit
	}
	if cmd == nil {
		return nil
	}
	select {
	case <-exited:
		return nil
	case <-time.After(5 * time.Second):
		// The plugin ignored EOF; stop waiting for a drain that isn't coming.
		return cmd.Process.Kill()
	}
}
