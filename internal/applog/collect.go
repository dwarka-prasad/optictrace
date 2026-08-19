// Package applog also collects lines the application already writes.
//
// The alternative — every service POSTing to /api/applogs/ingest — means
// touching code in the services whose logs you most want, which are usually the
// ones nobody wants to modify. A JSON logger writing to stdout needs no change
// at all.
package applog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/config"
)

// maxLineBytes bounds one line. A log without newlines — a minified blob, a
// binary file named .log by mistake — must cost a bounded amount of memory
// rather than however much the writer produced.
const maxLineBytes = 1 << 20

// Sink receives governed lines. The store implements it; tests use a fake.
type Sink interface {
	SaveAppLogs(ctx context.Context, lines []ext.AppLog) error
}

// Collector reads sources, governs each line, and batches to a Sink.
type Collector struct {
	gov      *Governor
	sink     Sink
	logger   *slog.Logger
	service  string
	batch    int
	interval time.Duration

	// onDrop is called with the reason for every discarded line, so drops stay
	// counted rather than silent.
	onDrop func(reason string)
	onKeep func(n int)
	// fanout receives every line that was stored, for the exporters. Separate
	// from the sink so a slow exporter cannot stall persistence.
	fanout func(lines []ext.AppLog)

	mu     sync.Mutex
	queue  []ext.AppLog
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewCollector builds a collector. service names lines whose source does not
// override it.
func NewCollector(gov *Governor, sink Sink, service string, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return &Collector{
		gov: gov, sink: sink, logger: logger, service: service,
		batch: 200, interval: 500 * time.Millisecond,
	}
}

// OnDrop and OnKeep install counters, normally the metrics collector's.
func (c *Collector) OnDrop(f func(reason string)) { c.onDrop = f }
func (c *Collector) OnKeep(f func(n int))         { c.onKeep = f }

// OnStored installs a fan-out for lines that were persisted — the exporters.
// Called after a successful save, so an exporter never sees a line the store
// rejected.
func (c *Collector) OnStored(f func(lines []ext.AppLog)) { c.fanout = f }

// Start begins flushing. Sources are attached with Tail and Read.
func (c *Collector) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.NewTicker(c.interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				c.flush(ctx)
			case <-ctx.Done():
				// Drain: the last lines before a shutdown are usually the ones
				// explaining the shutdown.
				c.flush(context.WithoutCancel(ctx))
				return
			}
		}
	}()
}

// Close stops collection and drains what is queued.
func (c *Collector) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
}

func (c *Collector) flush(ctx context.Context) {
	c.mu.Lock()
	batch := c.queue
	c.queue = nil
	c.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := c.sink.SaveAppLogs(ctx, batch); err != nil {
		// Never fatal: the application keeps running whatever the store does.
		c.logger.Warn("app log collection: save failed", "error", err, "lines", len(batch))
		return
	}
	if c.onKeep != nil {
		c.onKeep(len(batch))
	}
	if c.fanout != nil {
		c.fanout(batch)
	}
}

// submit governs one line and queues it if it survives.
func (c *Collector) submit(l ext.AppLog) {
	ok, reason := c.gov.Admit(&l)
	if !ok {
		if c.onDrop != nil {
			c.onDrop(string(reason))
		}
		return
	}
	// Bounded: a logging storm costs a bounded amount of memory and then drops
	// visibly rather than growing until the process dies. The counter is called
	// outside the lock, so a slow callback cannot stall the reader.
	c.mu.Lock()
	full := len(c.queue) >= 10*c.batch
	if !full {
		c.queue = append(c.queue, l)
	}
	c.mu.Unlock()

	if full && c.onDrop != nil {
		c.onDrop("queue_full")
	}
}

// Read consumes lines from r until EOF or ctx is done. Used for a child
// process's stdout and stderr.
func (c *Collector) Read(ctx context.Context, r io.Reader, src config.AppLogSource, echo io.Writer) {
	parser, err := newParser(src, c.service)
	if err != nil {
		c.logger.Error("app log source is unusable", "error", err)
		return
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := sc.Text()
		// Pass the line through untouched. Collecting a service's logs must not
		// stop them reaching the place its operators already read.
		if echo != nil {
			fmt.Fprintln(echo, line)
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		c.submit(parser.parse(line))
		if ctx.Err() != nil {
			return
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
		c.logger.Warn("app log source read failed", "error", err)
	}
}

// Tail follows a file, including across rotation.
//
// Starts at the END of an existing file: replaying a large log on every restart
// would flood the store with history nobody asked for, and the retention window
// would then silently discard the recent lines that were actually wanted.
func (c *Collector) Tail(ctx context.Context, src config.AppLogSource) {
	parser, err := newParser(src, c.service)
	if err != nil {
		c.logger.Error("app log source is unusable", "path", src.Path, "error", err)
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		var (
			f      *os.File
			reader *bufio.Reader
			ino    uint64
		)
		defer func() {
			if f != nil {
				f.Close()
			}
		}()

		open := func() {
			if f != nil {
				f.Close()
				f = nil
			}
			nf, err := os.Open(src.Path)
			if err != nil {
				return
			}
			// Seek to the end only on first open; after a rotation the new file
			// is read from the start, because those lines are new.
			if ino == 0 {
				nf.Seek(0, io.SeekEnd)
			}
			ino = inodeOf(nf)
			f = nf
			reader = bufio.NewReaderSize(nf, 64<<10)
		}
		open()

		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			if f == nil {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					open()
					continue
				}
			}
			line, err := reader.ReadString('\n')
			if err == nil {
				line = strings.TrimRight(line, "\r\n")
				if strings.TrimSpace(line) != "" {
					c.submit(parser.parse(line))
				}
				continue
			}
			// Partial line or EOF: wait, then check whether the file was
			// rotated out from under us.
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if st, serr := os.Stat(src.Path); serr != nil || inodeOfStat(st) != ino {
				ino = 1 // not first open: read a rotated file from its start
				open()
			}
		}
	}()
}

// parser turns a raw line into an AppLog according to one source's config.
type parser struct {
	service      string
	json         bool
	traceField   string
	spanField    string
	levelField   string
	messageField string
	routeField   string
	spanPattern  *regexp.Regexp
}

func newParser(src config.AppLogSource, defaultService string) (*parser, error) {
	p := &parser{
		service:      firstNonEmpty(src.Service, defaultService),
		json:         src.Format != "text",
		traceField:   firstNonEmpty(src.TraceField, "trace_id"),
		spanField:    firstNonEmpty(src.SpanField, "span_id"),
		levelField:   firstNonEmpty(src.LevelField, "level"),
		messageField: src.MessageField,
		routeField:   firstNonEmpty(src.RouteField, "route"),
	}
	if src.SpanPattern != "" {
		re, err := regexp.Compile(src.SpanPattern)
		if err != nil {
			return nil, err
		}
		p.spanPattern = re
	}
	return p, nil
}

func (p *parser) parse(line string) ext.AppLog {
	out := ext.AppLog{Time: time.Now(), Service: p.service, Level: "info",
		Message: line, Source: "collector"}

	if p.json {
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err == nil {
			out.TraceID = strField(doc, p.traceField)
			out.SpanID = strField(doc, p.spanField)
			out.Route = strField(doc, p.routeField)
			if lvl := strField(doc, p.levelField); lvl != "" {
				out.Level = lvl
			}
			out.Message = p.message(doc, line)
			out.Fields = fieldsOf(doc, p.traceField, p.spanField, p.levelField, p.routeField, p.messageField)
			if ts := strField(doc, "time"); ts != "" {
				if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
					out.Time = parsed
				}
			}
		}
		// A line that is not JSON is kept as a message rather than dropped: a
		// panic trace interleaved into a JSON log is exactly the line worth
		// having, and it is never valid JSON.
	}

	if out.SpanID == "" && p.spanPattern != nil {
		if m := p.spanPattern.FindStringSubmatch(line); len(m) > 1 {
			out.SpanID = m[1]
		}
	}
	return out
}

// message resolves the text, trying the configured key then the conventional
// ones. A logger that writes "msg" should not need to be told to.
func (p *parser) message(doc map[string]any, raw string) string {
	if p.messageField != "" {
		if v := strField(doc, p.messageField); v != "" {
			return v
		}
	}
	for _, k := range []string{"message", "msg"} {
		if v := strField(doc, k); v != "" {
			return v
		}
	}
	return raw
}

func strField(doc map[string]any, key string) string {
	if key == "" {
		return ""
	}
	if v, ok := doc[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// fieldsOf keeps everything the line carried that is not already a first-class
// column, stringified. Dropping them would throw away the structure that makes
// a structured log worth having.
func fieldsOf(doc map[string]any, skip ...string) map[string]string {
	skipped := map[string]bool{"message": true, "msg": true, "time": true}
	for _, k := range skip {
		if k != "" {
			skipped[k] = true
		}
	}
	out := map[string]string{}
	for k, v := range doc {
		if skipped[k] {
			continue
		}
		switch val := v.(type) {
		case string:
			out[k] = val
		case nil:
			// omit
		default:
			raw, err := json.Marshal(val)
			if err == nil {
				out[k] = string(raw)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
