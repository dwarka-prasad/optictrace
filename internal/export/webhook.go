package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// webhookExporter POSTs each batch as a JSON array. One retry on failure —
// beyond that the batch is counted failed (at-most-once by design; exporters
// must never buffer unboundedly).
type webhookExporter struct {
	name    string
	url     string
	headers map[string]string
	client  *http.Client
}

func newWebhookExporter(c *config.ExporterCfg) *webhookExporter {
	return &webhookExporter{
		name:    c.Name,
		url:     c.URL,
		headers: c.Headers,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (e *webhookExporter) Name() string { return e.name }
func (e *webhookExporter) Type() string { return "webhook" }

func (e *webhookExporter) Export(ctx context.Context, batch []*store.Record) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "optictrace-exporter")
		for k, v := range e.headers {
			req.Header.Set(k, v)
		}
		resp, err := e.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned %s", resp.Status)
	}
	return lastErr
}

func (e *webhookExporter) Close() error { return nil }
