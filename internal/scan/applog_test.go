package scan

import (
	"strings"
	"testing"
	"time"

	"github.com/dwarka-prasad/optictrace/ext"
)

// A leak detector that only reads payloads is looking where the data is
// easiest to protect rather than where it escapes. This is the surface that
// carries tokens and whole request bodies inside stack traces.
func TestScannerFindsSecretsInLogLines(t *testing.T) {
	sc := NewScanner(time.Now().Add(-time.Hour))
	now := time.Now()

	sc.AddAppLog(&ext.AppLog{
		Time: now, Service: "payments", Level: "debug",
		Message: "charging card 4111111111111111 for tenant acme",
	})
	sc.AddAppLog(&ext.AppLog{
		Time: now, Service: "payments", Level: "error",
		Message: "gateway rejected",
		Fields:  map[string]string{"card": "4111111111111111", "amount": "42"},
	})

	rep := sc.Report()
	if rep.LinesScanned != 2 {
		t.Errorf("LinesScanned = %d, want 2", rep.LinesScanned)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("no findings — a card number in a log line went unnoticed")
	}

	var inMessage, inField *Finding
	for i := range rep.Findings {
		f := &rep.Findings[i]
		if f.Location != "app_log" {
			t.Errorf("finding location = %q, want app_log", f.Location)
		}
		switch f.Field {
		case "message":
			inMessage = f
		case "card":
			inField = f
		}
	}
	if inMessage == nil {
		t.Error("a secret in the message text was not found")
	}
	if inField == nil {
		t.Error("a secret in a structured field was not found")
	}

	// The sample must never be the raw value — a leak report that reprints the
	// leak is a second copy of it.
	for _, f := range rep.Findings {
		if strings.Contains(f.Sample, "4111111111111111") {
			t.Errorf("finding sample leaked the raw value: %q", f.Sample)
		}
	}

	// The suggested fix has to be one that works here. A log line has no JSON
	// path, so suggesting redact.json_fields would be advice that cannot help.
	if inMessage != nil {
		if !strings.Contains(inMessage.Suggest, "app_logs") {
			t.Errorf("suggestion does not point at app_logs config: %q", inMessage.Suggest)
		}
		if strings.Contains(inMessage.Suggest, "json_fields") {
			t.Errorf("suggested a JSON path for a free-text log line: %q", inMessage.Suggest)
		}
	}
	if inField != nil && !strings.Contains(inField.Suggest, "fields: [card]") {
		t.Errorf("a structured field should be fixable by name: %q", inField.Suggest)
	}
}

// A clean log line must not invent findings, and the count still has to be
// reported — "0 findings" means something different when nothing was read.
func TestScannerReportsLinesScannedEvenWithNoFindings(t *testing.T) {
	sc := NewScanner(time.Now().Add(-time.Hour))
	sc.AddAppLog(&ext.AppLog{Time: time.Now(), Service: "api", Level: "info", Message: "order placed"})
	rep := sc.Report()
	if len(rep.Findings) != 0 {
		t.Errorf("invented %d finding(s) from a clean line", len(rep.Findings))
	}
	if rep.LinesScanned != 1 {
		t.Errorf("LinesScanned = %d, want 1", rep.LinesScanned)
	}
}
