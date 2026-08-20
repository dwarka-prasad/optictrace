// Package cli is the optictrace command line, exposed as a package so a
// binary built elsewhere can be optictrace plus something extra rather than a
// reimplementation of it.
//
// That is the whole reason this is not just cmd/optictrace/main.go: a
// distribution that adds licensed features needs every subcommand, flag and
// exit code to behave identically, and the only way to guarantee that is to
// run the same code. Register extensions with the ext package, then call Run.
//
//	func main() {
//		if lic.Allows("audit") {
//			audit.Install(...)
//		}
//		cli.Run(os.Args[1:], version)
//	}
//
// Run calls os.Exit, matching the behaviour a command line needs; it does not
// return.
//
// The command set:
//
//	optictrace run      -config optic.yaml   start proxy + admin/metrics server
//	optictrace validate -config optic.yaml   lint the config (CI-friendly)
//	optictrace version
//
// Hot reload: SIGHUP or POST /api/reload re-reads optic.yaml and swaps the
// rule engine atomically; in-flight requests finish under their old policy.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/dwarka-prasad/optictrace/ext"
	"github.com/dwarka-prasad/optictrace/internal/admin"
	"github.com/dwarka-prasad/optictrace/internal/applog"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/export"
	"github.com/dwarka-prasad/optictrace/internal/metrics"
	"github.com/dwarka-prasad/optictrace/internal/mock"
	"github.com/dwarka-prasad/optictrace/internal/proxy"
	"github.com/dwarka-prasad/optictrace/internal/replay"
	"github.com/dwarka-prasad/optictrace/internal/review"
	"github.com/dwarka-prasad/optictrace/internal/ruletest"
	"github.com/dwarka-prasad/optictrace/internal/scaffold"
	"github.com/dwarka-prasad/optictrace/internal/scan"
	"github.com/dwarka-prasad/optictrace/internal/spans"
	"github.com/dwarka-prasad/optictrace/internal/spec"
	"github.com/dwarka-prasad/optictrace/internal/store"
	"github.com/dwarka-prasad/optictrace/internal/suggest"
)

// version is set by Run. Package-level because the subcommands below read it
// for `optictrace version` and for the admin server's /api/system.
var version = "dev"

// Run executes one command. args excludes the program name; ver is stamped by
// the caller's build so a repackaged binary reports its own version.
func Run(args []string, ver string) {
	if ver != "" {
		version = ver
	}
	cmd := "run"
	if len(args) > 0 && !isFlag(args[0]) {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "optic.yaml", "path to optic.yaml")
	uiDir := fs.String("ui", "ui/out", "static dashboard directory (optional)")
	execCmd := fs.String("exec", "", "run: start this command and collect its stdout/stderr as application logs")
	initService := fs.String("service", "", "init: service name (default: the spec's title)")
	initListen := fs.String("proxy-listen", "", "init: sidecar listen address, e.g. :8080")
	initUpstream := fs.String("upstream", "", "init: upstream URL to forward to")
	initLow := fs.Bool("include-low", false, "init: also mask low-confidence names (name, first_name)")
	specPath := fs.String("spec", "", "OpenAPI spec file (check/mock/sdk)")
	outPath := fs.String("out", "", "output file (spec/sdk); default stdout")
	window := fs.Duration("window", 24*time.Hour, "traffic window to analyze (spec/check)")
	lang := fs.String("lang", "typescript", "SDK language (sdk)")
	listen := fs.String("listen", ":7070", "mock server listen address (mock)")
	ai := fs.Bool("ai", false, "mock: generate responses with Claude when ANTHROPIC_API_KEY is set")
	testsPath := fs.String("tests", "optic.test.yaml", "rule test file (test)")
	failOn := fs.String("fail-on", "high", "scan: severity that exits non-zero (critical|high|medium|never);\n\treview: regression|critical|high|never (default regression via -review-fail-on)")
	reviewFailOn := fs.String("review-fail-on", "regression", "review: what fails the check — regression (this PR only), critical, high, never")
	purgeLabel := fs.String("label", "", "purge: consumer label name (default: telemetry.billing.consumer_label)")
	purgeValue := fs.String("value", "", "purge: consumer label value to erase")
	olderThan := fs.Duration("older-than", 0, "purge: only delete records older than this (default: all)")
	yes := fs.Bool("yes", false, "purge: skip the interactive confirmation (for automation)")
	replayTarget := fs.String("target", "", "replay: base URL to replay captured traffic against")
	rate := fs.Float64("rate", 0, "replay: requests per second (0 = as fast as possible)")
	concurrency := fs.Int("concurrency", 4, "replay: parallel in-flight requests")
	dryRun := fs.Bool("dry-run", false, "replay: report what would be sent without sending")
	applyOut := fs.String("apply", "", "suggest: write proposed rules to this file instead of stdout")
	baseConfig := fs.String("base-config", "", "review: optic.yaml from the base branch, to diff governance against")
	fromAgent := fs.String("from", "", "review: pull traffic from a running agent's URL instead of a local store")
	fromFile := fs.String("from-file", "", "review: read traffic from a JSONL export instead of a store")
	token := fs.String("token", "", "review: bearer token for -from (or OPTICTRACE_TOKEN)")
	_ = fs.Parse(args)

	switch cmd {
	case "run":
		run(*configPath, *uiDir, *execCmd)
	case "validate":
		validate(*configPath)
	case "spec":
		specGenerate(*configPath, *window, *outPath)
	case "check":
		specCheck(*configPath, *specPath, *window)
	case "sdk":
		sdkGenerate(*configPath, *specPath, *window, *lang, *outPath)
	case "mock":
		mockServe(*specPath, *listen, *ai)
	case "scan":
		scanTraffic(*configPath, *window, *failOn)
	case "test":
		ruleTest(*configPath, *testsPath)
	case "purge":
		purge(*configPath, *purgeLabel, *purgeValue, *olderThan, *yes)
	case "replay":
		replayTraffic(*configPath, *window, *replayTarget, *rate, *concurrency, *dryRun)
	case "suggest":
		suggestRules(*configPath, *window, *applyOut)
	case "review":
		reviewChanges(reviewArgs{
			configPath: *configPath, baseConfig: *baseConfig, specPath: *specPath,
			from: *fromAgent, fromFile: *fromFile, token: *token,
			window: *window, out: *outPath, failOn: *reviewFailOn,
		})
	case "init":
		initConfig(*specPath, *outPath, *initService, *initListen, *initUpstream, *initLow)
	case "version":
		fmt.Println("optictrace", version)
	default:
		fmt.Fprintf(os.Stderr,
			"unknown command %q\n  (init, run, validate, test, scan, suggest, review, purge,\n   replay, spec, check, sdk, mock, version)\n", cmd)
		os.Exit(2)
	}
}

// purge deletes stored telemetry for one consumer — the erasure-request
// primitive ("delete everything you hold for tenant X"). Deliberately a
// separate command with a confirmation step rather than an API call: this is
// irreversible, and a stray HTTP request should not be able to trigger it.
func purge(configPath, label, value string, olderThan time.Duration, assumeYes bool) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	if cfg.Telemetry.Store.Driver == "none" {
		fmt.Fprintln(os.Stderr, "✗ purge needs a payload store (sqlite or postgres)")
		os.Exit(1)
	}
	if label == "" {
		label = "tenant"
		if cfg.Telemetry.Billing != nil {
			label = cfg.Telemetry.Billing.ConsumerLabel
		}
	}
	if value == "" {
		fmt.Fprintln(os.Stderr, "✗ purge requires -value <consumer> (optionally -label <name>)")
		os.Exit(2)
	}

	st, err := openStore(&cfg.Telemetry.Store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ open store: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	var before time.Time
	scope := "all records"
	if olderThan > 0 {
		before = time.Now().Add(-olderThan)
		scope = fmt.Sprintf("records older than %s", olderThan)
	}

	// Count first so the operator sees the blast radius before confirming.
	usage, err := st.UsageByLabel(context.Background(), time.Time{}, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	var held int64
	for _, u := range usage {
		if u.Consumer == value {
			held = u.Requests
		}
	}
	fmt.Printf("About to delete %s where %s=%q (store currently holds %d record(s) for it).\n",
		scope, label, value, held)
	if !assumeYes {
		fmt.Print("This cannot be undone. Type the consumer name to confirm: ")
		var typed string
		_, _ = fmt.Scanln(&typed)
		if typed != value {
			fmt.Fprintln(os.Stderr, "✗ aborted — confirmation did not match")
			os.Exit(1)
		}
	}
	removed, err := st.Purge(context.Background(), label, value, before)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✓ purged %d record(s) for %s=%q\n", removed, label, value)
}

// replayTraffic re-issues captured traffic against a target. Governed records
// cannot reproduce redacted or restricted payloads, so the summary reports
// what was skipped rather than pretending to full fidelity.
func replayTraffic(configPath string, window time.Duration, target string,
	rate float64, concurrency int, dryRun bool) {

	if target == "" {
		fmt.Fprintln(os.Stderr, "✗ replay requires -target <base-url>")
		os.Exit(2)
	}
	_, records := loadTraffic(configPath, window)
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "✗ no traffic captured in this window — nothing to replay")
		os.Exit(1)
	}
	sum, err := replay.Run(context.Background(), records, replay.Options{
		Target: target, RatePerSec: rate, Concurrency: concurrency, DryRun: dryRun,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	verb := "replayed"
	if dryRun {
		verb = "would replay"
	}
	fmt.Printf("%s %d/%d record(s) against %s in %s\n",
		verb, sum.Sent, sum.Total, target, sum.Elapsed.Round(time.Millisecond))
	if sum.Skipped > 0 {
		fmt.Printf("skipped %d:\n", sum.Skipped)
		for reason, n := range sum.SkipReason {
			fmt.Printf("  %d × %s\n", n, reason)
		}
	}
	if !dryRun {
		fmt.Printf("status match: %d · diverged: %d · failed: %d\n", sum.Matched, sum.Diverged, sum.Failed)
		for _, d := range sum.Diffs {
			if d.Err != nil {
				fmt.Printf("  ✗ %s %s — %v\n", d.Method, d.Path, d.Err)
			} else {
				fmt.Printf("  ⚠ %s %s — was %d, now %d\n", d.Method, d.Path, d.OriginalCode, d.ReplayedCode)
			}
		}
	}
	if sum.Failed > 0 {
		os.Exit(1)
	}
}

// suggestRules proposes governance for fields whose NAMES look sensitive —
// the complement to scan, which inspects values.
func suggestRules(configPath string, window time.Duration, applyOut string) {
	cfg, records := loadTraffic(configPath, window)
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "✗ no traffic captured in this window — nothing to analyse")
		os.Exit(1)
	}
	report := suggest.Records(records, engine.New(cfg))
	actionable := report.Actionable()

	if len(actionable) == 0 {
		fmt.Printf("✓ analysed %d record(s) — every sensitive-looking field is already governed\n",
			report.Scanned)
		return
	}
	icons := map[string]string{suggest.High: "✗", suggest.Medium: "⚠", suggest.Low: "·"}
	for _, s := range actionable {
		fmt.Printf("%s [%s] %s %q on %s\n", icons[s.Confidence], s.Confidence, s.Kind, s.Field, s.Route)
		fmt.Printf("    %s (seen %d×)\n", s.Why, s.Seen)
	}
	governed := len(report.Suggestions) - len(actionable)
	fmt.Printf("\n%d suggestion(s); %d sensitive-looking field(s) already covered by your rules\n",
		len(actionable), governed)

	yaml := report.YAML()
	if applyOut != "" {
		writeOut(applyOut, []byte(yaml))
		fmt.Fprintln(os.Stderr, "  review these rules before merging them into optic.yaml")
		return
	}
	fmt.Printf("\n--- proposed optic.yaml rules ---\n%s", yaml)
}

type reviewArgs struct {
	configPath, baseConfig, specPath string
	from, fromFile, token            string
	window                           time.Duration
	out, failOn                      string
}

// reviewChanges produces the pull-request comment: coverage, what this change
// does to governance versus the base branch, leaks, and breaking changes.
func reviewChanges(a reviewArgs) {
	headCfg, err := config.Load(a.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}

	// Traffic can come from a running agent (the CI case), a JSONL export,
	// or a local store.
	var records []store.Record
	switch {
	case a.from != "":
		tok := a.token
		if tok == "" {
			tok = os.Getenv("OPTICTRACE_TOKEN")
		}
		records, err = review.FetchRemote(a.from, tok, a.window.String(), 90*time.Second)
	case a.fromFile != "":
		records, err = review.LoadJSONL(a.fromFile)
	default:
		_, records = loadTraffic(a.configPath, a.window)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "✗ no captured traffic to review — point -from at an agent watching staging, or pass -from-file")
		os.Exit(1)
	}

	opts := review.Options{Records: records, Head: headCfg, Window: a.window.String()}
	// Application log lines from the same window, when the local store has
	// them. A remote or file-based review has records only, which is reported
	// rather than hidden: the report prints how many lines it read.
	if a.from == "" && a.fromFile == "" {
		opts.AppLogs = loadAppLogs(headCfg, a.window)
	}
	if a.baseConfig != "" {
		// A missing base config is not fatal: on the first PR that adds
		// optic.yaml there is nothing to diff against, and failing there
		// would be hostile.
		if baseCfg, err := config.Load(a.baseConfig); err != nil {
			fmt.Fprintf(os.Stderr, "· no base policy to compare against (%v); reporting coverage only\n", err)
		} else {
			opts.Base = baseCfg
		}
	}
	if a.specPath != "" {
		if raw, err := os.ReadFile(a.specPath); err == nil {
			if doc, err := spec.Parse(raw); err == nil {
				opts.Spec = doc
			}
		}
	}

	rep := review.Run(opts)
	md := rep.Markdown()
	if a.out != "" {
		writeOut(a.out, []byte(md))
	} else {
		fmt.Print(md)
	}
	fmt.Fprintln(os.Stderr, rep.Summary())

	if rep.Blocking(a.failOn) {
		os.Exit(1)
	}
}

// scanTraffic is the safety net: it looks for values that LOOK sensitive in
// records that already passed governance — the field you forgot to declare.
func scanTraffic(configPath string, window time.Duration, failOn string) {
	cfg, records := loadTraffic(configPath, window)
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "✗ no traffic captured in this window — nothing to scan")
		os.Exit(1)
	}
	custom, err := cfg.Detectors()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	sc := scan.NewScannerWith(time.Now().Add(-window), custom)
	for i := range records {
		sc.Add(&records[i])
	}
	// And the application log lines, which are the riskier surface: a payload
	// is structured and can be masked by JSON path, a log line is free text
	// written by whoever was debugging that day.
	scanAppLogs(sc, cfg, window)
	report := sc.Report()
	crit, high, med := report.Counts()

	if len(report.Findings) == 0 {
		fmt.Printf("✓ scanned %s over %s — no sensitive values found outside your rules\n",
			scannedSummary(report), window)
		return
	}

	icons := map[string]string{scan.SevCritical: "✗", scan.SevHigh: "⚠", scan.SevMedium: "·"}
	for _, f := range report.Findings {
		fmt.Printf("%s [%s] %s in %s %s → %s.%s\n",
			icons[f.Severity], f.Severity, f.Kind, f.Method, f.Route, f.Location, f.Field)
		fmt.Printf("    %s · seen %d× (last %s ago) · sample %s\n",
			f.Why, f.Count, ago(f.LastAt), f.Sample)
		fmt.Printf("    fix: %s\n\n", strings.ReplaceAll(f.Suggest, "\n", "\n         "))
	}
	fmt.Printf("scanned %s: %d critical, %d high, %d medium\n",
		scannedSummary(report), crit, high, med)

	if failOn != "never" && report.HasAtLeast(failOn) {
		fmt.Fprintf(os.Stderr, "\n✗ sensitive data found at or above severity %q\n", failOn)
		os.Exit(1)
	}
}

// ruleTest asserts optic.yaml behaves as intended, without a running server.
func ruleTest(configPath, testsPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	cases, err := ruletest.Load(testsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	res := ruletest.Run(engine.New(cfg), cases)

	for _, f := range res.Failures {
		fmt.Printf("✗ %s\n    %s\n      want: %s\n      got:  %s\n", f.Case, f.Assert, f.Want, f.Got)
	}
	if len(res.Failures) == 0 {
		fmt.Printf("✓ %d/%d rule test(s) passed against %s\n", res.Passed, res.Total, configPath)
		return
	}
	fmt.Fprintf(os.Stderr, "\n✗ %d/%d passed — %d assertion(s) failed\n",
		res.Passed, res.Total, len(res.Failures))
	os.Exit(1)
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

// loadTraffic opens the configured store read-only and pulls the window.
// scannedSummary names what was actually read. "0 findings" over 0 log lines
// means something very different from 0 findings over 40,000 of them, and the
// difference is invisible unless it is printed.
func scannedSummary(r *scan.Report) string {
	if r.LinesScanned == 0 {
		return fmt.Sprintf("%d record(s)", r.Scanned)
	}
	return fmt.Sprintf("%d record(s) and %d log line(s)", r.Scanned, r.LinesScanned)
}

// scanAppLogs feeds stored application log lines to the scanner. A store
// driver without app-log support, or a config with the feature off, simply
// contributes nothing — this is an optional surface, not a required one.
// loadAppLogs reads stored application log lines for a window. Returns nothing
// when the feature is off or the driver has no app-log support — this is an
// optional surface, not a required one.
func loadAppLogs(cfg *config.Config, window time.Duration) []ext.AppLog {
	if cfg == nil || cfg.Telemetry.AppLogs == nil || !cfg.Telemetry.AppLogs.Enabled {
		return nil
	}
	st, err := openStore(&cfg.Telemetry.Store)
	if err != nil {
		return nil
	}
	defer st.Close()
	als, ok := st.(store.AppLogStore)
	if !ok {
		return nil
	}
	var out []ext.AppLog
	limit := store.AnalysisLimit(cfg.Telemetry.Store.AnalysisMaxRows)
	since := time.Now().Add(-window)
	for len(out) < limit {
		lines, total, err := als.QueryAppLogs(context.Background(), store.AppLogFilter{
			Since: since, Limit: 500, Offset: len(out),
		})
		if err != nil || len(lines) == 0 {
			break
		}
		out = append(out, lines...)
		if int64(len(out)) >= total {
			break
		}
	}
	return out
}

func scanAppLogs(sc *scan.Scanner, cfg *config.Config, window time.Duration) {
	if cfg == nil || cfg.Telemetry.AppLogs == nil || !cfg.Telemetry.AppLogs.Enabled {
		return
	}
	st, err := openStore(&cfg.Telemetry.Store)
	if err != nil {
		return
	}
	defer st.Close()
	als, ok := st.(store.AppLogStore)
	if !ok {
		return
	}
	since := time.Now().Add(-window)
	limit := store.AnalysisLimit(cfg.Telemetry.Store.AnalysisMaxRows)
	for offset := 0; offset < limit; {
		lines, total, err := als.QueryAppLogs(context.Background(), store.AppLogFilter{
			Since: since, Limit: 500, Offset: offset,
		})
		if err != nil || len(lines) == 0 {
			return
		}
		for i := range lines {
			sc.AddAppLog(&lines[i])
		}
		offset += len(lines)
		if int64(offset) >= total {
			return
		}
	}
}

// hasStdoutSource reports whether the config already declares one, so -exec
// does not add a duplicate.
func hasStdoutSource(sources []config.AppLogSource) bool {
	for _, s := range sources {
		if s.Type == "stdout" {
			return true
		}
	}
	return false
}

// startChild runs a command with `sh -c`, collecting its output.
//
// The output is ALSO echoed to this process's own stdout/stderr: collecting a
// service's logs must not stop them reaching wherever its operators already
// read them. A collector that silently swallows logs is worse than no
// collector.
func startChild(command string, collector *applog.Collector, sources []config.AppLogSource,
	logger *slog.Logger) <-chan int {

	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = os.Stdin

	src := config.AppLogSource{Type: "stdout"}
	for _, s := range sources {
		if s.Type == "stdout" {
			src = s
			break
		}
	}

	if collector == nil {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	} else {
		outPipe, err := cmd.StdoutPipe()
		if err != nil {
			logger.Error("cannot capture child stdout", "error", err)
			return nil
		}
		errPipe, err := cmd.StderrPipe()
		if err != nil {
			logger.Error("cannot capture child stderr", "error", err)
			return nil
		}
		go collector.Read(context.Background(), outPipe, src, os.Stdout)
		go collector.Read(context.Background(), errPipe, src, os.Stderr)
	}

	if err := cmd.Start(); err != nil {
		logger.Error("cannot start -exec command", "command", command, "error", err)
		os.Exit(1)
	}
	logger.Info("started child process", "command", command, "pid", cmd.Process.Pid)

	// The child is the reason this agent is running: if it exits, staying up
	// would leave a proxy in front of nothing. But it must NOT exit from here.
	// os.Exit in a goroutine skips the shutdown path, and the shutdown path is
	// what drains collected log lines — so the last lines of a crashing
	// process, which are the ones worth having, would be lost. Report the code
	// and let the main loop shut down properly.
	done := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			code = 1
		}
		logger.Info("child process exited", "code", code)
		done <- code
	}()
	return done
}

// initConfig scaffolds an optic.yaml from an OpenAPI or Swagger document.
//
// The bootstrap problem: governance is otherwise written by hand against an API
// you may not have written, and the gaps only surface once traffic flows. A
// specification already lists the routes and payload shapes, so most of a first
// draft can be derived rather than guessed.
func initConfig(specPath, outPath, service, listen, upstream string, includeLow bool) {
	if specPath == "" {
		fmt.Fprintln(os.Stderr, "✗ -spec is required: point it at an OpenAPI or Swagger document\n"+
			"  optictrace init -spec openapi.yaml -out optic.yaml")
		os.Exit(2)
	}
	raw, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	doc, err := scaffold.Parse(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %s: %v\n", specPath, err)
		os.Exit(1)
	}
	res := scaffold.Generate(doc, scaffold.Options{
		ServiceName: service, Listen: listen, Upstream: upstream, IncludeLow: includeLow,
	})

	// Validate what was generated before handing it over. A scaffolding tool
	// that emits a file the agent then refuses is worse than no tool: it
	// teaches people the config format is unreliable.
	cfg, err := config.Parse([]byte(res.YAML))
	if err == nil {
		err = cfg.Validate()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ generated config did not validate — this is a bug in `init`, "+
			"please report it with the spec that caused it:\n  %v\n", err)
		os.Exit(1)
	}

	if outPath == "" {
		fmt.Print(res.YAML)
	} else {
		// Never clobber: an existing optic.yaml is a reviewed policy, and
		// overwriting it from a spec would silently discard hand-written rules.
		if _, err := os.Stat(outPath); err == nil {
			fmt.Fprintf(os.Stderr, "✗ %s already exists — refusing to overwrite a reviewed policy.\n"+
				"  Write elsewhere with -out, or delete it deliberately.\n", outPath)
			os.Exit(1)
		}
		if err := os.WriteFile(outPath, []byte(res.YAML), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ wrote %s — %d route(s), %d rule(s), %d field(s) masked\n",
			outPath, res.Routes, res.Rules, res.MaskedFields)
	}

	// To stderr, so `optictrace init -spec x.yaml > optic.yaml` still produces a
	// clean file while the caveats stay visible.
	if len(res.Notes) > 0 {
		fmt.Fprintln(os.Stderr, "\nBefore trusting this:")
		for _, n := range res.Notes {
			fmt.Fprintf(os.Stderr, "  · %s\n", n)
		}
	}
}

func loadTraffic(configPath string, window time.Duration) (*config.Config, []store.Record) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	if cfg.Telemetry.Store.Driver == "none" {
		fmt.Fprintln(os.Stderr, "✗ this command needs a payload store (telemetry.store.driver: sqlite or postgres)")
		os.Exit(1)
	}
	st, err := openStore(&cfg.Telemetry.Store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ open store: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()
	limit := cfg.Telemetry.Store.AnalysisMaxRows
	records, err := st.Recent(context.Background(), time.Now().Add(-window), limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ query store: %v\n", err)
		os.Exit(1)
	}
	// Silent truncation would read as "analysed everything" when it did not.
	if len(records) == store.AnalysisLimit(limit) {
		fmt.Fprintf(os.Stderr,
			"! reached the %d-record analysis limit — older traffic in this window was not read.\n"+
				"  Narrow -window, or raise telemetry.store.analysis_max_rows.\n",
			len(records))
	}
	return cfg, records
}

func specGenerate(configPath string, window time.Duration, out string) {
	cfg, records := loadTraffic(configPath, window)
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "✗ no traffic captured in this window — nothing to infer")
		os.Exit(1)
	}
	doc := spec.Infer(cfg.Service.Name, records)
	raw, err := doc.YAML()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	writeOut(out, raw)
	fmt.Fprintf(os.Stderr, "✓ inferred spec from %d records: %d path(s)\n", len(records), len(doc.Paths))
}

func specCheck(configPath, specPath string, window time.Duration) {
	if specPath == "" {
		fmt.Fprintln(os.Stderr, "✗ check requires -spec <openapi.yaml>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	doc, err := spec.Parse(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	_, records := loadTraffic(configPath, window)
	findings := spec.Check(doc, records)

	if len(findings) == 0 {
		fmt.Printf("✓ %s matches all %d observed request(s) — no divergence\n", specPath, len(records))
		return
	}
	icons := map[string]string{"breaking": "✗", "warn": "⚠", "info": "·"}
	for _, f := range findings {
		fmt.Printf("%s [%s] %s\n", icons[f.Severity], f.Severity, f.Message)
	}
	if spec.HasBreaking(findings) {
		fmt.Fprintf(os.Stderr, "\n✗ breaking divergence: this spec does not cover live traffic (checked %d records over %s)\n", len(records), window)
		os.Exit(1)
	}
	fmt.Printf("\n✓ no breaking findings (%d records over %s)\n", len(records), window)
}

func sdkGenerate(configPath, specPath string, window time.Duration, lang, out string) {
	switch lang {
	case "typescript", "ts", "python", "py", "go":
	default:
		fmt.Fprintf(os.Stderr, "✗ unsupported -lang %q (available: typescript, python, go)\n", lang)
		os.Exit(2)
	}
	var doc *spec.Spec
	if specPath != "" {
		raw, err := os.ReadFile(specPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
			os.Exit(1)
		}
		if doc, err = spec.Parse(raw); err != nil {
			fmt.Fprintf(os.Stderr, "✗ %v\n", err)
			os.Exit(1)
		}
	} else {
		cfg, records := loadTraffic(configPath, window)
		if len(records) == 0 {
			fmt.Fprintln(os.Stderr, "✗ no traffic to infer from; pass -spec to generate from a spec file")
			os.Exit(1)
		}
		doc = spec.Infer(cfg.Service.Name, records)
	}
	var code, label string
	switch lang {
	case "python", "py":
		code, label = spec.GeneratePython(doc), "Python"
	case "go":
		code, label = spec.GenerateGo(doc, "apiclient"), "Go"
	default:
		code, label = spec.GenerateTypeScript(doc), "TypeScript"
	}
	writeOut(out, []byte(code))
	fmt.Fprintf(os.Stderr, "✓ generated %s client for %d path(s)\n", label, len(doc.Paths))
}

func mockServe(specPath, listen string, ai bool) {
	if specPath == "" {
		fmt.Fprintln(os.Stderr, "✗ mock requires -spec <openapi.yaml>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	doc, err := spec.Parse(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	srv := mock.New(doc, logger, mock.Options{AI: ai})
	logger.Info("mock server listening", "listen", listen, "paths", len(doc.Paths),
		"stateful", true, "ai", srv.AIEnabled())
	if err := http.ListenAndServe(listen, srv); err != nil {
		logger.Error("mock server failed", "error", err)
		os.Exit(1)
	}
}

func writeOut(path string, data []byte) {
	if path == "" || path == "-" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "✗ %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "✓ wrote %s (%d bytes)\n", path, len(data))
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

// openStore resolves the configured driver. Both implementations satisfy the
// same LogStore contract, enforced by the conformance suite in internal/store.
// scanDetectors compiles the org-specific scan detectors. Validate already
// proved they compile, so a failure here means the file changed underneath us;
// log it and carry on with the built-ins rather than refusing to serve.
func scanDetectors(cfg *config.Config, logger *slog.Logger) []scan.Detector {
	dets, err := cfg.Detectors()
	if err != nil {
		logger.Error("ignoring scan.detectors", "error", err)
		return nil
	}
	return dets
}

func openStore(cfg *config.StoreCfg) (store.LogStore, error) {
	switch cfg.Driver {
	case "postgres":
		return store.NewPostgres(cfg.DSN)
	case "clickhouse":
		return store.NewClickHouse(cfg.DSN)
	case "sqlite", "":
		return store.NewSQLite(cfg.DSN)
	default:
		// An out-of-tree driver registered via ext.RegisterStore. Validate
		// already accepted the name on that basis, so a miss here means the
		// registry changed after the config was loaded.
		open, ok := ext.LookupStore(cfg.Driver)
		if !ok {
			return nil, fmt.Errorf("no store driver registered as %q", cfg.Driver)
		}
		return open(cfg.DSN, cfg.Settings)
	}
}

func validate(path string) {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("✓ %s is valid — service %q, %d rule(s), %d custom label(s)\n",
		path, cfg.Service.Name, len(cfg.Rules), len(engine.New(cfg).LabelKeys()))
	// Not an error: a config for embedded middleware has neither address. But
	// having one without the other is almost always an omission, and finding
	// out at `run` is worse than finding out here.
	if err := cfg.RequireProxyAddrs(); err != nil &&
		(cfg.Service.Listen != "" || cfg.Service.Upstream != "") {
		fmt.Printf("  note: %v — fine for embedded middleware, but `optictrace run` will refuse this\n", err)
	}
	if cfg.Telemetry.Auth.Resolve() == "" && cfg.Telemetry.AdminReachable() {
		fmt.Printf("  note: telemetry.admin_listen %q is reachable beyond loopback and telemetry.auth is not set —\n"+
			"        anyone who can reach that port can read every captured payload\n",
			cfg.Telemetry.AdminListen)
	}
}

// resolveUIDir finds the dashboard build.
//
// The -ui default is relative to the WORKING DIRECTORY, so running the agent
// from anywhere but the repo root used to serve the "dashboard build not
// found" page with no hint about where it had looked. A released binary sits
// beside its assets, so fall back to paths relative to the executable before
// giving up — and when giving up, say which paths were tried.
func resolveUIDir(flagValue string, logger *slog.Logger) string {
	tried := []string{}
	check := func(p string) bool {
		if p == "" {
			return false
		}
		tried = append(tried, p)
		st, err := os.Stat(p)
		return err == nil && st.IsDir()
	}
	if check(flagValue) {
		return flagValue
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		// bin/optictrace -> ../ui/out is the source layout; ./ui/out is how a
		// release tarball is laid out.
		for _, cand := range []string{
			filepath.Join(dir, "ui", "out"),
			filepath.Join(dir, "..", "ui", "out"),
		} {
			if check(cand) {
				abs, _ := filepath.Abs(cand)
				logger.Info("dashboard build found next to the binary", "ui_dir", abs)
				return cand
			}
		}
	}
	logger.Warn("no dashboard build found — the admin API still works, "+
		"but / will serve a status page instead of the dashboard "+
		"(build it with `make ui`, or pass -ui <dir>)",
		"tried", strings.Join(tried, ", "))
	return ""
}

func run(configPath, uiDir, execCmd string) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	uiDir = resolveUIDir(uiDir, logger)

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	// Two ways to run. As a SIDECAR the agent proxies traffic, and both
	// addresses are required — without this an omitted service.listen reaches
	// net/http as Addr:"" and binds port 80.
	//
	// As a COLLECTOR it proxies nothing: framework SDKs govern in-process and
	// POST governed records to /api/ingest, so there is no upstream to name.
	// Requiring a listen/upstream there would mean inventing a dummy proxy
	// nobody talks to, which is a workaround, not a configuration.
	collectorOnly := cfg.Service.Listen == "" && cfg.Service.Upstream == ""
	if !collectorOnly {
		if err := cfg.RequireProxyAddrs(); err != nil {
			logger.Error("invalid configuration", "error", err)
			os.Exit(1)
		}
	}
	eng := engine.New(cfg)

	// --- metrics -------------------------------------------------------
	var collector *metrics.Collector
	if config.Bool(cfg.Telemetry.Metrics.Enabled) {
		collector = metrics.New(cfg.Service.Name, cfg.Telemetry.Metrics.Buckets,
			eng.LabelKeys(), cfg.Telemetry.Metrics.LabelValueCap())
	}

	// --- payload store ---------------------------------------------------
	var reader store.LogStore
	var writer *store.AsyncWriter
	if cfg.Telemetry.Store.Driver != "none" {
		sqlStore, err := openStore(&cfg.Telemetry.Store)
		if err != nil {
			logger.Error("failed to open store", "driver", cfg.Telemetry.Store.Driver, "error", err)
			os.Exit(1)
		}
		reader = sqlStore
		var asyncOpts []store.AsyncOption
		if collector != nil {
			asyncOpts = append(asyncOpts, store.WithDropCallback(collector.StoreDropped))
		}
		asyncOpts = append(asyncOpts, store.WithRetention(cfg.Telemetry.Store.RetentionMaxRows),
			store.WithMaxAge(cfg.Telemetry.Store.MaxAge()))
		if al := cfg.Telemetry.AppLogs; al != nil && al.RetentionMaxAge > 0 {
			asyncOpts = append(asyncOpts, store.WithAppLogMaxAge(al.RetentionMaxAge))
		}
		if sp := cfg.Telemetry.Spans; sp != nil && sp.RetentionMaxAge > 0 {
			asyncOpts = append(asyncOpts, store.WithSpanMaxAge(sp.RetentionMaxAge))
		}
		writer = store.NewAsyncWriter(sqlStore, cfg.Telemetry.Store.QueueSize, logger, asyncOpts...)
		logger.Info("payload store ready", "driver", cfg.Telemetry.Store.Driver)
	}

	// --- application logs -------------------------------------------------
	// Two independent things have to be true for this to work: the policy has
	// to be on, and the driver has to support it. They fail differently, so
	// they are reported differently — "your config is off" and "your driver
	// cannot do this" look identical from the endpoint otherwise.
	appLogs, err := applog.New(cfg.Telemetry.AppLogs)
	if err != nil {
		logger.Error("invalid app-log policy", "error", err)
		os.Exit(1)
	}
	// Per-rule `logs:` blocks tighten the global policy for the routes they
	// match. Compiled here rather than per line, and only ever narrowing.
	if err := appLogs.WithRules(cfg.Rules); err != nil {
		logger.Error("invalid per-rule app-log policy", "error", err)
		os.Exit(1)
	}
	var appLogStore store.AppLogStore
	if appLogs.Enabled() {
		if als, ok := reader.(store.AppLogStore); ok {
			appLogStore = als
			logger.Info("application logs enabled",
				"level_min", cfg.Telemetry.AppLogs.LevelMin,
				"drop_orphans", cfg.Telemetry.AppLogs.DropOrphanLines())
		} else {
			logger.Warn("application logs are enabled but the store driver does not support them — "+
				"lines will be refused",
				"driver", cfg.Telemetry.Store.Driver)
		}
	}

	// --- inner spans ------------------------------------------------------
	// Same two independent conditions as app logs, reported the same way: the
	// policy has to be on and the driver has to support it, and "your config
	// is off" must not look like "your driver cannot do this".
	spanGov, err := spans.New(cfg.Telemetry.Spans)
	if err != nil {
		logger.Error("invalid span policy", "error", err)
		os.Exit(1)
	}
	var spanStore store.SpanStore
	if spanGov.Enabled() {
		if ss, ok := reader.(store.SpanStore); ok {
			spanStore = ss
			logger.Info("inner spans enabled",
				"min_duration", cfg.Telemetry.Spans.MinDuration,
				"max_per_request", cfg.Telemetry.Spans.MaxPerRequest,
				"drop_orphans", cfg.Telemetry.Spans.DropOrphanSpans())
		} else {
			logger.Warn("inner spans are enabled but the store driver does not support them — "+
				"spans will be refused",
				"driver", cfg.Telemetry.Store.Driver)
		}
	}

	// --- application-log collection ---------------------------------------
	// Sources read what the application already writes, so a service that logs
	// JSON to stdout needs no code change. Started before the child process so
	// its first lines are not missed.
	var logCollector *applog.Collector
	// Closed when an -exec child exits, carrying its status so this process can
	// mirror it after shutting down cleanly.
	var childExit <-chan int
	if appLogs.Enabled() && appLogStore != nil {
		cfgSources := cfg.Telemetry.AppLogs.Sources
		if execCmd != "" && !hasStdoutSource(cfgSources) {
			// -exec without a declared stdout source is unambiguous: the point
			// of -exec is to collect that process's output.
			cfgSources = append(cfgSources, config.AppLogSource{Type: "stdout"})
		}
		if len(cfgSources) > 0 {
			logCollector = applog.NewCollector(appLogs, appLogStore, cfg.Service.Name, logger)
			if collector != nil {
				// Same counters as the ingest endpoint, so a drop is visible
				// however the line arrived.
				logCollector.OnDrop(func(reason string) { collector.AppLogDropped(reason, 1) })
				logCollector.OnKeep(collector.AppLogStored)
			}
			logCollector.Start(context.Background())
			for _, src := range cfgSources {
				// A line with no span is an orphan, and orphans are dropped by
				// default. For a text source without a span_pattern that is
				// EVERY line, which looks like a broken collector rather than a
				// working policy — so say it at startup rather than leaving
				// someone to find an empty dashboard and a drop counter.
				if src.Format == "text" && src.SpanPattern == "" && cfg.Telemetry.AppLogs.DropOrphanLines() {
					logger.Warn("app-log source has format: text with no span_pattern — "+
						"its lines carry no span, so every one will be dropped as an orphan; "+
						"set span_pattern, use format: json, or set drop_orphans: false",
						"path", src.Path, "type", src.Type)
				}
				if src.Type == "file" {
					logger.Info("collecting application logs", "source", "file", "path", src.Path)
					logCollector.Tail(context.Background(), src)
				}
			}
			if execCmd != "" {
				childExit = startChild(execCmd, logCollector, cfgSources, logger)
			}
		}
	} else if execCmd != "" {
		logger.Warn("-exec given but application logs are not collectable — " +
			"set telemetry.app_logs.enabled and a store driver that supports them; " +
			"the command will still run, its output only echoed")
		childExit = startChild(execCmd, nil, nil, logger)
	}

	// --- output exporters (custom plugins) --------------------------------
	var dispatcher *export.Dispatcher
	if len(cfg.Telemetry.Exporters) > 0 {
		var expMetrics export.Metrics
		if collector != nil {
			expMetrics = collector
		}
		dispatcher, err = export.New(cfg.Telemetry.Exporters, logger, expMetrics, cfg.Service.Name)
		if err != nil {
			logger.Error("failed to start exporters", "error", err)
			os.Exit(1)
		}
		logger.Info("exporters started", "count", len(cfg.Telemetry.Exporters))

		// Collected lines fan out to exporters too. Wired here rather than
		// where the collector is built, because the dispatcher does not exist
		// until now — an audit trail holding the requests but not the lines
		// those requests wrote is missing the riskier half.
		if logCollector != nil && dispatcher.AcceptsAppLogs() {
			logCollector.OnStored(func(lines []ext.AppLog) {
				for i := range lines {
					dispatcher.EnqueueAppLog(&lines[i])
				}
			})
		}
	}

	// --- proxy ----------------------------------------------------------
	var proxyOpts []proxy.Option
	if collector != nil {
		proxyOpts = append(proxyOpts, proxy.WithMetrics(collector))
	}
	if writer != nil {
		proxyOpts = append(proxyOpts, proxy.WithStore(writer))
	}
	if dispatcher != nil {
		proxyOpts = append(proxyOpts, proxy.WithExporters(dispatcher))
	}
	handler, interceptor, err := proxy.NewReverseProxy(cfg, eng, logger, proxyOpts...)
	if err != nil {
		logger.Error("failed to build proxy", "error", err)
		os.Exit(1)
	}

	// live tracks the config currently in effect, so a reload can report what
	// it could not apply. Only the reload closure touches it, and SIGHUP and
	// POST /api/reload are both serialized through reloadMu.
	live := cfg
	var reloadMu sync.Mutex
	reload := func() error {
		reloadMu.Lock()
		defer reloadMu.Unlock()

		newCfg, err := config.Load(configPath)
		if err != nil {
			logger.Error("reload rejected: config invalid", "error", err)
			return err
		}
		newEng := engine.New(newCfg)
		interceptor.SwapEngine(newEng)

		// A new `labels:` key has to become a real Prometheus dimension, which
		// means rebuilding the vectors — their label sets are immutable. Without
		// this the label appears in the dashboard but never in /metrics, and a
		// Grafana panel built on it stays empty with nothing to explain why.
		relabeled := false
		if collector != nil {
			relabeled = collector.SetLabelKeys(newEng.LabelKeys())
		}
		// Everything a reload cannot apply is named rather than discarded in
		// silence, which is how it behaved before.
		if stale := live.RestartRequired(newCfg); len(stale) > 0 {
			logger.Warn("reload applied rules only — these changes need a restart",
				"fields", strings.Join(stale, ", "))
		}
		live = newCfg
		logger.Info("configuration reloaded",
			"rules", len(newCfg.Rules), "metrics_relabeled", relabeled)
		return nil
	}

	// --- admin / metrics server ------------------------------------------
	adminSrv := &http.Server{
		Addr: cfg.Telemetry.AdminListen,
		Handler: (&admin.Server{
			Logger:          logger,
			Collector:       collector,
			Reader:          reader,
			Writer:          writer,
			Dispatcher:      dispatcher,
			ConfigPath:      configPath,
			Reload:          reload,
			UIDir:           uiDir,
			Version:         version,
			AuthToken:       cfg.Telemetry.Auth.Resolve(),
			HealthOpen:      cfg.Telemetry.Auth.HealthOpen(),
			CORSOrigins:     cfg.Telemetry.CORSOrigins,
			AnalysisMaxRows: cfg.Telemetry.Store.AnalysisMaxRows,
			Detectors:       scanDetectors(cfg, logger),
			AppLogs:         appLogs,
			AppLogStore:     appLogStore,
			Spans:           spanGov,
			SpanStore:       spanStore,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		tlsCfg := cfg.Telemetry.TLS
		logger.Info("admin server listening",
			"listen", cfg.Telemetry.AdminListen,
			"auth", cfg.Telemetry.Auth.Resolve() != "",
			"tls", tlsCfg != nil)
		if cfg.Telemetry.Auth.Resolve() == "" && cfg.Telemetry.AdminReachable() {
			// Loopback-only and unauthenticated is a reasonable local posture,
			// so only warn when the port actually accepts remote connections.
			logger.Warn("admin server is reachable beyond loopback WITHOUT authentication — "+
				"anyone who can reach this port can read every captured payload; "+
				"set telemetry.auth.token_env",
				"listen", cfg.Telemetry.AdminListen)
		}
		var err error
		if tlsCfg != nil {
			err = adminSrv.ListenAndServeTLS(tlsCfg.CertFile, tlsCfg.KeyFile)
		} else {
			err = adminSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("admin server failed", "error", err)
			os.Exit(1)
		}
	}()

	proxyHandler := handler
	if cfg.Service.HTTP2 {
		// Cleartext HTTP/2. Without this the listener is HTTP/1.1-only, so an
		// h2c client cannot complete a handshake — which is why gRPC could
		// not traverse the sidecar at all, rather than merely being
		// unparsed. HTTP/1.1 clients are unaffected: h2c.NewHandler only
		// takes over on the HTTP/2 preface or an `Upgrade: h2c`, so
		// WebSocket upgrades still reach the handler below.
		proxyHandler = h2c.NewHandler(handler, &http2.Server{})
	}
	var proxySrv *http.Server
	if collectorOnly {
		logger.Info("optictrace collector mode — no proxy listener",
			"service", cfg.Service.Name,
			"ingest", cfg.Telemetry.AdminListen+"/api/ingest",
			"rules", len(cfg.Rules),
			"version", version)
	} else {
		proxySrv = &http.Server{
			Addr:              cfg.Service.Listen,
			Handler:           proxyHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			logger.Info("optictrace listening",
				"h2c", cfg.Service.HTTP2,
				"service", cfg.Service.Name,
				"listen", cfg.Service.Listen,
				"upstream", cfg.Service.Upstream,
				"rules", len(cfg.Rules),
				"version", version)
			if err := proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("proxy server failed", "error", err)
				os.Exit(1)
			}
		}()
	}

	// --- signals ----------------------------------------------------------
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			_ = reload()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	exitCode := 0
	select {
	case <-stop:
	case code := <-childExit:
		// Mirror the child's status: a supervisor reads it, and reporting 0 for
		// a crashed process would make the crash invisible.
		exitCode = code
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if proxySrv != nil {
		_ = proxySrv.Shutdown(ctx)
	}
	_ = adminSrv.Shutdown(ctx)
	if logCollector != nil {
		logCollector.Close() // drains collected log lines
	}
	if writer != nil {
		_ = writer.Close() // drains the telemetry queue
	}
	if dispatcher != nil {
		dispatcher.Shutdown() // flushes exporter batches
	}
	logger.Info("optictrace stopped")
	if exitCode != 0 {
		// Only after the drain above: the last lines of a crashing process are
		// the ones worth having.
		os.Exit(exitCode)
	}
}
