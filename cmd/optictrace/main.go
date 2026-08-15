// optictrace is the standalone agent:
//
//	optictrace run      -config optic.yaml   start proxy + admin/metrics server
//	optictrace validate -config optic.yaml   lint the config (CI-friendly)
//	optictrace version
//
// Hot reload: SIGHUP or POST /api/reload re-reads optic.yaml and swaps the
// rule engine atomically; in-flight requests finish under their old policy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/admin"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/export"
	"github.com/dwarka-prasad/optictrace/internal/metrics"
	"github.com/dwarka-prasad/optictrace/internal/mock"
	"github.com/dwarka-prasad/optictrace/internal/proxy"
	"github.com/dwarka-prasad/optictrace/internal/replay"
	"github.com/dwarka-prasad/optictrace/internal/ruletest"
	"github.com/dwarka-prasad/optictrace/internal/scan"
	"github.com/dwarka-prasad/optictrace/internal/spec"
	"github.com/dwarka-prasad/optictrace/internal/store"
	"github.com/dwarka-prasad/optictrace/internal/suggest"
)

var version = "0.7.0-dev" // overridden via -ldflags at release time

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !isFlag(args[0]) {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	configPath := fs.String("config", "optic.yaml", "path to optic.yaml")
	uiDir := fs.String("ui", "ui/out", "static dashboard directory (optional)")
	specPath := fs.String("spec", "", "OpenAPI spec file (check/mock/sdk)")
	outPath := fs.String("out", "", "output file (spec/sdk); default stdout")
	window := fs.Duration("window", 24*time.Hour, "traffic window to analyze (spec/check)")
	lang := fs.String("lang", "typescript", "SDK language (sdk)")
	listen := fs.String("listen", ":7070", "mock server listen address (mock)")
	ai := fs.Bool("ai", false, "mock: generate responses with Claude when ANTHROPIC_API_KEY is set")
	testsPath := fs.String("tests", "optic.test.yaml", "rule test file (test)")
	failOn := fs.String("fail-on", "high", "scan: minimum severity that exits non-zero (critical|high|medium|never)")
	purgeLabel := fs.String("label", "", "purge: consumer label name (default: telemetry.billing.consumer_label)")
	purgeValue := fs.String("value", "", "purge: consumer label value to erase")
	olderThan := fs.Duration("older-than", 0, "purge: only delete records older than this (default: all)")
	yes := fs.Bool("yes", false, "purge: skip the interactive confirmation (for automation)")
	replayTarget := fs.String("target", "", "replay: base URL to replay captured traffic against")
	rate := fs.Float64("rate", 0, "replay: requests per second (0 = as fast as possible)")
	concurrency := fs.Int("concurrency", 4, "replay: parallel in-flight requests")
	dryRun := fs.Bool("dry-run", false, "replay: report what would be sent without sending")
	applyOut := fs.String("apply", "", "suggest: write proposed rules to this file instead of stdout")
	_ = fs.Parse(args)

	switch cmd {
	case "run":
		run(*configPath, *uiDir)
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
	case "version":
		fmt.Println("optictrace", version)
	default:
		fmt.Fprintf(os.Stderr,
			"unknown command %q\n  (run, validate, test, scan, suggest, purge, replay,\n   spec, check, sdk, mock, version)\n", cmd)
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

// scanTraffic is the safety net: it looks for values that LOOK sensitive in
// records that already passed governance — the field you forgot to declare.
func scanTraffic(configPath string, window time.Duration, failOn string) {
	_, records := loadTraffic(configPath, window)
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "✗ no traffic captured in this window — nothing to scan")
		os.Exit(1)
	}
	report := scan.Records(records, time.Now().Add(-window))
	crit, high, med := report.Counts()

	if len(report.Findings) == 0 {
		fmt.Printf("✓ scanned %d record(s) over %s — no sensitive values found outside your rules\n",
			report.Scanned, window)
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
	fmt.Printf("scanned %d record(s): %d critical, %d high, %d medium\n",
		report.Scanned, crit, high, med)

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
	records, err := st.Recent(context.Background(), time.Now().Add(-window), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ query store: %v\n", err)
		os.Exit(1)
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
func openStore(cfg *config.StoreCfg) (store.LogStore, error) {
	switch cfg.Driver {
	case "postgres":
		return store.NewPostgres(cfg.DSN)
	default:
		return store.NewSQLite(cfg.DSN)
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
}

func run(configPath, uiDir string) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
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
		writer = store.NewAsyncWriter(sqlStore, cfg.Telemetry.Store.QueueSize, logger, asyncOpts...)
		logger.Info("payload store ready", "driver", cfg.Telemetry.Store.Driver)
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

	reload := func() error {
		newCfg, err := config.Load(configPath)
		if err != nil {
			logger.Error("reload rejected: config invalid", "error", err)
			return err
		}
		interceptor.SwapEngine(engine.New(newCfg))
		logger.Info("configuration reloaded", "rules", len(newCfg.Rules))
		return nil
	}

	// --- admin / metrics server ------------------------------------------
	adminSrv := &http.Server{
		Addr: cfg.Telemetry.AdminListen,
		Handler: (&admin.Server{
			Logger:     logger,
			Collector:  collector,
			Reader:     reader,
			Writer:     writer,
			Dispatcher: dispatcher,
			ConfigPath: configPath,
			Reload:     reload,
			UIDir:      uiDir,
			Version:    version,
			AuthToken:  cfg.Telemetry.Auth.Resolve(),
			HealthOpen: cfg.Telemetry.Auth.HealthOpen(),
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		tlsCfg := cfg.Telemetry.TLS
		logger.Info("admin server listening",
			"listen", cfg.Telemetry.AdminListen,
			"auth", cfg.Telemetry.Auth.Resolve() != "",
			"tls", tlsCfg != nil)
		if cfg.Telemetry.Auth.Resolve() == "" {
			logger.Warn("admin server is unauthenticated — do not expose this port publicly",
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

	proxySrv := &http.Server{
		Addr:              cfg.Service.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info("optictrace listening",
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
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = proxySrv.Shutdown(ctx)
	_ = adminSrv.Shutdown(ctx)
	if writer != nil {
		_ = writer.Close() // drains the telemetry queue
	}
	if dispatcher != nil {
		dispatcher.Shutdown() // flushes exporter batches
	}
	logger.Info("optictrace stopped")
}
