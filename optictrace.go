// Package optictrace is the public embedding API: drop config-driven API
// telemetry and governance into any Go HTTP service.
//
//	agent, err := optictrace.New("optic.yaml")
//	if err != nil { log.Fatal(err) }
//	defer agent.Close()
//	http.ListenAndServe(":8080", agent.Middleware(mux))
//
// The agent optionally serves its own admin endpoint (metrics, dashboard,
// log APIs) on telemetry.admin_listen when started with ServeAdmin.
package optictrace

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dwarka-prasad/optictrace/internal/admin"
	"github.com/dwarka-prasad/optictrace/internal/config"
	"github.com/dwarka-prasad/optictrace/internal/engine"
	"github.com/dwarka-prasad/optictrace/internal/export"
	"github.com/dwarka-prasad/optictrace/internal/metrics"
	"github.com/dwarka-prasad/optictrace/internal/proxy"
	"github.com/dwarka-prasad/optictrace/internal/scan"
	"github.com/dwarka-prasad/optictrace/internal/store"
)

// Agent bundles the rule engine, telemetry sinks, and optional admin server.
type Agent struct {
	cfg         *config.Config
	configPath  string
	interceptor *proxy.Interceptor
	collector   *metrics.Collector
	reader      store.LogStore
	writer      *store.AsyncWriter
	dispatcher  *export.Dispatcher
	logger      *slog.Logger
	adminSrv    *http.Server
	// reloadMu serializes Reload against itself; cfg is only touched there.
	reloadMu sync.Mutex
}

// AgentOption customizes construction.
type AgentOption func(*Agent)

// WithLogger overrides the default JSON stdout logger.
func WithLogger(l *slog.Logger) AgentOption {
	return func(a *Agent) { a.logger = l }
}

// New loads optic.yaml and assembles the telemetry pipeline (metrics
// collector and async payload store per the config's telemetry block).
func New(configPath string, opts ...AgentOption) (*Agent, error) {
	a := &Agent{configPath: configPath}
	for _, o := range opts {
		o(a)
	}
	if a.logger == nil {
		a.logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	a.cfg = cfg
	eng := engine.New(cfg)

	if config.Bool(cfg.Telemetry.Metrics.Enabled) {
		a.collector = metrics.New(cfg.Service.Name, cfg.Telemetry.Metrics.Buckets,
			eng.LabelKeys(), cfg.Telemetry.Metrics.LabelValueCap())
	}
	if cfg.Telemetry.Store.Driver != "none" {
		var sqlStore store.LogStore
		var err error
		switch cfg.Telemetry.Store.Driver {
		case "postgres":
			sqlStore, err = store.NewPostgres(cfg.Telemetry.Store.DSN)
		case "clickhouse":
			sqlStore, err = store.NewClickHouse(cfg.Telemetry.Store.DSN)
		default:
			sqlStore, err = store.NewSQLite(cfg.Telemetry.Store.DSN)
		}
		if err != nil {
			return nil, err
		}
		a.reader = sqlStore
		asyncOpts := []store.AsyncOption{
			store.WithRetention(cfg.Telemetry.Store.RetentionMaxRows),
			store.WithMaxAge(cfg.Telemetry.Store.MaxAge()),
		}
		if a.collector != nil {
			asyncOpts = append(asyncOpts, store.WithDropCallback(a.collector.StoreDropped))
		}
		a.writer = store.NewAsyncWriter(sqlStore, cfg.Telemetry.Store.QueueSize, a.logger, asyncOpts...)
	}

	if len(cfg.Telemetry.Exporters) > 0 {
		var expMetrics export.Metrics
		if a.collector != nil {
			expMetrics = a.collector
		}
		a.dispatcher, err = export.New(cfg.Telemetry.Exporters, a.logger, expMetrics, cfg.Service.Name)
		if err != nil {
			return nil, err
		}
	}

	var proxyOpts []proxy.Option
	if a.collector != nil {
		proxyOpts = append(proxyOpts, proxy.WithMetrics(a.collector))
	}
	if a.writer != nil {
		proxyOpts = append(proxyOpts, proxy.WithStore(a.writer))
	}
	if a.dispatcher != nil {
		proxyOpts = append(proxyOpts, proxy.WithExporters(a.dispatcher))
	}
	a.interceptor = proxy.NewInterceptor(cfg, eng, a.logger, proxyOpts...)
	return a, nil
}

// Middleware wraps an http.Handler with interception (embedded mode).
func (a *Agent) Middleware(next http.Handler) http.Handler {
	return a.interceptor.Wrap(next)
}

// Reload re-reads optic.yaml, atomically swaps the rule engine, and re-points
// the metrics label schema. Settings that cannot be hot-swapped are reported
// rather than silently ignored — see Config.RestartRequired.
func (a *Agent) Reload() error {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()

	cfg, err := config.Load(a.configPath)
	if err != nil {
		return err
	}
	eng := engine.New(cfg)
	a.interceptor.SwapEngine(eng)
	relabeled := false
	if a.collector != nil {
		relabeled = a.collector.SetLabelKeys(eng.LabelKeys())
	}
	if stale := a.cfg.RestartRequired(cfg); len(stale) > 0 {
		a.logger.Warn("reload applied rules only — these changes need a restart",
			"fields", strings.Join(stale, ", "))
	}
	a.cfg = cfg
	a.logger.Info("configuration reloaded",
		"rules", len(cfg.Rules), "metrics_relabeled", relabeled)
	return nil
}

// scanDetectors compiles the org-specific scan detectors, falling back to the
// built-ins if the config changed underneath us.
func scanDetectors(cfg *config.Config, logger *slog.Logger) []scan.Detector {
	dets, err := cfg.Detectors()
	if err != nil {
		logger.Error("ignoring scan.detectors", "error", err)
		return nil
	}
	return dets
}

// AdminHandler exposes /metrics, the dashboard, and query APIs for mounting
// on a listener you control.
func (a *Agent) AdminHandler(uiDir string) http.Handler {
	return (&admin.Server{
		Logger:          a.logger,
		Collector:       a.collector,
		Reader:          a.reader,
		Writer:          a.writer,
		Dispatcher:      a.dispatcher,
		ConfigPath:      a.configPath,
		Reload:          a.Reload,
		UIDir:           uiDir,
		AuthToken:       a.cfg.Telemetry.Auth.Resolve(),
		HealthOpen:      a.cfg.Telemetry.Auth.HealthOpen(),
		CORSOrigins:     a.cfg.Telemetry.CORSOrigins,
		AnalysisMaxRows: a.cfg.Telemetry.Store.AnalysisMaxRows,
		Detectors:       scanDetectors(a.cfg, a.logger),
	}).Handler()
}

// ServeAdmin starts the admin server on telemetry.admin_listen in a
// background goroutine.
func (a *Agent) ServeAdmin(uiDir string) {
	a.adminSrv = &http.Server{
		Addr:              a.cfg.Telemetry.AdminListen,
		Handler:           a.AdminHandler(uiDir),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		tlsCfg := a.cfg.Telemetry.TLS
		a.logger.Info("admin server listening", "listen", a.cfg.Telemetry.AdminListen,
			"auth", a.cfg.Telemetry.Auth.Resolve() != "", "tls", tlsCfg != nil)
		var err error
		if tlsCfg != nil {
			err = a.adminSrv.ListenAndServeTLS(tlsCfg.CertFile, tlsCfg.KeyFile)
		} else {
			err = a.adminSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.logger.Error("admin server failed", "error", err)
		}
	}()
}

// Close drains the telemetry queue, flushes exporters, and releases resources.
func (a *Agent) Close() error {
	if a.adminSrv != nil {
		_ = a.adminSrv.Close()
	}
	var err error
	if a.writer != nil {
		err = a.writer.Close()
	}
	if a.dispatcher != nil {
		a.dispatcher.Shutdown()
	}
	return err
}
