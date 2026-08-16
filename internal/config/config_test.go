package config

import (
	"strings"
	"testing"
)

// base is a minimal valid document. Tests mutate one thing at a time so a
// failure names exactly which invariant broke.
const base = `
version: 1
service:
  name: t
  listen: ":8080"
  upstream: "http://localhost:9000"
`

func TestParseAppliesDefaults(t *testing.T) {
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Loopback, not ":9095". The admin API can read every captured payload,
	// so binding all interfaces must be something the operator asked for.
	if cfg.Telemetry.AdminListen != "127.0.0.1:9095" {
		t.Errorf("admin_listen default = %q, want 127.0.0.1:9095", cfg.Telemetry.AdminListen)
	}
	if cfg.Telemetry.Store.Driver != "sqlite" {
		t.Errorf("store driver default = %q", cfg.Telemetry.Store.Driver)
	}
	if cfg.Defaults.CaptureLimitBytes != DefaultCaptureLimitBytes {
		t.Errorf("capture limit default = %d", cfg.Defaults.CaptureLimitBytes)
	}
	if cfg.Telemetry.Metrics.MaxLabelValues == nil || *cfg.Telemetry.Metrics.MaxLabelValues != 500 {
		t.Error("max_label_values default should be 500")
	}
	if len(cfg.Telemetry.CORSOrigins) != 0 {
		t.Error("no CORS origins should be allowed by default")
	}
}

func TestAdminReachable(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9095", false},
		{"localhost:9095", true}, // a name, not an IP — assume the worst
		{"[::1]:9095", false},
		{":9095", true},          // every interface
		{"0.0.0.0:9095", true},   // explicit
		{"192.168.1.5:9095", true},
		{"garbage", true}, // unparseable — assume the worst
	} {
		tel := Telemetry{AdminListen: tc.addr}
		if got := tel.AdminReachable(); got != tc.want {
			t.Errorf("AdminReachable(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want string // substring the message must contain
	}{
		{
			name: "wrong version",
			yaml: "version: 2\n",
			want: "unsupported config version",
		},
		{
			name: "listen without a port",
			yaml: base + "telemetry:\n  admin_listen: \"9095\"\n",
			want: "must be host:port",
		},
		{
			name: "listen with a bad port",
			yaml: "version: 1\nservice:\n  listen: \":notaport\"\n  upstream: \"http://x:1\"\n",
			want: "is not a valid port",
		},
		{
			name: "upstream not absolute",
			yaml: "version: 1\nservice:\n  listen: \":8080\"\n  upstream: \"localhost:9000\"\n",
			want: "not a valid absolute URL",
		},
		{
			// A wildcard origin with no credential lets any page a developer
			// visits read the entire capture store.
			name: "wildcard CORS without auth",
			yaml: base + "telemetry:\n  cors_origins: [\"*\"]\n",
			want: `"*" requires telemetry.auth`,
		},
		{
			name: "CORS origin with a path",
			yaml: base + "telemetry:\n  cors_origins: [\"http://localhost:3001/app\"]\n",
			want: "must be a scheme://host[:port] origin",
		},
		{
			name: "CORS origin without a scheme",
			yaml: base + "telemetry:\n  cors_origins: [\"localhost:3001\"]\n",
			want: "must be a scheme://host[:port] origin",
		},
		{
			name: "unknown store driver",
			yaml: base + "telemetry:\n  store:\n    driver: mysql\n",
			want: "is not supported",
		},
		{
			name: "postgres driver with a sqlite dsn",
			yaml: base + "telemetry:\n  store:\n    driver: postgres\n    dsn: ./local.db\n",
			want: "must be a postgres:// URL",
		},
		{
			name: "auth with neither token nor token_env",
			yaml: base + "telemetry:\n  auth: {}\n",
			want: "set either token or token_env",
		},
		{
			name: "negative retention age",
			yaml: base + "telemetry:\n  store:\n    retention_max_age: \"-1h\"\n",
			want: "must be positive",
		},
		{
			// KnownFields(true): a typo must fail loudly rather than be
			// silently ignored, which would look like the rule working.
			name: "typo in a key",
			yaml: base + "rules:\n  - name: r\n    match: {path: \"/**\"}\n    redct: {}\n",
			want: "field redct not found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected rejection, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("message %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"minimal sidecar", base},
		{
			// Embedded middleware opens no listener, so neither address is
			// required. This must keep working.
			name: "embedded: no listen, no upstream",
			yaml: "version: 1\nservice:\n  name: embedded\n",
		},
		{
			// The proxy package's tests construct exactly this.
			name: "upstream without listen",
			yaml: "version: 1\nservice:\n  upstream: \"http://localhost:9000\"\n",
		},
		{
			name: "explicit CORS origin",
			yaml: base + "telemetry:\n  cors_origins: [\"http://localhost:3001\"]\n",
		},
		{
			name: "wildcard CORS with a token",
			yaml: base + "telemetry:\n  cors_origins: [\"*\"]\n  auth:\n    token: s3cret\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err != nil {
				t.Errorf("should be valid: %v", err)
			}
		})
	}
}

// RequireProxyAddrs is what `run` calls. Validate deliberately does not, so
// embedded use keeps working — this is the check that stops an omitted
// service.listen from reaching net/http as Addr:"" and binding port 80.
func TestRequireProxyAddrs(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"both present", base, ""},
		{
			name: "missing listen",
			yaml: "version: 1\nservice:\n  upstream: \"http://localhost:9000\"\n",
			want: "binds port 80",
		},
		{
			name: "missing upstream",
			yaml: "version: 1\nservice:\n  listen: \":8080\"\n",
			want: "nowhere to forward",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = cfg.RequireProxyAddrs()
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.want != "" && err == nil:
				t.Errorf("expected an error mentioning %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Errorf("message %q does not mention %q", err, tc.want)
			}
		})
	}
}
