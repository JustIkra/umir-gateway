package config

import (
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8080" {
		t.Errorf("port: %q", cfg.Port)
	}
	if got := cfg.ServingURL.String(); got != "http://serving:8080" {
		t.Errorf("serving: %s", got)
	}
	if got := cfg.WarehouseURL.String(); got != "http://warehouse:8080" {
		t.Errorf("warehouse: %s", got)
	}
	if cfg.UpstreamTimeout != 15*time.Second {
		t.Errorf("timeout: %s", cfg.UpstreamTimeout)
	}
	if cfg.WriteTimeout != 20*time.Second {
		t.Errorf("write timeout: %s", cfg.WriteTimeout)
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"PORT":             "18081",
		"SERVING_URL":      "http://127.0.0.1:18082",
		"WAREHOUSE_URL":    "https://warehouse.internal:8443/base",
		"UPSTREAM_TIMEOUT": "2500ms",
		"WRITE_TIMEOUT":    "4s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "18081" || cfg.ServingURL.Host != "127.0.0.1:18082" ||
		cfg.WarehouseURL.String() != "https://warehouse.internal:8443/base" ||
		cfg.UpstreamTimeout != 2500*time.Millisecond || cfg.WriteTimeout != 4*time.Second {
		t.Fatalf("config: %+v", cfg)
	}
}

func TestLoadDerivesWriteTimeoutFromUpstreamTimeout(t *testing.T) {
	cfg, err := Load(env(map[string]string{"UPSTREAM_TIMEOUT": "2500ms"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WriteTimeout != 7500*time.Millisecond {
		t.Fatalf("write timeout: %s", cfg.WriteTimeout)
	}
}

func TestLoadRejectsInvalidSettings(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"SERVING_URL", "file:///tmp/upstream"},
		{"SERVING_URL", "ftp://serving:21"},
		{"SERVING_URL", "http://"},
		{"SERVING_URL", "serving:8080"},
		{"WAREHOUSE_URL", "http://user:secret@warehouse:8080"},
		{"WAREHOUSE_URL", "http://warehouse:8080?debug=1"},
		{"WAREHOUSE_URL", "http://warehouse:8080/#fragment"},
		{"PORT", "http"},
		{"PORT", "0"},
		{"PORT", "65536"},
		{"UPSTREAM_TIMEOUT", "15"},
		{"UPSTREAM_TIMEOUT", "0s"},
		{"UPSTREAM_TIMEOUT", "-1s"},
		// The derived write timeout would overflow time.Duration.
		{"UPSTREAM_TIMEOUT", "2562047h47m16.854775807s"},
		{"WRITE_TIMEOUT", "20"},
		{"WRITE_TIMEOUT", "0s"},
		{"WRITE_TIMEOUT", "-1s"},
		// The response must outlive the default 15s upstream budget.
		{"WRITE_TIMEOUT", "15s"},
		{"WRITE_TIMEOUT", "10s"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			_, err := Load(env(map[string]string{tc.key: tc.value}))
			if err == nil {
				t.Fatal("invalid setting accepted")
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("error does not name the setting: %v", err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("error exposes credentials: %v", err)
			}
		})
	}
}
