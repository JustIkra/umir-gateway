package config

import (
	"maps"
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

// withOperator adds the required operator settings to values.
func withOperator(values map[string]string) map[string]string {
	all := map[string]string{
		"OPERATOR_COOKIE_MODE":   "loopback-development",
		"OPERATOR_PUBLIC_ORIGIN": "http://127.0.0.1:8080",
		"OPERATOR_STORE_PATH":    "/data/operator/account.json",
	}
	maps.Copy(all, values)
	return all
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(withOperator(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "8080" || cfg.ListenHost != "127.0.0.1" {
		t.Errorf("port: %q, listen host: %q", cfg.Port, cfg.ListenHost)
	}
	if got := cfg.ServingURL.String(); got != "http://serving:8080" {
		t.Errorf("serving: %s", got)
	}
	if got := cfg.WarehouseURL.String(); got != "http://warehouse:8080" {
		t.Errorf("warehouse: %s", got)
	}
	if got := cfg.FeedbackURL.String(); got != "http://feedback:8084" {
		t.Errorf("feedback: %s", got)
	}
	if cfg.UpstreamTimeout != 15*time.Second {
		t.Errorf("timeout: %s", cfg.UpstreamTimeout)
	}
	want := Operator{
		CookieMode: CookieModeLoopback, PublicOrigin: "http://127.0.0.1:8080", StorePath: "/data/operator/account.json",
		IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 8 * time.Hour,
	}
	if cfg.Operator != want {
		t.Errorf("operator: %+v", cfg.Operator)
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	cfg, err := Load(env(withOperator(map[string]string{
		"PORT":                             "18081",
		"LISTEN_HOST":                      "0.0.0.0",
		"SERVING_URL":                      "http://127.0.0.1:18082",
		"WAREHOUSE_URL":                    "https://warehouse.internal:8443/base",
		"FEEDBACK_URL":                     "http://127.0.0.1:18083",
		"UPSTREAM_TIMEOUT":                 "2500ms",
		"OPERATOR_COOKIE_MODE":             "secure",
		"OPERATOR_PUBLIC_ORIGIN":           "https://xn----ctbhsteek4c3c.empty-lab.ru",
		"OPERATOR_BOOTSTRAP_LOGIN":         "operator",
		"OPERATOR_BOOTSTRAP_DISPLAY_NAME":  "Оператор",
		"OPERATOR_BOOTSTRAP_PASSWORD_HASH": "$argon2id$fake",
		"OPERATOR_IDLE_TIMEOUT":            "15m",
		"OPERATOR_ABSOLUTE_TIMEOUT":        "4h",
	})))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != "18081" || cfg.ListenHost != "0.0.0.0" || cfg.ServingURL.Host != "127.0.0.1:18082" ||
		cfg.WarehouseURL.String() != "https://warehouse.internal:8443/base" || cfg.FeedbackURL.Host != "127.0.0.1:18083" ||
		cfg.UpstreamTimeout != 2500*time.Millisecond {
		t.Fatalf("config: %+v", cfg)
	}
	want := Operator{
		CookieMode: CookieModeSecure, PublicOrigin: "https://xn----ctbhsteek4c3c.empty-lab.ru",
		StorePath: "/data/operator/account.json", BootstrapLogin: "operator", BootstrapDisplayName: "Оператор",
		BootstrapPasswordHash: "$argon2id$fake", IdleTimeout: 15 * time.Minute, AbsoluteTimeout: 4 * time.Hour,
	}
	if cfg.Operator != want {
		t.Errorf("operator: %+v", cfg.Operator)
	}
}

func TestLoadAcceptsLoopbackOrigins(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:8080", "http://127.0.0.1:49152", "http://[::1]:8080", "http://127.0.0.2"} {
		if _, err := Load(env(withOperator(map[string]string{"OPERATOR_PUBLIC_ORIGIN": origin}))); err != nil {
			t.Errorf("%s: %v", origin, err)
		}
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
		{"FEEDBACK_URL", "feedback:8080"},
		{"FEEDBACK_URL", "http://user:secret@feedback:8080"},
		{"PORT", "http"},
		{"PORT", "0"},
		{"PORT", "65536"},
		{"LISTEN_HOST", "example.com"},
		{"LISTEN_HOST", "10.77.42.240"},
		{"LISTEN_HOST", "127.0.0.1:80"},
		{"UPSTREAM_TIMEOUT", "15"},
		{"UPSTREAM_TIMEOUT", "0s"},
		{"UPSTREAM_TIMEOUT", "-1s"},
		{"OPERATOR_COOKIE_MODE", ""},
		{"OPERATOR_COOKIE_MODE", "insecure"},
		{"OPERATOR_COOKIE_MODE", "secure"}, // with the loopback http origin
		{"OPERATOR_PUBLIC_ORIGIN", ""},
		{"OPERATOR_PUBLIC_ORIGIN", "null"},
		{"OPERATOR_PUBLIC_ORIGIN", "https://example.org"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://localhost:8080"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://10.77.42.240:8080"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:8080/"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:8080/app"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:8080?secret=1"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:8080#secret"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://user:secret@127.0.0.1:8080"},
		{"OPERATOR_PUBLIC_ORIGIN", "HTTP://127.0.0.1:8080"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:80"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:65536"},
		{"OPERATOR_PUBLIC_ORIGIN", "http://127.0.0.1:08080"},
		{"OPERATOR_STORE_PATH", ""},
		{"OPERATOR_STORE_PATH", "account.json"},
		{"OPERATOR_STORE_PATH", "/data/../data/operator/account.json"},
		{"OPERATOR_IDLE_TIMEOUT", "abc"},
		{"OPERATOR_IDLE_TIMEOUT", "0s"},
		{"OPERATOR_IDLE_TIMEOUT", "9h"}, // longer than the 8h absolute default
		{"OPERATOR_ABSOLUTE_TIMEOUT", "-1h"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			_, err := Load(env(withOperator(map[string]string{tc.key: tc.value})))
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

func TestLoadRejectsInvalidSecureOrigins(t *testing.T) {
	for _, origin := range []string{
		"http://example.org",
		"https://Example.org",
		"https://example.org:443",
		"https://ровный-ход.empty-lab.ru",
	} {
		t.Run(origin, func(t *testing.T) {
			_, err := Load(env(withOperator(map[string]string{
				"OPERATOR_COOKIE_MODE": "secure", "OPERATOR_PUBLIC_ORIGIN": origin,
			})))
			if err == nil || !strings.Contains(err.Error(), "OPERATOR_PUBLIC_ORIGIN") || strings.Contains(err.Error(), origin) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
