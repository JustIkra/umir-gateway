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
	if cfg.JournalCapacity != 1000 || cfg.ExpirationRunInterval != time.Second {
		t.Errorf("journal capacity: %d, expiration run interval: %s", cfg.JournalCapacity, cfg.ExpirationRunInterval)
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
		"JOURNAL_CAPACITY":                 "250",
		"EXPIRATION_RUN_INTERVAL":          "500ms",
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
		cfg.UpstreamTimeout != 2500*time.Millisecond || cfg.JournalCapacity != 250 || cfg.ExpirationRunInterval != 500*time.Millisecond {
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
		{"JOURNAL_CAPACITY", "0"},
		{"JOURNAL_CAPACITY", "-5"},
		{"JOURNAL_CAPACITY", "1e3"},
		{"JOURNAL_CAPACITY", "100001"},
		{"EXPIRATION_RUN_INTERVAL", "1"},
		{"EXPIRATION_RUN_INTERVAL", "0s"},
		{"EXPIRATION_RUN_INTERVAL", "-1s"},
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

func TestG5AuthRuntimeCredentialAndPrivatePort(t *testing.T) {
	values := map[string]string{"AUTH_URL": "http://127.0.0.1:8085", "AUTH_SERVICE_KEY": "gateway-auth-key", "SERVING_URL": "http://127.0.0.1:8083", "WAREHOUSE_URL": "http://127.0.0.1:8082", "FEEDBACK_URL": "http://127.0.0.1:8084", "SERVING_SERVICE_KEY": "s-key", "WAREHOUSE_SERVICE_KEY": "w-key", "FEEDBACK_SERVICE_KEY": "f-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": "http://127.0.0.1:8080"}
	for _, key := range []string{"", "gateway-auth-key", "has space"} {
		values["AUTH_RUNTIME_SERVICE_KEY"] = key
		if _, err := Load(func(k string) string { return values[k] }); err == nil {
			t.Fatal("missing/reused/malformed runtime credential accepted")
		}
	}
	values["AUTH_RUNTIME_SERVICE_KEY"] = "auth-runtime-key"
	cfg, err := Load(func(k string) string { return values[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrivatePort != "8086" || cfg.PrivateListenHost != "127.0.0.1" {
		t.Fatal("private listener defaults")
	}
	values["PRIVATE_PORT"] = "8080"
	if _, err := Load(func(k string) string { return values[k] }); err == nil {
		t.Fatal("public/private port shared")
	}
}

func authValues(extra map[string]string) map[string]string {
	values := map[string]string{"AUTH_URL": "http://127.0.0.1:8085", "AUTH_SERVICE_KEY": "gateway-auth-key", "AUTH_RUNTIME_SERVICE_KEY": "auth-runtime-key", "SERVING_URL": "http://127.0.0.1:8083", "WAREHOUSE_URL": "http://127.0.0.1:8082", "FEEDBACK_URL": "http://127.0.0.1:8084", "SERVING_SERVICE_KEY": "s-key", "WAREHOUSE_SERVICE_KEY": "w-key", "FEEDBACK_SERVICE_KEY": "f-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": "http://127.0.0.1:8080"}
	maps.Copy(values, extra)
	return values
}

func TestW1RegistryRefreshDefaults(t *testing.T) {
	cfg, err := Load(env(authValues(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RegistryRefreshInterval != 2*time.Second || cfg.RegistryMaxAge != 30*time.Second {
		t.Fatalf("defaults: %s %s", cfg.RegistryRefreshInterval, cfg.RegistryMaxAge)
	}
	if cfg.InstanceID != "" {
		t.Fatalf("instance has no configured default: %q", cfg.InstanceID)
	}
}

func TestW1RegistryRefreshRanges(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"below one second":              {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "999ms"},
		"above thirty seconds":          {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "31s", "GATEWAY_REGISTRY_MAX_AGE": "5m"},
		"not a duration":                {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "soon"},
		"zero":                          {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "0s"},
		"max age under three intervals": {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "10s", "GATEWAY_REGISTRY_MAX_AGE": "29s"},
		"max age not a duration":        {"GATEWAY_REGISTRY_MAX_AGE": "old"},
		"max age negative":              {"GATEWAY_REGISTRY_MAX_AGE": "-1s"},
		"default max age under default three intervals": {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "30s"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(env(authValues(values))); err == nil {
				t.Fatal("invalid registry refresh settings accepted")
			}
		})
	}
	for name, values := range map[string]map[string]string{
		"minimum":      {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "1s", "GATEWAY_REGISTRY_MAX_AGE": "3s"},
		"maximum":      {"GATEWAY_REGISTRY_REFRESH_INTERVAL": "30s", "GATEWAY_REGISTRY_MAX_AGE": "90s"},
		"explicit age": {"GATEWAY_REGISTRY_MAX_AGE": "1m"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(env(authValues(values))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestW1InstanceID(t *testing.T) {
	for _, good := range []string{"gateway-2.eu_1", "umir/gateway#2@eu~1", "~", strings.Repeat("a", 128)} {
		cfg, err := Load(env(authValues(map[string]string{"GATEWAY_INSTANCE_ID": good})))
		if err != nil || cfg.InstanceID != good {
			t.Fatalf("instance %q: %q %v", good, cfg.InstanceID, err)
		}
	}
	for _, bad := range []string{"has space", "line\nbreak", "tab\there", "del\x7f", "nul\x00", strings.Repeat("a", 129), "кириллица"} {
		if _, err := Load(env(authValues(map[string]string{"GATEWAY_INSTANCE_ID": bad}))); err == nil {
			t.Fatalf("instance %q accepted", bad)
		} else if strings.Contains(err.Error(), bad) {
			t.Fatal("instance value echoed")
		}
	}
}

func TestW1RegistrySettingsIgnoredWithoutAuth(t *testing.T) {
	if _, err := Load(env(withOperator(map[string]string{"GATEWAY_REGISTRY_REFRESH_INTERVAL": "soon"}))); err != nil {
		t.Fatalf("legacy mode reads Auth-mode settings: %v", err)
	}
}

func TestW1ExpirationPoolDefaults(t *testing.T) {
	cfg, err := Load(env(authValues(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExpirationConcurrency != 8 || cfg.ExpirationIterationBudget != 10*time.Second {
		t.Fatalf("defaults: %d %s", cfg.ExpirationConcurrency, cfg.ExpirationIterationBudget)
	}
}

func TestW1ExpirationPoolRanges(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"concurrency zero":          {"GATEWAY_EXPIRATION_CONCURRENCY": "0"},
		"concurrency negative":      {"GATEWAY_EXPIRATION_CONCURRENCY": "-1"},
		"concurrency not a number":  {"GATEWAY_EXPIRATION_CONCURRENCY": "many"},
		"concurrency above limit":   {"GATEWAY_EXPIRATION_CONCURRENCY": "257"},
		"budget zero":               {"GATEWAY_EXPIRATION_ITERATION_BUDGET": "0s"},
		"budget negative":           {"GATEWAY_EXPIRATION_ITERATION_BUDGET": "-1s"},
		"budget not a duration":     {"GATEWAY_EXPIRATION_ITERATION_BUDGET": "long"},
		"budget below one second":   {"GATEWAY_EXPIRATION_ITERATION_BUDGET": "999ms"},
		"budget above five minutes": {"GATEWAY_EXPIRATION_ITERATION_BUDGET": "301s"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(env(authValues(values)))
			if err == nil {
				t.Fatal("invalid scheduler pool settings accepted")
			}
			for _, raw := range values {
				if strings.Contains(err.Error(), raw) {
					t.Fatal("setting value echoed")
				}
			}
		})
	}
	cfg, err := Load(env(authValues(map[string]string{"GATEWAY_EXPIRATION_CONCURRENCY": "256", "GATEWAY_EXPIRATION_ITERATION_BUDGET": "5m"})))
	if err != nil || cfg.ExpirationConcurrency != 256 || cfg.ExpirationIterationBudget != 5*time.Minute {
		t.Fatalf("limits rejected: %v", err)
	}
	if cfg, err = Load(env(authValues(map[string]string{"GATEWAY_EXPIRATION_CONCURRENCY": "1", "GATEWAY_EXPIRATION_ITERATION_BUDGET": "1s"}))); err != nil || cfg.ExpirationConcurrency != 1 {
		t.Fatalf("minimum rejected: %v", err)
	}
}

func TestW1ExpirationPoolSettingsIgnoredWithoutAuth(t *testing.T) {
	if _, err := Load(env(withOperator(map[string]string{"GATEWAY_EXPIRATION_CONCURRENCY": "many"}))); err != nil {
		t.Fatalf("legacy mode reads Auth-mode settings: %v", err)
	}
}

func TestW1LiveRingCapacity(t *testing.T) {
	cfg, err := Load(env(authValues(nil)))
	if err != nil || cfg.LiveRingCapacity != 128 {
		t.Fatalf("default: %d %v", cfg.LiveRingCapacity, err)
	}
	for _, raw := range []string{"0", "15", "4097", "-1", "many"} {
		_, err := Load(env(authValues(map[string]string{"GATEWAY_LIVE_RING_CAPACITY": raw})))
		if err == nil || strings.Contains(err.Error(), "many") {
			t.Fatalf("value %q: %v", raw, err)
		}
	}
	for raw, want := range map[string]int{"16": 16, "4096": 4096} {
		cfg, err := Load(env(authValues(map[string]string{"GATEWAY_LIVE_RING_CAPACITY": raw})))
		if err != nil || cfg.LiveRingCapacity != want {
			t.Fatalf("bound %s rejected: %v", raw, err)
		}
	}
	if _, err := Load(env(withOperator(map[string]string{"GATEWAY_LIVE_RING_CAPACITY": "many"}))); err != nil {
		t.Fatalf("legacy mode reads Auth-mode settings: %v", err)
	}
}

func TestW1LiveStreamLimits(t *testing.T) {
	cfg, err := Load(env(authValues(nil)))
	if err != nil || cfg.LiveMaxStreams != 64 || cfg.LiveMaxStreamsPerSession != 8 || cfg.LiveMaxStreamsPerOrg != 32 {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	cfg, err = Load(env(authValues(map[string]string{"GATEWAY_LIVE_MAX_STREAMS": "200", "GATEWAY_LIVE_MAX_STREAMS_PER_SESSION": "2", "GATEWAY_LIVE_MAX_STREAMS_PER_ORG": "100"})))
	if err != nil || cfg.LiveMaxStreams != 200 || cfg.LiveMaxStreamsPerSession != 2 || cfg.LiveMaxStreamsPerOrg != 100 {
		t.Fatalf("custom: %+v %v", cfg, err)
	}
	for _, key := range []string{"GATEWAY_LIVE_MAX_STREAMS", "GATEWAY_LIVE_MAX_STREAMS_PER_SESSION", "GATEWAY_LIVE_MAX_STREAMS_PER_ORG"} {
		for _, raw := range []string{"0", "-1", "many", "100001"} {
			_, err := Load(env(authValues(map[string]string{key: raw})))
			if err == nil || strings.Contains(err.Error(), "many") {
				t.Fatalf("%s=%q: %v", key, raw, err)
			}
		}
	}
}
