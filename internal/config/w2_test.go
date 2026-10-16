package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestW2Defaults(t *testing.T) {
	cfg, err := Load(env(authValues(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RedisTimeout != 200*time.Millisecond || cfg.LiveMaxScopes != 2000 || cfg.LiveRingIdle != 10*time.Minute ||
		cfg.LiveTopics != TopicsAll || cfg.RegistrySyncInterval != 30*time.Second || cfg.ExpirationBatch != 500 {
		t.Fatalf("defaults: %+v", cfg)
	}
	if cfg.LiveMaxStreamsPerSession != 8 || cfg.LiveMaxStreamsPerOrg != 200 || cfg.LiveMaxStreams != 1000 {
		t.Fatalf("stream defaults: %d %d %d", cfg.LiveMaxStreamsPerSession, cfg.LiveMaxStreamsPerOrg, cfg.LiveMaxStreams)
	}
	want := map[string]Budget{
		"csrf_client": {60, time.Minute, 20}, "csrf_global": {5000, 10 * time.Minute, 1500},
		"login_client":        {20, time.Minute, 5},
		"registration_client": {10, 10 * time.Minute, 2}, "registration_preauth": {3, 10 * time.Minute, 1}, "registration_global": {300, 10 * time.Minute, 60},
		"reset_client":    {10, 10 * time.Minute, 2},
		"feedback_client": {20, time.Hour, 4}, "feedback_preauth": {5, 10 * time.Minute, 1}, "feedback_global": {200, time.Hour, 40},
		"order_user": {60, time.Minute, 20}, "order_restaurant": {600, time.Minute, 200},
		"sse_session": {8, 0, 4}, "sse_org": {200, 0, 50}, "sse_cell": {2000, 0, 500},
	}
	for name, budget := range want {
		if cfg.Budgets[name] != budget {
			t.Errorf("budget %s: %+v, want %+v", name, cfg.Budgets[name], budget)
		}
	}
	if len(cfg.Budgets) != len(want) {
		t.Errorf("budgets: %d", len(cfg.Budgets))
	}
}

func TestW2BudgetOverrideAndRanges(t *testing.T) {
	cfg, err := Load(env(authValues(map[string]string{"GATEWAY_BUDGET_LOGIN_CLIENT": "7/30s", "GATEWAY_BUDGET_SSE_ORG": "50", "GATEWAY_BUDGET_FEEDBACK_CLIENT_STRICT": "2"})))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Budgets["login_client"]; got.Limit != 7 || got.Window != 30*time.Second || got.Strict != 5 {
		t.Errorf("login: %+v", got)
	}
	if got := cfg.Budgets["sse_org"]; got.Limit != 50 || got.Strict != 50 {
		t.Errorf("a strict value above the normal one is clamped: %+v", got)
	}
	if got := cfg.Budgets["feedback_client"]; got.Strict != 2 {
		t.Errorf("strict override: %+v", got)
	}
	for name, raw := range map[string]string{
		"GATEWAY_BUDGET_LOGIN_CLIENT": "0/1m", "GATEWAY_BUDGET_CSRF_CLIENT": "5", "GATEWAY_BUDGET_RESET_CLIENT": "5/0s",
		"GATEWAY_BUDGET_ORDER_USER": "5/48h", "GATEWAY_BUDGET_SSE_CELL": "5/1m", "GATEWAY_BUDGET_SSE_SESSION": "x",
		"GATEWAY_BUDGET_FEEDBACK_GLOBAL_STRICT": "0",
	} {
		_, err := Load(env(authValues(map[string]string{name: raw})))
		if err == nil || raw == "x" && strings.Contains(err.Error(), raw+"\n") {
			t.Errorf("%s=%q: %v", name, raw, err)
		}
	}
}

func TestW2DurableSettingsRanges(t *testing.T) {
	for name, raw := range map[string]string{
		"GATEWAY_REDIS_TIMEOUT": "0s", "GATEWAY_LIVE_MAX_SCOPES": "0", "GATEWAY_LIVE_RING_IDLE": "1s", "GATEWAY_LIVE_TOPICS": "some",
		"GATEWAY_REGISTRY_SYNC_INTERVAL": "1s", "GATEWAY_EXPIRATION_BATCH": "1001", "GATEWAY_REDIS_TIMEOUT_X": "",
	} {
		if raw == "" {
			continue
		}
		if _, err := Load(env(authValues(map[string]string{name: raw}))); err == nil {
			t.Errorf("%s=%q accepted", name, raw)
		}
	}
	cfg, err := Load(env(authValues(map[string]string{"GATEWAY_LIVE_TOPICS": "event", "GATEWAY_REDIS_TIMEOUT": "500ms"})))
	if err != nil || cfg.LiveTopics != TopicsEvent || cfg.RedisTimeout != 500*time.Millisecond {
		t.Fatalf("%v %+v", err, cfg)
	}
}

func TestW2RuntimeKeyIsOptional(t *testing.T) {
	values := authValues(nil)
	delete(values, "AUTH_RUNTIME_SERVICE_KEY")
	cfg, err := Load(env(values))
	if err != nil {
		t.Fatalf("the private listener is optional: %v", err)
	}
	if cfg.AuthRuntimeServiceKey != "" {
		t.Fatal("no runtime key, no private listener")
	}
	for _, key := range []string{"gateway-auth-key", "has space"} {
		values["AUTH_RUNTIME_SERVICE_KEY"] = key
		if _, err := Load(env(values)); err == nil {
			t.Fatalf("reused or malformed runtime key %q accepted", key)
		}
	}
}

func durableValues(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"GATEWAY_ADMISSION_KEY_FILE": keyFile(t, strings.Repeat("a", 32)+"\n"), "GATEWAY_LIVE_CURSOR_KEY_FILE": keyFile(t, strings.Repeat("c", 32)),
		"GATEWAY_LIMITER_GENERATION": "gen-2026-10-16",
	}
}

func TestW2LoadDurable(t *testing.T) {
	values := durableValues(t)
	d, err := LoadDurable(env(values))
	if err != nil {
		t.Fatal(err)
	}
	if string(d.AdmissionKey) != strings.Repeat("a", 32) || string(d.CursorKey) != strings.Repeat("c", 32) || d.LimiterGeneration != "gen-2026-10-16" {
		t.Fatalf("durable settings: %+v", d)
	}
}

func TestW2LoadDurableRefusals(t *testing.T) {
	base := durableValues(t)
	cases := map[string]func(map[string]string){
		"no admission key":    func(v map[string]string) { delete(v, "GATEWAY_ADMISSION_KEY_FILE") },
		"no cursor key":       func(v map[string]string) { delete(v, "GATEWAY_LIVE_CURSOR_KEY_FILE") },
		"no generation":       func(v map[string]string) { delete(v, "GATEWAY_LIMITER_GENERATION") },
		"blank generation":    func(v map[string]string) { v["GATEWAY_LIMITER_GENERATION"] = " " },
		"long generation":     func(v map[string]string) { v["GATEWAY_LIMITER_GENERATION"] = strings.Repeat("g", 257) },
		"short admission key": func(v map[string]string) { v["GATEWAY_ADMISSION_KEY_FILE"] = keyFile(t, "short") },
		"missing file":        func(v map[string]string) { v["GATEWAY_LIVE_CURSOR_KEY_FILE"] = filepath.Join(t.TempDir(), "none") },
		"same key twice": func(v map[string]string) {
			v["GATEWAY_LIVE_CURSOR_KEY_FILE"] = v["GATEWAY_ADMISSION_KEY_FILE"]
		},
	}
	for name, mutate := range cases {
		values := map[string]string{}
		for k, v := range base {
			values[k] = v
		}
		mutate(values)
		_, err := LoadDurable(env(values))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		for _, secret := range []string{strings.Repeat("a", 32), strings.Repeat("c", 32)} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error echoes a key", name)
			}
		}
	}

}
