package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/expiration"
)

func TestAuthCutoverDoesNotOpenLocalAccount(t *testing.T) {
	var calls atomic.Int32
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/internal/auth/v1/public/me" || r.Header.Get("X-Umir-Service-Key") != "synthetic-service-key" {
			t.Errorf("Auth request = %s %v", r.URL.Path, r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := io.WriteString(w, `{"code":"AuthUnavailable","outcome":"unavailable","message":"not ready","retryable":false}`); err != nil {
			t.Error(err)
		}
	}))
	defer auth.Close()
	store := filepath.Join(t.TempDir(), "must-not-exist.json")
	values := map[string]string{
		"AUTH_URL": auth.URL, "AUTH_SERVICE_KEY": "synthetic-service-key", "AUTH_ISOLATED_TEST_NETWORK": "true", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin,
		"OPERATOR_STORE_PATH": store, "OPERATOR_BOOTSTRAP_PASSWORD_HASH": "invalid-local-verifier",
	}
	app, err := componentsForTest(t, loadConfig(t, values), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("Auth cutover consulted local account: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/operator/me", nil)
	request.AddCookie(&http.Cookie{Name: "umir_operator_session", Value: "synthetic-session"})
	w := httptest.NewRecorder()
	app.handler.ServeHTTP(w, request)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "AuthUnavailable") || calls.Load() != 1 || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("Auth outage = %d %s, calls=%d", w.Code, w.Body, calls.Load())
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatalf("local account file exists: %v", err)
	}
	if _, legacy := app.expiry.(*expiration.Runner); legacy || app.streams != nil {
		t.Fatal("unscoped legacy scheduler or streams enabled in Auth topology")
	}
	for _, path := range []string{"/api/serving/menu", "/api/warehouse/stock", "/api/live"} {
		w = httptest.NewRecorder()
		app.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidArgument") {
			t.Errorf("unscoped route %s = %d %s", path, w.Code, w.Body)
		}
	}
}

func TestAuthConfigRejectsMissingCredentialWithoutLocalFallback(t *testing.T) {
	values := map[string]string{"AUTH_URL": "http://auth:8085", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}
	_, err := config.Load(func(key string) string { return values[key] })
	if err == nil || !strings.Contains(err.Error(), "AUTH_SERVICE_KEY") {
		t.Fatalf("missing credential config = %v", err)
	}
}

func TestAuthTransportRequiresTLSOutsideIsolatedTests(t *testing.T) {
	values := map[string]string{"AUTH_URL": "http://auth.example:8085", "AUTH_SERVICE_KEY": "synthetic-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}
	_, err := config.Load(func(key string) string { return values[key] })
	if err == nil || !strings.Contains(err.Error(), "AUTH_ISOLATED_TEST_NETWORK") {
		t.Fatalf("insecure remote Auth config=%v", err)
	}
	values["AUTH_ISOLATED_TEST_NETWORK"] = "true"
	values["SERVING_SERVICE_KEY"] = "serving-key"
	values["WAREHOUSE_SERVICE_KEY"] = "warehouse-key"
	values["FEEDBACK_SERVICE_KEY"] = "feedback-key"
	values["AUTH_RUNTIME_SERVICE_KEY"] = "auth-runtime-key"
	if _, err := config.Load(func(key string) string { return values[key] }); err != nil {
		t.Fatalf("isolated test transport=%v", err)
	}
}
