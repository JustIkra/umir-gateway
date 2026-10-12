package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/config"
)

func TestBusinessRoutesRequireSession(t *testing.T) {
	app := gatewayApp(t, unusedUpstream(t), unusedUpstream(t), "")
	for _, tc := range []struct{ method, target string }{
		{http.MethodGet, "/api/serving/menu"},
		{http.MethodGet, "/api/warehouse/inventory"},
		{http.MethodOptions, "/api/serving/menu"},
		{http.MethodPost, "/api/serving/order-confirmations"},
		{http.MethodPost, "/api/warehouse/healthz"},
	} {
		request := httptest.NewRequest(tc.method, tc.target, strings.NewReader(`{}`))
		request.Header.Set("Origin", testOrigin)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusUnauthorized ||
			body["code"] != "Unauthenticated" || body["requestID"] == "" {
			t.Errorf("%s %s: %d %s", tc.method, tc.target, response.Code, response.Body)
		}
	}
}

func TestHealthChecksStayPublic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected upstream request: %s", r.URL)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	app := gatewayApp(t, upstream.URL, upstream.URL, "")
	for _, target := range []string{"/healthz", "/api/serving/healthz", "/api/warehouse/healthz"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			response := httptest.NewRecorder()
			app.ServeHTTP(response, httptest.NewRequest(method, target, nil))
			if response.Code != http.StatusOK {
				t.Errorf("%s %s: %d %s", method, target, response.Code, response.Body)
			}
		}
	}
}

func TestUpstreamNeverSeesOperatorCredentials(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookies := r.Header.Values("Cookie"); !slices.Equal(cookies, []string{"theme=dark"}) {
			t.Errorf("cookies upstream: %q", cookies)
		}
		if r.Header.Get("X-CSRF-Token") != "" {
			t.Error("CSRF header reached the upstream")
		}
		w.Header().Add("Set-Cookie", "umir_operator_session=forged; Path=/")
		w.Header().Add("Set-Cookie", "__Host-umir_operator_session=forged; Path=/; Secure")
		w.Header().Add("Set-Cookie", "theme=light; Path=/")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	app := gateway(t, upstream.URL, unusedUpstream(t), "")
	request := httptest.NewRequest(http.MethodPost, "/api/serving/orders", strings.NewReader(`{}`))
	request.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if got := response.Header().Values("Set-Cookie"); response.Code != http.StatusAccepted || !slices.Equal(got, []string{"theme=light; Path=/"}) {
		t.Fatalf("response: %d %q", response.Code, got)
	}
}

func TestInvalidBootstrapFailsWithoutEchoOrFile(t *testing.T) {
	values := operatorEnv(t)
	// Valid PHC syntax, but far below the allowed cost.
	values["OPERATOR_BOOTSTRAP_PASSWORD_HASH"] = "$argon2id$v=19$m=1024,t=1,p=1$c2VjcmV0c2VjcmV0c2VjcmV0$c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2U"
	cfg, err := config.Load(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newAccounts(cfg.Operator); err == nil || strings.Contains(err.Error(), "c2VjcmV0") {
		t.Fatalf("newAccounts error = %v", err)
	}
	if _, err := os.Stat(values["OPERATOR_STORE_PATH"]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("rejected bootstrap created the account file: %v", err)
	}
}

func TestSessionsSurviveAGatewayRestart(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer upstream.Close()
	values := operatorEnv(t)
	values["SERVING_URL"], values["WAREHOUSE_URL"] = upstream.URL, upstream.URL
	creds := signIn(t, gatewayWith(t, values))
	restarted := withSession(gatewayWith(t, values), creds)
	response := httptest.NewRecorder()
	restarted.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/serving/orders", strings.NewReader(`{}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("session after a restart: %d %s", response.Code, response.Body)
	}
}

func TestClearSessionsEmptiesTheStoredSessions(t *testing.T) {
	values := operatorEnv(t)
	creds := signIn(t, gatewayWith(t, values))
	var out strings.Builder
	if err := clearSessions(loadConfig(t, values).Operator, &out); err != nil || out.String() != "cleared sessions: 1\n" {
		t.Fatalf("clearSessions = %q, %v", out.String(), err)
	}
	restarted := withSession(gatewayWith(t, values), creds)
	response := httptest.NewRecorder()
	restarted.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/operator/me", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("cleared session: %d %s", response.Code, response.Body)
	}
}
