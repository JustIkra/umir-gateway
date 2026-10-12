package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/accountfile"
	"github.com/JustIkra/umir-gateway/internal/config"
	"github.com/JustIkra/umir-gateway/internal/operator"
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

// TestUpstreamInformationalResponsesCannotSetOperatorCookies covers 1xx answers such as 103 Early Hints,
// which the reverse proxy forwards without ModifyResponse.
func TestUpstreamInformationalResponsesCannotSetOperatorCookies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "umir_operator_session=forged; Path=/")
		w.Header().Add("Set-Cookie", "__Host-umir_operator_preauth=forged; Path=/; Secure")
		w.Header().Add("Set-Cookie", "theme=light; Path=/")
		w.Header().Add("Link", "</app.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Set-Cookie")
		w.Header().Del("Link")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	server := httptest.NewServer(gateway(t, upstream.URL, unusedUpstream(t), ""))
	defer server.Close()
	var hints []http.Header
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints {
			hints = append(hints, http.Header(header).Clone())
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, server.URL+"/api/serving/menu", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(hints) != 1 {
		t.Fatalf("status %d with %d early hints, want 200 after one", response.StatusCode, len(hints))
	}
	if got := hints[0].Values("Set-Cookie"); !slices.Equal(got, []string{"theme=light; Path=/"}) || hints[0].Get("Link") == "" {
		t.Errorf("early hints = %q, want only the unrelated cookie and the Link header", hints[0])
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

func TestClearSessionsRepairsInvalidSessionRecords(t *testing.T) {
	values := operatorEnv(t)
	signIn(t, gatewayWith(t, values))
	cfg := loadConfig(t, values).Operator
	state, store, err := accountfile.Open(cfg.StorePath, accountfile.Bootstrap{}, accountfile.Options{
		NewProfileID: newToken, Validate: operator.ValidateState,
	})
	if err != nil {
		t.Fatal(err)
	}
	state.Sessions[0].LastSeen = state.Sessions[0].Created.Add(-time.Second)
	if err := store.Replace(state); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := clearSessions(cfg, &out); err != nil || out.String() != "cleared sessions: 1\n" {
		t.Fatalf("clearSessions = %q, %v", out.String(), err)
	}
	gatewayWith(t, values)
}
