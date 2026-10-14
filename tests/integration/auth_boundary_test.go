package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/authclient"
	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

const authView = `{"user":{"userID":"11111111-1111-4111-8111-111111111111","login":"operator","displayName":"Operator","credentialVersion":"1"},"session":{"expiresAt":"2026-10-13T01:30:00+03:00","idleExpiresAt":"2026-10-13T01:30:00+03:00","absoluteExpiresAt":"2026-10-13T09:00:00+03:00","rememberMe":false,"csrfToken":"csrf-secret"}}`

func boundary(t *testing.T, handler http.Handler) (http.Handler, *bytes.Buffer) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := authclient.New(authclient.Options{URL: target, ServiceKey: "gateway-auth-secret", Timeout: time.Second, Transport: &http.Transport{}})
	if err != nil {
		t.Fatal(err)
	}
	logs := new(bytes.Buffer)
	api, err := operatorhttp.NewRemote(operatorhttp.RemoteOptions{
		Auth: client, Mode: operatorhttp.ModeSecure, PublicOrigin: "https://umir.test", Logger: log.New(logs, "", 0),
		Now:          func() time.Time { return time.Date(2026, 10, 13, 1, 0, 0, 0, time.FixedZone("MSK", 10800)) },
		NewCommandID: func() string { return "alias-command" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return api, logs
}

func callAuth(api http.Handler, method, path, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://umir.test")
	r.Header.Set("X-CSRF-Token", "csrf-secret")
	r.AddCookie(&http.Cookie{Name: "__Host-umir_operator_session", Value: "session-secret"})
	if mutate != nil {
		mutate(r)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	return w
}

func reply(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if _, err := io.WriteString(w, body); err != nil {
		t.Error(err)
	}
}

func TestAuthLoginCompatibilityAndCredentialIsolation(t *testing.T) {
	var received map[string]any
	api, logs := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/auth/v1/public/session" || r.Method != http.MethodPost ||
			r.Header.Get("X-Umir-Service-Key") != "gateway-auth-secret" || r.Header.Get("X-Umir-Session") != "session-secret" ||
			r.Header.Get("X-Umir-CSRF-Token") != "csrf-secret" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("private request = %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		w.Header().Add("Set-Cookie", "__Host-umir_operator_session=forged; Secure; Path=/")
		w.Header().Set("Authorization", "private-jwt-secret")
		reply(t, w, `{"view":`+authView+`,"sessionToken":"new-session-secret"}`)
	}))
	w := callAuth(api, http.MethodPost, "/api/operator/session", `{"login":"operator","password":" password-secret "}`, nil)
	if w.Code != http.StatusOK || received["password"] != " password-secret " || received["commandID"] != "alias-command" {
		t.Fatalf("login = %d %s, request = %v", w.Code, w.Body, received)
	}
	if strings.Contains(w.Body.String(), "sessionToken") || strings.Contains(w.Body.String(), "credentialVersion") ||
		strings.Contains(w.Body.String(), "new-session-secret") || !strings.Contains(w.Body.String(), `"operator"`) ||
		w.Header().Get("Authorization") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("public credentials/view = %v %s", w.Header(), w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "new-session-secret" || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Domain != "" || !cookies[0].Expires.IsZero() {
		t.Fatalf("session cookies = %v", cookies)
	}
	for _, secret := range []string{"password-secret", "new-session-secret", "session-secret", "gateway-auth-secret", "private-jwt-secret"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("secret in logs: %s", secret)
		}
	}
}

func TestAuthOriginAndCSRFRejectBeforeTransport(t *testing.T) {
	var calls atomic.Int32
	api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); reply(t, w, "{}") }))
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		code   string
	}{
		{"duplicate origin", func(r *http.Request) { r.Header.Add("Origin", "https://umir.test") }, "InvalidOrigin"},
		{"missing CSRF", func(r *http.Request) { r.Header.Del("X-CSRF-Token") }, "InvalidCsrfToken"},
		{"browser service credential", func(r *http.Request) { r.Header.Set("X-Umir-Service-Key", "spoof") }, "InvalidRequest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := callAuth(api, http.MethodPost, "/api/operator/session", `{"login":"operator","password":"password-secret"}`, tc.mutate)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), tc.code) {
				t.Errorf("refusal = %d %s", w.Code, w.Body)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("rejected requests reached Auth: %d", calls.Load())
	}
}

func TestAuthMalformedRepliesFailClosedWithoutCookies(t *testing.T) {
	for _, body := range []string{
		`{}`, `{"view":` + authView + `}`, `{"view":` + authView + `,"sessionToken":"secret"} {}`,
		`{"view":` + authView + `,"sessionToken":"secret","unexpected":true}`,
		`{"view":` + strings.Replace(authView, `"rememberMe":false`, `"rememberMe":false,"rememberMe":true`, 1) + `,"sessionToken":"secret"}`,
		`{"view":` + strings.Replace(authView, `"expiresAt":"2026-10-13T01:30:00+03:00"`, `"expiresAt":null`, 1) + `,"sessionToken":"secret"}`,
		`{"view":` + strings.ReplaceAll(authView, "2026-10-13T01:30:00+03:00", "2026-10-13T01:30:00,1+03:00") + `,"sessionToken":"secret"}`,
		`{"view":` + strings.ReplaceAll(authView, "2026-10-13T01:30:00+03:00", "2026-10-13T01:30:00.1234567890+03:00") + `,"sessionToken":"secret"}`,
	} {
		t.Run(body, func(t *testing.T) {
			var calls atomic.Int32
			api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); reply(t, w, body) }))
			w := callAuth(api, http.MethodPost, "/api/operator/session", `{"login":"operator","password":"password-secret"}`, nil)
			if w.Code != http.StatusServiceUnavailable || len(w.Header().Values("Set-Cookie")) != 0 || calls.Load() != 1 {
				t.Fatalf("malformed reply = %d %s %v, calls=%d", w.Code, w.Body, w.Header(), calls.Load())
			}
		})
	}
}

type timeoutTransport struct{ calls atomic.Int32 }

func (t *timeoutTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestAuthTimeoutDoesNotRetryUncertainMutation(t *testing.T) {
	target, err := url.Parse("http://auth.test")
	if err != nil {
		t.Fatal(err)
	}
	transport := new(timeoutTransport)
	client, err := authclient.New(authclient.Options{URL: target, ServiceKey: "secret", Timeout: time.Millisecond, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Login(context.Background(), operatorhttp.BrowserContext{PreauthToken: "preauth", CSRFToken: "csrf"}, operatorhttp.LoginInput{Login: "operator", Password: "secret", CommandID: "one"})
	var failure *operatorhttp.AuthFailure
	if !errors.As(err, &failure) || failure.Outcome != "unknown" || transport.calls.Load() != 1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout=%v, calls=%d", err, transport.calls.Load())
	}
}

func TestAuthBackgroundAndDurableRefusals(t *testing.T) {
	for _, tc := range []struct {
		status     int
		body, code string
	}{
		{200, authView, ""},
		{503, `{"code":"AuthUpdateOutcomeUnknown","outcome":"unknown","message":"private secret","retryable":true}`, "SessionUpdateOutcomeUnknown"},
		{401, `{"code":"Unauthenticated","outcome":"unavailable","message":"expired","retryable":false}`, "Unauthenticated"},
	} {
		t.Run(tc.body, func(t *testing.T) {
			api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Umir-Activity") != "background" {
					t.Errorf("activity=%q", r.Header.Get("X-Umir-Activity"))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				reply(t, w, tc.body)
			}))
			w := callAuth(api, http.MethodGet, "/api/operator/me", "", func(r *http.Request) { r.Header.Set("X-Umir-Activity", "background") })
			if w.Code != tc.status || (tc.code != "" && !strings.Contains(w.Body.String(), tc.code)) || strings.Contains(w.Body.String(), "private secret") {
				t.Fatalf("me=%d %s", w.Code, w.Body)
			}
		})
	}
}

func TestAuthRequiredInputsAndUnknownOutcome(t *testing.T) {
	var calls atomic.Int32
	api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); reply(t, w, `{}`) }))
	for _, tc := range []struct{ path, body string }{
		{"/api/operator/me/display-name", `{}`},
		{"/api/operator/me/password", `{"newPassword":"next-password"}`},
		{"/api/v2/me/password", `{"currentPassword":"old-password","commandID":"one"}`},
	} {
		w := callAuth(api, http.MethodPatch, tc.path, tc.body, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("missing required input %s=%d %s", tc.path, w.Code, w.Body)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("invalid input sent to Auth: %d", calls.Load())
	}
	w := callAuth(api, http.MethodPost, "/api/operator/session", `{"login":"operator","password":"password-secret"}`, nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "SessionUpdateOutcomeUnknown") {
		t.Errorf("unknown mutation=%d %s", w.Code, w.Body)
	}
}

func TestAuthCSRFV2IdentityAndProfileMutation(t *testing.T) {
	var calls atomic.Int32
	api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/internal/auth/v1/public/csrf":
			if r.Header.Get("X-Umir-Activity") != "background" {
				t.Error("csrf extended activity")
			}
			reply(t, w, `{"csrfToken":"preauth-csrf","preauthToken":"preauth-secret","expiresAt":"2026-10-13T01:30:00+03:00"}`)
		case "/internal/auth/v1/public/session":
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			var input map[string]string
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input["commandID"] != "frozen-command" {
				t.Error("v2 identity was replaced")
			}
			reply(t, w, `{"view":`+authView+`,"sessionToken":"new-session"}`)
		case "/internal/auth/v1/public/me/display-name":
			reply(t, w, `{"userID":"11111111-1111-4111-8111-111111111111","login":"operator","displayName":"Changed","credentialVersion":"1"}`)
		case "/internal/auth/v1/public/me/password":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
		}
	}))
	w := callAuth(api, http.MethodGet, "/api/operator/csrf", "", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "preauth-secret") || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].Value != "preauth-secret" {
		t.Fatalf("csrf=%d %s %v", w.Code, w.Body, w.Header())
	}
	w = callAuth(api, http.MethodPost, "/api/v2/session", `{"login":"operator","password":"password-secret","commandID":"frozen-command"}`, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"user"`) || strings.Contains(w.Body.String(), "sessionToken") {
		t.Fatalf("v2 login=%d %s", w.Code, w.Body)
	}
	w = callAuth(api, http.MethodPatch, "/api/operator/me/display-name", `{"displayName":"Changed"}`, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"operator"`) || strings.Contains(w.Body.String(), "credentialVersion") {
		t.Fatalf("profile=%d %s", w.Code, w.Body)
	}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodDelete, "/api/operator/session", ""},
		{http.MethodPatch, "/api/operator/me/password", `{"currentPassword":"old-password","newPassword":"new-password"}`},
	} {
		w = callAuth(api, tc.method, tc.path, tc.body, nil)
		if w.Code != 204 || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
			t.Fatalf("revocation=%d %s %v", w.Code, w.Body, w.Header())
		}
	}
	if calls.Load() != 5 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestAuthPasswordLimitRequiresDefiniteRevocation(t *testing.T) {
	for _, outcome := range []string{"not_committed", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				reply(t, w, `{"code":"PasswordChangeRateLimited","outcome":"`+outcome+`","message":"paused","retryable":false,"sessionRevoked":true}`)
			}))
			w := callAuth(api, http.MethodPatch, "/api/operator/me/password", `{"currentPassword":"old-password","newPassword":"new-password"}`, nil)
			if outcome == "not_committed" {
				if w.Code != 429 || w.Header().Get("Retry-After") != "60" || len(w.Result().Cookies()) != 1 || w.Result().Cookies()[0].MaxAge != -1 {
					t.Fatalf("definite limit=%d %s %v", w.Code, w.Body, w.Header())
				}
			} else if w.Code != 503 || len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), "AccountUpdateOutcomeUnknown") {
				t.Fatalf("unknown limit=%d %s %v", w.Code, w.Body, w.Header())
			}
		})
	}
}

func TestAuthV2LocalErrorsAndBodyLimit(t *testing.T) {
	var calls atomic.Int32
	api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		reply(t, w, `{"view":`+authView+`,"sessionToken":"new-session"}`)
	}))
	w := callAuth(api, http.MethodPost, "/api/v2/session", `{"login":"operator","password":"password-secret","commandID":"one"}`, func(r *http.Request) { r.Header.Del("Origin") })
	var problem struct {
		Code, Outcome string
		Retryable     *bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if w.Code != 403 || problem.Code != "InvalidOrigin" || problem.Outcome != "not_committed" || problem.Retryable == nil || *problem.Retryable {
		t.Errorf("v2 local refusal=%d %s", w.Code, w.Body)
	}
	w = callAuth(api, http.MethodPost, "/api/v2/session", `{"login":"operator","password":"password-secret","commandID":"expiration/reserved"}`, nil)
	if w.Code != 400 || calls.Load() != 0 {
		t.Errorf("reserved command=%d %s, calls=%d", w.Code, w.Body, calls.Load())
	}
	w = callAuth(api, http.MethodPost, "/api/v2/session", `{"login":"operator","password":"password-secret","commandID":"`+strings.Repeat("c", 9<<10)+`"}`, nil)
	if w.Code != 200 {
		t.Errorf("valid v2 request under 1 MiB=%d %s", w.Code, w.Body)
	}
}

func TestAuthAliasPreservesFractionalDeadlineInstants(t *testing.T) {
	api, _ := boundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reply(t, w, strings.ReplaceAll(authView, "2026-10-13T01:30:00+03:00", "2026-10-13T01:30:00.123456789+03:00"))
	}))
	w := callAuth(api, http.MethodGet, "/api/operator/me", "", nil)
	if w.Code != 200 || strings.Count(w.Body.String(), "2026-10-13T01:30:00.123456789+03:00") != 2 {
		t.Fatalf("deadline changed=%d %s", w.Code, w.Body)
	}
}
