package operatorhttp

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

func TestNewRejectsInconsistentSetup(t *testing.T) {
	f := loopbackFixture(t)
	logger := log.New(io.Discard, "", 0)
	for name, opts := range map[string]Options{
		"secure over http":    {Accounts: f.accounts, Logger: logger, Mode: ModeSecure, PublicOrigin: testOrigin},
		"loopback over https": {Accounts: f.accounts, Logger: logger, Mode: ModeLoopback, PublicOrigin: "https://example.org"},
		"unknown mode":        {Accounts: f.accounts, Logger: logger, Mode: "insecure", PublicOrigin: testOrigin},
		"no origin":           {Accounts: f.accounts, Logger: logger, Mode: ModeLoopback},
		"no accounts":         {Logger: logger, Mode: ModeLoopback, PublicOrigin: testOrigin},
		"no logger":           {Accounts: f.accounts, Mode: ModeLoopback, PublicOrigin: testOrigin},
	} {
		if _, err := New(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCSRFBootstrapCreatesNoSession(t *testing.T) {
	f := loopbackFixture(t)
	w := f.do(call{method: http.MethodGet, path: "/api/operator/csrf"})
	token := csrfTokenOf(t, w)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response: %d %v", w.Code, w.Header())
	}
	cookies := cookiesOf(t, w)
	preauth := cookies["umir_operator_preauth"]
	if preauth == nil || preauth.Value == "" || !preauth.HttpOnly || preauth.SameSite != http.SameSiteStrictMode ||
		preauth.Path != "/" || preauth.Domain != "" || preauth.Secure || len(cookies) != 1 {
		t.Fatalf("cookies = %v", w.Header().Values("Set-Cookie"))
	}
	// The same context is reused, so no new cookie is set.
	again := f.do(call{method: http.MethodGet, path: "/api/operator/csrf", cookies: []*http.Cookie{preauth}})
	if csrfTokenOf(t, again) != token || len(again.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("second bootstrap: %v %s", again.Header(), again.Body)
	}
	// The pre-auth cookie is not a session.
	me := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{preauth}})
	wantProblem(t, me, http.StatusUnauthorized, "Unauthenticated")
}

func TestSecureModeCookies(t *testing.T) {
	f := newFixture(t, ModeSecure, "https://example.org")
	w := f.do(call{method: http.MethodGet, path: "/api/operator/csrf"})
	preauth := cookiesOf(t, w)["__Host-umir_operator_preauth"]
	if preauth == nil || !preauth.Secure || !preauth.HttpOnly || preauth.SameSite != http.SameSiteStrictMode ||
		preauth.Path != "/" || preauth.Domain != "" {
		t.Fatalf("pre-auth cookie = %v", w.Header().Values("Set-Cookie"))
	}
	login := f.signIn(testPassword)
	session := cookiesOf(t, login)["__Host-umir_operator_session"]
	if login.Code != http.StatusOK || session == nil || !session.Secure || !session.HttpOnly ||
		session.SameSite != http.SameSiteStrictMode || session.Path != "/" || session.Domain != "" {
		t.Fatalf("login: %d %v", login.Code, login.Header().Values("Set-Cookie"))
	}
}

func TestLoginOpensSession(t *testing.T) {
	f := loopbackFixture(t)
	preauth, token := f.anonymous()
	login := call{
		method: http.MethodPost, path: "/api/operator/session",
		body:    f.json(map[string]string{"login": "operator", "password": testPassword}),
		cookies: []*http.Cookie{preauth}, csrf: token, origin: testOrigin,
	}
	w := f.do(login)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var body struct {
		Operator operatorView `json:"operator"`
		Session  sessionView  `json:"session"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Operator != (operatorView{ID: "PROFILE1", Login: "operator", DisplayName: "Оператор"}) {
		t.Errorf("operator = %+v", body.Operator)
	}
	if body.Session.ExpiresAt != "2026-10-11T12:30:00+03:00" || body.Session.IdleExpiresAt != body.Session.ExpiresAt ||
		body.Session.AbsoluteExpiresAt != "2026-10-11T20:00:00+03:00" || body.Session.CSRFToken == "" ||
		body.Session.CSRFToken == token {
		t.Errorf("session = %+v", body.Session)
	}
	cookies := cookiesOf(t, w)
	session := cookies["umir_operator_session"]
	if session == nil || session.Value == "" || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" {
		t.Fatalf("session cookie = %v", w.Header().Values("Set-Cookie"))
	}
	if cleared := cookies["umir_operator_preauth"]; cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("pre-auth cookie not cleared: %v", w.Header().Values("Set-Cookie"))
	}
	// The anonymous context is spent: replaying the login gets no session.
	replay := f.do(login)
	wantProblem(t, replay, http.StatusForbidden, "InvalidCsrfToken")
	me := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}})
	if me.Code != http.StatusOK {
		t.Errorf("me: %d %s", me.Code, me.Body)
	}
}

func TestLoginRejections(t *testing.T) {
	f := loopbackFixture(t)
	preauth, token := f.anonymous()
	credentials := func(login, password string) string {
		return f.json(map[string]string{"login": login, "password": password})
	}
	valid := func() call {
		return call{
			method: http.MethodPost, path: "/api/operator/session", body: credentials("operator", testPassword),
			cookies: []*http.Cookie{preauth}, csrf: token, origin: testOrigin,
		}
	}
	bodies := map[string]string{}
	for _, tc := range []struct {
		name   string
		change func(*call)
		status int
		code   string
	}{
		{"no origin", func(c *call) { c.origin = "" }, http.StatusForbidden, "InvalidOrigin"},
		{"other origin", func(c *call) { c.origin = "http://127.0.0.1:9999" }, http.StatusForbidden, "InvalidOrigin"},
		{"cross-site fetch", func(c *call) { c.header = map[string]string{"Sec-Fetch-Site": "cross-site"} }, http.StatusForbidden, "InvalidOrigin"},
		{"same-site fetch", func(c *call) { c.header = map[string]string{"Sec-Fetch-Site": "same-site"} }, http.StatusForbidden, "InvalidOrigin"},
		{"no token", func(c *call) { c.csrf = "" }, http.StatusForbidden, "InvalidCsrfToken"},
		{"token of another context", func(c *call) { c.csrf = "tok-999" }, http.StatusForbidden, "InvalidCsrfToken"},
		{"no pre-auth cookie", func(c *call) { c.cookies = nil }, http.StatusForbidden, "InvalidCsrfToken"},
		{"form body", func(c *call) { c.header = map[string]string{"Content-Type": "application/x-www-form-urlencoded"} }, http.StatusUnsupportedMediaType, "UnsupportedMediaType"},
		{"too large", func(c *call) { c.body = credentials("operator", strings.Repeat("x", 9000)) }, http.StatusRequestEntityTooLarge, "PayloadTooLarge"},
		{"malformed", func(c *call) { c.body = `{"login":` }, http.StatusBadRequest, "InvalidRequest"},
		{"unknown field", func(c *call) { c.body = `{"login":"operator","password":"x","remember":true}` }, http.StatusBadRequest, "InvalidRequest"},
		{"trailing data", func(c *call) { c.body = credentials("operator", testPassword) + `{}` }, http.StatusBadRequest, "InvalidRequest"},
		{"missing password", func(c *call) { c.body = `{"login":"operator"}` }, http.StatusBadRequest, "InvalidRequest"},
		{"wrong password", func(c *call) { c.body = credentials("operator", "wrong password!") }, http.StatusUnauthorized, "InvalidCredentials"},
		{"unknown login", func(c *call) { c.body = credentials("nobody", testPassword) }, http.StatusUnauthorized, "InvalidCredentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.change(&c)
			w := f.do(c)
			wantProblem(t, w, tc.status, tc.code)
			if _, ok := cookiesOf(t, w)["umir_operator_session"]; ok {
				t.Error("rejected login set a session cookie")
			}
			bodies[tc.name] = w.Body.String()
		})
	}
	if bodies["wrong password"] != bodies["unknown login"] {
		t.Errorf("responses reveal whether the login exists: %s vs %s", bodies["wrong password"], bodies["unknown login"])
	}
}

func TestLoginRateLimitHasRetryAfter(t *testing.T) {
	f := loopbackFixture(t)
	for range operator.DefaultFailureLimit {
		wantProblem(t, f.signIn("wrong password!"), http.StatusUnauthorized, "InvalidCredentials")
	}
	limited := f.signIn(testPassword)
	wantProblem(t, limited, http.StatusTooManyRequests, "LoginRateLimited")
	if got := limited.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q", got)
	}
	f.clock.Advance(operator.DefaultCooldown)
	if w := f.signIn(testPassword); w.Code != http.StatusOK {
		t.Errorf("after the cooldown: %d %s", w.Code, w.Body)
	}
}

func TestLoginWithLiveSessionRotatesIt(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	// With a live session, /csrf returns its token and sets no pre-auth cookie.
	bootstrap := f.do(call{method: http.MethodGet, path: "/api/operator/csrf", cookies: []*http.Cookie{session}})
	if csrfTokenOf(t, bootstrap) != token || len(bootstrap.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("csrf with session: %v %s", bootstrap.Header(), bootstrap.Body)
	}
	w := f.do(call{
		method: http.MethodPost, path: "/api/operator/session",
		body:    f.json(map[string]string{"login": "operator", "password": testPassword}),
		cookies: []*http.Cookie{session}, csrf: token, origin: testOrigin,
	})
	rotated := cookiesOf(t, w)["umir_operator_session"]
	if w.Code != http.StatusOK || rotated == nil || rotated.Value == session.Value {
		t.Fatalf("relogin: %d %v", w.Code, w.Header().Values("Set-Cookie"))
	}
	old := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}})
	wantProblem(t, old, http.StatusUnauthorized, "Unauthenticated")
}

func TestMeReturnsAndExtendsTheSession(t *testing.T) {
	f := loopbackFixture(t)
	session, _ := f.login()
	f.clock.Advance(20 * time.Minute)
	w := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}})
	var body accountView
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK || body.Session == nil {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	if body.Session.IdleExpiresAt != "2026-10-11T12:50:00+03:00" || body.Session.ExpiresAt != body.Session.IdleExpiresAt ||
		body.Session.AbsoluteExpiresAt != "2026-10-11T20:00:00+03:00" || body.Operator.Login != "operator" {
		t.Errorf("me = %+v %+v", body.Operator, body.Session)
	}
	head := f.do(call{method: http.MethodHead, path: "/api/operator/me", cookies: []*http.Cookie{session}})
	if head.Code != http.StatusOK {
		t.Errorf("HEAD me: %d", head.Code)
	}
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/me"}), http.StatusUnauthorized, "Unauthenticated")
	forged := &http.Cookie{Name: "umir_operator_session", Value: "tok-999"}
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{forged}}),
		http.StatusUnauthorized, "Unauthenticated")
}

func TestLogoutIsIdempotent(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	logout := func(cookies []*http.Cookie, token, origin string) *httptest.ResponseRecorder {
		return f.do(call{method: http.MethodDelete, path: "/api/operator/session", cookies: cookies, csrf: token, origin: origin})
	}
	wantProblem(t, logout([]*http.Cookie{session}, token, ""), http.StatusForbidden, "InvalidOrigin")
	wantProblem(t, logout([]*http.Cookie{session}, "tok-999", testOrigin), http.StatusForbidden, "InvalidCsrfToken")
	w := logout([]*http.Cookie{session}, token, testOrigin)
	if cleared := cookiesOf(t, w)["umir_operator_session"]; w.Code != http.StatusNoContent || cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("logout: %d %v", w.Code, w.Header().Values("Set-Cookie"))
	}
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}}),
		http.StatusUnauthorized, "Unauthenticated")
	// Without a live session, logout needs an anonymous token and still answers 204.
	wantProblem(t, logout([]*http.Cookie{session}, token, testOrigin), http.StatusForbidden, "InvalidCsrfToken")
	preauth, anonymous := f.anonymous()
	if w := logout([]*http.Cookie{session, preauth}, anonymous, testOrigin); w.Code != http.StatusNoContent {
		t.Errorf("logout of a revoked session: %d %s", w.Code, w.Body)
	}
	if w := logout([]*http.Cookie{preauth}, anonymous, testOrigin); w.Code != http.StatusNoContent {
		t.Errorf("logout without a session: %d %s", w.Code, w.Body)
	}
	// An expired session is logged out the same way.
	expired, expiredToken := f.login()
	f.clock.Advance(31 * time.Minute)
	wantProblem(t, logout([]*http.Cookie{expired}, expiredToken, testOrigin), http.StatusForbidden, "InvalidCsrfToken")
	fresh, freshToken := f.anonymous()
	if w := logout([]*http.Cookie{expired, fresh}, freshToken, testOrigin); w.Code != http.StatusNoContent {
		t.Errorf("logout of an expired session: %d %s", w.Code, w.Body)
	}
}

func TestUnknownRoutesAndMethods(t *testing.T) {
	f := loopbackFixture(t)
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/unknown"}), http.StatusNotFound, "NotFound")
	for _, tc := range []struct{ method, path, allow string }{
		{http.MethodPut, "/api/operator/session", "DELETE, POST"},
		{http.MethodPost, "/api/operator/me", "GET, HEAD"},
		{http.MethodPost, "/api/operator/csrf", "GET, HEAD"},
	} {
		w := f.do(call{method: tc.method, path: tc.path})
		wantProblem(t, w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		if got := w.Header().Get("Allow"); got != tc.allow {
			t.Errorf("%s %s Allow = %q, want %q", tc.method, tc.path, got, tc.allow)
		}
	}
}

func TestRecoveryAllowsOnlyAnonymousCSRFAndLogout(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	f.store.fail(errors.New("disk vanished"))
	if _, err := f.accounts.UpdateDisplayName(session.Value, "Смена"); !errors.Is(err, operator.ErrUpdateOutcomeUnknown) {
		t.Fatalf("UpdateDisplayName = %v", err)
	}
	// /csrf ignores the old session and issues an anonymous token.
	bootstrap := f.do(call{method: http.MethodGet, path: "/api/operator/csrf", cookies: []*http.Cookie{session}})
	anonymous := csrfTokenOf(t, bootstrap)
	preauth := cookiesOf(t, bootstrap)["umir_operator_preauth"]
	if anonymous == token || preauth == nil {
		t.Fatalf("csrf during recovery: %v %s", bootstrap.Header(), bootstrap.Body)
	}
	login := f.do(call{
		method: http.MethodPost, path: "/api/operator/session",
		body:    f.json(map[string]string{"login": "operator", "password": testPassword}),
		cookies: []*http.Cookie{preauth}, csrf: anonymous, origin: testOrigin,
	})
	wantProblem(t, login, http.StatusServiceUnavailable, "AuthUnavailable")
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}}),
		http.StatusServiceUnavailable, "AuthUnavailable")
	logout := f.do(call{
		method: http.MethodDelete, path: "/api/operator/session",
		cookies: []*http.Cookie{session, preauth}, csrf: anonymous, origin: testOrigin,
	})
	if logout.Code != http.StatusNoContent {
		t.Errorf("logout during recovery: %d %s", logout.Code, logout.Body)
	}
}

func TestRememberMeKeepsTheCookieUntilTheAbsoluteDeadline(t *testing.T) {
	f := loopbackFixture(t)
	for _, tc := range []struct {
		name, extra string
		persistent  bool
	}{
		{"remember me", `,"rememberMe":true`, true},
		{"explicitly not", `,"rememberMe":false`, false},
		{"field absent", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preauth, token := f.anonymous()
			w := f.do(call{
				method: http.MethodPost, path: "/api/operator/session",
				body:    `{"login":"operator","password":"` + testPassword + `"` + tc.extra + `}`,
				cookies: []*http.Cookie{preauth}, csrf: token, origin: testOrigin,
			})
			session := cookiesOf(t, w)["umir_operator_session"]
			if w.Code != http.StatusOK || session == nil {
				t.Fatalf("login: %d %s", w.Code, w.Body)
			}
			// The server deadlines do not change; only the browser keeps the cookie across restarts.
			if persistent := !session.Expires.IsZero(); persistent != tc.persistent ||
				tc.persistent && !session.Expires.Equal(f.clock.Now().Add(operator.DefaultAbsoluteTimeout)) {
				t.Errorf("Expires = %v, want persistent %v", session.Expires, tc.persistent)
			}
			if session.MaxAge != 0 {
				t.Errorf("Max-Age = %d", session.MaxAge)
			}
		})
	}
	preauth, token := f.anonymous()
	wantProblem(t, f.do(call{
		method: http.MethodPost, path: "/api/operator/session",
		body:    `{"login":"operator","password":"` + testPassword + `","rememberMe":"yes"}`,
		cookies: []*http.Cookie{preauth}, csrf: token, origin: testOrigin,
	}), http.StatusBadRequest, "InvalidRequest")
}
