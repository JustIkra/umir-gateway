package operatorhttp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/operator"
)

const (
	testOrigin   = "http://127.0.0.1:8080"
	testPassword = "correct horse battery staple"
)

// start is noon in Moscow; responses must show it with the +03:00 offset.
var start = time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)

func fakeHash(password string) string { return "hash:" + hex.EncodeToString([]byte(password)) }

// fakeHasher keeps the tests fast: a "hash" is the hex of the password.
type fakeHasher struct{}

func (fakeHasher) Hash(password string) (string, error) { return fakeHash(password), nil }

func (fakeHasher) Verify(password, encoded string) (bool, error) {
	return fakeHash(password) == encoded, nil
}

func (fakeHasher) Check(encoded string) error {
	if !strings.HasPrefix(encoded, "hash:") {
		return errors.New("not a fake hash")
	}
	return nil
}

// fakeStore records committed accounts; after fail, every commit returns that error.
type fakeStore struct {
	mu    sync.Mutex
	err   error
	saved []operator.Account
}

func (s *fakeStore) Replace(next operator.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.saved = append(s.saved, next.Account)
	return nil
}

func (s *fakeStore) fail(err error) { s.mu.Lock(); defer s.mu.Unlock(); s.err = err }

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

type fixture struct {
	t        *testing.T
	origin   string
	cookies  cookieNames
	api      *API
	accounts *operator.Service
	store    *fakeStore
	clock    *clock
	logs     *bytes.Buffer
}

func newFixture(t *testing.T, mode CookieMode, origin string) *fixture {
	t.Helper()
	f := &fixture{t: t, origin: origin, store: &fakeStore{}, clock: &clock{now: start}, logs: &bytes.Buffer{}}
	var mu sync.Mutex
	issued := 0
	accounts, err := operator.NewService(operator.Account{
		ProfileID: "PROFILE1", Login: "operator", DisplayName: "Оператор",
		PasswordHash: fakeHash(testPassword), CredentialVersion: 1,
	}, operator.Options{
		Store: f.store, Hasher: fakeHasher{}, Now: f.clock.Now,
		NewToken: func() (string, error) {
			mu.Lock()
			defer mu.Unlock()
			issued++
			return fmt.Sprintf("tok-%d", issued), nil
		},
		IdleTimeout: operator.DefaultIdleTimeout, AbsoluteTimeout: operator.DefaultAbsoluteTimeout,
		MaxSessions: operator.DefaultMaxSessions, MaxAnonymous: operator.DefaultMaxAnonymous,
		AnonymousTTL: operator.DefaultAnonymousTTL, MaxVerifications: operator.DefaultMaxVerifications,
		MaxQueuedLogins: operator.DefaultMaxQueuedLogins, FailureLimit: operator.DefaultFailureLimit,
		FailureWindow: operator.DefaultFailureWindow, Cooldown: operator.DefaultCooldown,
	})
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Options{Accounts: accounts, Mode: mode, PublicOrigin: origin, Logger: log.New(f.logs, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	f.accounts, f.api, f.cookies = accounts, api, api.cookies
	return f
}

func loopbackFixture(t *testing.T) *fixture { return newFixture(t, ModeLoopback, testOrigin) }

// call is one request. Nothing is added implicitly: unsafe calls name their origin, token and cookies.
type call struct {
	method, path, body string
	cookies            []*http.Cookie
	csrf, origin       string
	header             map[string]string
}

// send serves c through h with request ID req-1.
func (f *fixture) send(h http.Handler, c call) *httptest.ResponseRecorder {
	f.t.Helper()
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	r := httptest.NewRequest(c.method, c.path, body)
	if c.body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.origin != "" {
		r.Header.Set("Origin", c.origin)
	}
	if c.csrf != "" {
		r.Header.Set(CSRFHeader, c.csrf)
	}
	for _, cookie := range c.cookies {
		r.AddCookie(cookie)
	}
	for key, value := range c.header {
		r.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	httpapi.WithRequestID(h, func() string { return "req-1" }).ServeHTTP(w, r)
	return w
}

func (f *fixture) do(c call) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.send(f.api, c)
}

func (f *fixture) json(v any) string {
	f.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func cookiesOf(t *testing.T, w *httptest.ResponseRecorder) map[string]*http.Cookie {
	t.Helper()
	cookies := map[string]*http.Cookie{}
	for _, line := range w.Header().Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatalf("Set-Cookie %q: %v", line, err)
		}
		cookies[cookie.Name] = cookie
	}
	return cookies
}

func csrfTokenOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.CSRFToken == "" {
		t.Fatalf("%d %q has no csrfToken", w.Code, w.Body)
	}
	return body.CSRFToken
}

// anonymous fetches a pre-auth cookie and its CSRF token.
func (f *fixture) anonymous() (*http.Cookie, string) {
	f.t.Helper()
	w := f.do(call{method: http.MethodGet, path: "/api/operator/csrf"})
	cookie := cookiesOf(f.t, w)[f.cookies.preauth]
	if w.Code != http.StatusOK || cookie == nil {
		f.t.Fatalf("csrf bootstrap: %d %v", w.Code, w.Header())
	}
	return cookie, csrfTokenOf(f.t, w)
}

// signIn posts the operator's login with password from a fresh anonymous context.
func (f *fixture) signIn(password string) *httptest.ResponseRecorder {
	f.t.Helper()
	preauth, token := f.anonymous()
	return f.do(call{
		method: http.MethodPost, path: "/api/operator/session",
		body:    f.json(map[string]string{"login": "operator", "password": password}),
		cookies: []*http.Cookie{preauth}, csrf: token, origin: f.origin,
	})
}

// login signs in and returns the session cookie and the session's CSRF token.
func (f *fixture) login() (*http.Cookie, string) {
	f.t.Helper()
	w := f.signIn(testPassword)
	var body struct {
		Session struct {
			CSRFToken string `json:"csrfToken"`
		} `json:"session"`
	}
	session := cookiesOf(f.t, w)[f.cookies.session]
	if w.Code != http.StatusOK || session == nil || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Session.CSRFToken == "" {
		f.t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return session, body.Session.CSRFToken
}

// wantProblem checks the envelope of an error response and returns it.
func wantProblem(t *testing.T, w *httptest.ResponseRecorder, status int, code string) httpapi.Problem {
	t.Helper()
	var p httpapi.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("%d %q is not a problem", w.Code, w.Body)
	}
	if w.Code != status || p.Code != code || p.RequestID != "req-1" ||
		w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("response = %d %+v %v, want %d %s", w.Code, p, w.Header(), status, code)
	}
	return p
}
