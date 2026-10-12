package operatorhttp

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// upstream records the methods it received and answers 202.
type upstream struct {
	t       *testing.T
	mu      sync.Mutex
	methods []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.methods = append(u.methods, r.Method)
	u.mu.Unlock()
	w.Header().Set("X-Upstream", "yes")
	w.WriteHeader(http.StatusAccepted)
	if _, err := io.WriteString(w, "accepted"); err != nil {
		u.t.Errorf("write upstream response: %v", err)
	}
}

func (u *upstream) calls() []string { u.mu.Lock(); defer u.mu.Unlock(); return slices.Clone(u.methods) }

func TestProtectRejectsBeforeDispatch(t *testing.T) {
	f := loopbackFixture(t)
	up := &upstream{t: t}
	guarded := f.api.Protect(up)
	session, token := f.login()
	_, anonymous := f.anonymous()
	forged := &http.Cookie{Name: "umir_operator_session", Value: "forged"}
	for _, tc := range []struct {
		name   string
		c      call
		status int
		code   string
	}{
		{"read without session", call{method: http.MethodGet, path: "/api/serving/menu"}, http.StatusUnauthorized, "Unauthenticated"},
		{"read with forged session", call{method: http.MethodGet, path: "/api/serving/menu", cookies: []*http.Cookie{forged}}, http.StatusUnauthorized, "Unauthenticated"},
		{"write without session", call{method: http.MethodPost, path: "/api/serving/orders", csrf: token, origin: testOrigin}, http.StatusUnauthorized, "Unauthenticated"},
		{"write without token", call{method: http.MethodPost, path: "/api/serving/orders", cookies: []*http.Cookie{session}, origin: testOrigin}, http.StatusForbidden, "InvalidCsrfToken"},
		{"write with anonymous token", call{method: http.MethodPut, path: "/api/warehouse/items/1", cookies: []*http.Cookie{session}, csrf: anonymous, origin: testOrigin}, http.StatusForbidden, "InvalidCsrfToken"},
		{"write without origin", call{method: http.MethodDelete, path: "/api/warehouse/items/1", cookies: []*http.Cookie{session}, csrf: token}, http.StatusForbidden, "InvalidOrigin"},
		{"write cross-site", call{method: http.MethodPatch, path: "/api/warehouse/items/1", cookies: []*http.Cookie{session}, csrf: token, origin: testOrigin,
			header: map[string]string{"Sec-Fetch-Site": "cross-site"}}, http.StatusForbidden, "InvalidOrigin"},
		{"TRACE", call{method: http.MethodTrace, path: "/api/serving/menu", cookies: []*http.Cookie{session}}, http.StatusMethodNotAllowed, "MethodNotAllowed"},
		{"PROPFIND", call{method: "PROPFIND", path: "/api/serving/menu", cookies: []*http.Cookie{session}, csrf: token, origin: testOrigin}, http.StatusMethodNotAllowed, "MethodNotAllowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.send(guarded, tc.c)
			wantProblem(t, w, tc.status, tc.code)
			if tc.status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE" {
				t.Errorf("Allow = %q", w.Header().Get("Allow"))
			}
		})
	}
	if calls := up.calls(); len(calls) != 0 {
		t.Fatalf("rejected requests reached the upstream: %v", calls)
	}
}

func TestProtectAdmitsTheSession(t *testing.T) {
	f := loopbackFixture(t)
	up := &upstream{t: t}
	guarded := f.api.Protect(up)
	session, token := f.login()
	methods := []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, method := range methods {
		c := call{method: method, path: "/api/serving/orders", cookies: []*http.Cookie{session}}
		if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
			c.csrf, c.origin = token, testOrigin
		}
		if w := f.send(guarded, c); w.Code != http.StatusAccepted || w.Header().Get("X-Upstream") != "yes" {
			t.Errorf("%s: %d %s", method, w.Code, w.Body)
		}
	}
	if calls := up.calls(); !slices.Equal(calls, methods) {
		t.Errorf("upstream calls = %v", calls)
	}
}

func TestProtectRejectsWhenOrdinaryActivityCannotBeStored(t *testing.T) {
	for _, tc := range []struct {
		name     string
		method   string
		storeErr error
		code     string
	}{
		{"safe known failure", http.MethodGet, fmt.Errorf("disk full: %w", operator.ErrStorageUnavailable), "SessionStorageUnavailable"},
		{"safe unknown outcome", http.MethodGet, errors.New("rename outcome unknown"), "SessionUpdateOutcomeUnknown"},
		{"unsafe known failure", http.MethodPost, fmt.Errorf("disk full: %w", operator.ErrStorageUnavailable), "SessionStorageUnavailable"},
		{"unsafe unknown outcome", http.MethodPost, errors.New("rename outcome unknown"), "SessionUpdateOutcomeUnknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := loopbackFixture(t)
			session, token := f.login()
			f.clock.Advance(time.Minute)
			f.store.fail(tc.storeErr)
			up := &upstream{t: t}
			c := call{method: tc.method, path: "/api/serving/orders", cookies: []*http.Cookie{session}}
			if tc.method != http.MethodGet {
				c.csrf, c.origin = token, testOrigin
			}
			w := f.send(f.api.Protect(up), c)
			wantProblem(t, w, http.StatusServiceUnavailable, tc.code)
			if calls := up.calls(); len(calls) != 0 {
				t.Fatalf("request reached the upstream after failed activity commit: %v", calls)
			}
		})
	}
}

func TestProtectDuringRecovery(t *testing.T) {
	f := loopbackFixture(t)
	up := &upstream{t: t}
	session, _ := f.login()
	f.store.fail(errors.New("disk vanished"))
	if _, err := f.accounts.UpdateDisplayName(session.Value, "Смена"); !errors.Is(err, operator.ErrUpdateOutcomeUnknown) {
		t.Fatalf("UpdateDisplayName = %v", err)
	}
	w := f.send(f.api.Protect(up), call{method: http.MethodGet, path: "/api/serving/menu", cookies: []*http.Cookie{session}})
	wantProblem(t, w, http.StatusServiceUnavailable, "AuthUnavailable")
	if len(up.calls()) != 0 {
		t.Fatal("request reached the upstream during recovery")
	}
}

func TestSessionExpiryDuringDispatchKeepsTheResponse(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	started, release := make(chan struct{}), make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusAccepted)
		if _, err := io.WriteString(w, "accepted"); err != nil {
			t.Errorf("write: %v", err)
		}
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- f.send(f.api.Protect(slow), call{method: http.MethodPost, path: "/api/serving/order-confirmations",
			cookies: []*http.Cookie{session}, csrf: token, origin: testOrigin})
	}()
	<-started
	f.clock.Advance(31 * time.Minute) // the session expires while the upstream works
	close(release)
	select {
	case w := <-done:
		if w.Code != http.StatusAccepted || w.Body.String() != "accepted" {
			t.Fatalf("in-flight response: %d %s", w.Code, w.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	up := &upstream{t: t}
	w := f.send(f.api.Protect(up), call{method: http.MethodGet, path: "/api/serving/menu", cookies: []*http.Cookie{session}})
	wantProblem(t, w, http.StatusUnauthorized, "Unauthenticated")
	if len(up.calls()) != 0 {
		t.Fatal("expired session reached the upstream")
	}
}

func TestStripCredentials(t *testing.T) {
	var got http.Header
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Clone() })
	r := httptest.NewRequest(http.MethodPost, "/orders", nil)
	r.Header.Add("Cookie", "theme=dark; umir_operator_session=S1; __Host-umir_operator_preauth=P1")
	r.Header.Add("Cookie", "UMIR_OPERATOR_SESSION=S2; lang=ru")
	r.Header.Set(CSRFHeader, "T1")
	r.Header.Set("X-Other", "kept")
	StripCredentials(next).ServeHTTP(httptest.NewRecorder(), r)
	if cookies := got.Values("Cookie"); !slices.Equal(cookies, []string{"theme=dark", "lang=ru"}) {
		t.Errorf("forwarded cookies = %q", cookies)
	}
	if got.Get(CSRFHeader) != "" || got.Get("X-Other") != "kept" {
		t.Errorf("forwarded headers = %v", got)
	}
	// The caller's request is left as it was.
	if len(r.Header.Values("Cookie")) != 2 || r.Header.Get(CSRFHeader) != "T1" {
		t.Errorf("original request changed: %v", r.Header)
	}
	only := httptest.NewRequest(http.MethodGet, "/menu", nil)
	only.Header.Set("Cookie", "umir_operator_session=S1")
	StripCredentials(next).ServeHTTP(httptest.NewRecorder(), only)
	if _, ok := got["Cookie"]; ok {
		t.Errorf("empty Cookie header forwarded: %v", got)
	}
}

func TestDropReservedCookies(t *testing.T) {
	response := &http.Response{Header: http.Header{"Set-Cookie": {
		"umir_operator_session=forged; Path=/",
		"theme=light; Path=/",
		"__Host-umir_operator_session=forged; Path=/; Secure",
		"__host-UMIR_operator_preauth=forged",
		"=umir_operator_session=forged; Path=/", // a browser sends a nameless cookie back as its value
		"=x",
		"lang=ru",
	}}}
	if err := DropReservedCookies(response); err != nil {
		t.Fatal(err)
	}
	if got := response.Header.Values("Set-Cookie"); !slices.Equal(got, []string{"theme=light; Path=/", "lang=ru"}) {
		t.Errorf("Set-Cookie = %q", got)
	}
}

func TestLoggedPathCannotForgeLines(t *testing.T) {
	f := loopbackFixture(t)
	w := f.send(f.api.Protect(&upstream{t: t}), call{
		method: http.MethodGet,
		path:   "/api/serving/menu%0Aoperator%20req-9%20POST%20/api/operator/session:%20200%20LoginOK",
	})
	wantProblem(t, w, http.StatusUnauthorized, "Unauthenticated")
	if logs := f.logs.String(); strings.Count(logs, "\n") != 1 {
		t.Errorf("one rejection wrote several log lines:\n%s", logs)
	}
}
