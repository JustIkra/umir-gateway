package operatorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// savedCount is the number of commits the account store received.
func (s *fakeStore) savedCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.saved) }

// idleDeadline reads the session's idle deadline without extending it.
func (f *fixture) idleDeadline(session *http.Cookie) time.Time {
	f.t.Helper()
	_, current, err := f.accounts.Peek(session.Value)
	if err != nil {
		f.t.Fatalf("Peek: %v", err)
	}
	return current.IdleExpiresAt
}

func TestBackgroundRequestsDoNotExtendTheSession(t *testing.T) {
	f := loopbackFixture(t)
	up := &upstream{t: t}
	guarded := f.api.Protect(up)
	session, token := f.login()
	before := f.idleDeadline(session)
	f.clock.Advance(10 * time.Minute)
	saved := f.store.savedCount()
	background := map[string]string{ActivityHeader: "background"}
	for _, c := range []call{
		{method: http.MethodGet, path: "/api/warehouse/expiring-batches", cookies: []*http.Cookie{session}, header: background},
		{method: http.MethodPost, path: "/api/serving/order-confirmations", cookies: []*http.Cookie{session}, csrf: token, origin: testOrigin, header: background},
	} {
		if w := f.send(guarded, c); w.Code != http.StatusAccepted {
			t.Fatalf("background %s: %d %s", c.method, w.Code, w.Body)
		}
	}
	if got := f.idleDeadline(session); !got.Equal(before) || f.store.savedCount() != saved {
		t.Fatalf("background requests moved the idle deadline to %v or wrote %d times", got, f.store.savedCount()-saved)
	}
	// The same request without the header is the operator's action and extends the session.
	if w := f.send(guarded, call{method: http.MethodGet, path: "/api/warehouse/expiring-batches", cookies: []*http.Cookie{session}}); w.Code != http.StatusAccepted {
		t.Fatalf("ordinary GET: %d", w.Code)
	}
	if got := f.idleDeadline(session); !got.Equal(f.clock.Now().Add(30*time.Minute)) || f.store.savedCount() != saved+1 {
		t.Fatalf("ordinary GET: idle %v, writes %d", got, f.store.savedCount()-saved)
	}
}

func TestBackgroundRequestsPassTheSameChecks(t *testing.T) {
	f := loopbackFixture(t)
	up := &upstream{t: t}
	guarded := f.api.Protect(up)
	session, token := f.login()
	_, anonymous := f.anonymous()
	background := map[string]string{ActivityHeader: "background"}
	crossSite := map[string]string{ActivityHeader: "background", "Sec-Fetch-Site": "cross-site"}
	for _, tc := range []struct {
		name   string
		c      call
		status int
		code   string
	}{
		{"read without session", call{method: http.MethodGet, path: "/api/serving/menu", header: background}, http.StatusUnauthorized, "Unauthenticated"},
		{"write without origin", call{method: http.MethodPost, path: "/api/serving/orders", cookies: []*http.Cookie{session}, csrf: token, header: background}, http.StatusForbidden, "InvalidOrigin"},
		{"write cross-site", call{method: http.MethodPost, path: "/api/serving/orders", cookies: []*http.Cookie{session}, csrf: token, origin: testOrigin, header: crossSite}, http.StatusForbidden, "InvalidOrigin"},
		{"write without token", call{method: http.MethodPost, path: "/api/serving/orders", cookies: []*http.Cookie{session}, origin: testOrigin, header: background}, http.StatusForbidden, "InvalidCsrfToken"},
		{"write with anonymous token", call{method: http.MethodDelete, path: "/api/warehouse/items/1", cookies: []*http.Cookie{session}, csrf: anonymous, origin: testOrigin, header: background}, http.StatusForbidden, "InvalidCsrfToken"},
		{"TRACE", call{method: http.MethodTrace, path: "/api/serving/menu", cookies: []*http.Cookie{session}, header: background}, http.StatusMethodNotAllowed, "MethodNotAllowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantProblem(t, f.send(guarded, tc.c), tc.status, tc.code)
		})
	}
	if calls := up.calls(); len(calls) != 0 {
		t.Fatalf("rejected background requests reached the upstream: %v", calls)
	}
}

func TestOnlyTheExactBackgroundValueSkipsExtension(t *testing.T) {
	for _, values := range [][]string{{"Background"}, {"background "}, {"background", "background"}, {"foreground"}, {""}} {
		t.Run("", func(t *testing.T) {
			f := loopbackFixture(t)
			session, _ := f.login()
			f.clock.Advance(time.Minute)
			r := httptest.NewRequest(http.MethodGet, "/api/serving/menu", nil)
			r.AddCookie(session)
			r.Header[ActivityHeader] = values
			w := httptest.NewRecorder()
			f.api.Protect(&upstream{t: t}).ServeHTTP(w, r)
			if w.Code != http.StatusAccepted || !f.idleDeadline(session).Equal(f.clock.Now().Add(30*time.Minute)) {
				t.Errorf("%q: %d, idle %v; any other value counts as the operator's action", values, w.Code, f.idleDeadline(session))
			}
		})
	}
}

func TestBackgroundProfileReadDoesNotExtendTheSession(t *testing.T) {
	f := loopbackFixture(t)
	session, _ := f.login()
	before := f.idleDeadline(session)
	f.clock.Advance(10 * time.Minute)
	saved := f.store.savedCount()
	w := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}, header: map[string]string{ActivityHeader: "background"}})
	var body struct {
		Session struct {
			IdleExpiresAt string `json:"idleExpiresAt"`
		} `json:"session"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("background /me: %d %s", w.Code, w.Body)
	}
	if body.Session.IdleExpiresAt != timestamp(before) || f.store.savedCount() != saved {
		t.Fatalf("background /me reported %s and wrote %d times, want %s", body.Session.IdleExpiresAt, f.store.savedCount()-saved, timestamp(before))
	}
}

func TestActivityHeaderNeverReachesTheUpstream(t *testing.T) {
	var got http.Header
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.Header.Clone() })
	r := httptest.NewRequest(http.MethodGet, "/menu", nil)
	r.Header.Set(ActivityHeader, "background")
	StripCredentials(next).ServeHTTP(httptest.NewRecorder(), r)
	if _, ok := got[ActivityHeader]; ok {
		t.Errorf("forwarded headers = %v", got)
	}
}
