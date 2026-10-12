package operatorhttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

func TestPasswordChangeRateLimited(t *testing.T) {
	f := loopbackFixture(t)
	caller, callerToken := f.login()
	other, otherToken := f.login()
	change := func(session *http.Cookie, token, current string) *httptest.ResponseRecorder {
		return f.patch("/api/operator/me/password",
			f.json(map[string]string{"currentPassword": current, "newPassword": newPassword}), session, token)
	}
	for range operator.DefaultFailureLimit - 1 {
		w := change(caller, callerToken, "wrong current password")
		wantProblem(t, w, http.StatusForbidden, "CurrentPasswordIncorrect")
		if strings.Contains(w.Body.String(), "sessionRevoked") {
			t.Errorf("sessionRevoked outside PasswordChangeRateLimited: %s", w.Body)
		}
	}
	// The fifth wrong password revokes the calling session and clears its cookie.
	w := change(caller, callerToken, "wrong current password")
	p := wantProblem(t, w, http.StatusTooManyRequests, "PasswordChangeRateLimited")
	if p.SessionRevoked == nil || !*p.SessionRevoked || w.Header().Get("Retry-After") != "60" {
		t.Errorf("fifth wrong password: Retry-After %q, %s", w.Header().Get("Retry-After"), w.Body)
	}
	if cleared := cookiesOf(t, w)["umir_operator_session"]; cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("session cookie not cleared: %v", w.Header().Values("Set-Cookie"))
	}
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{caller}}),
		http.StatusUnauthorized, "Unauthenticated")
	// During the cooldown another session is refused, keeps its cookie and stays signed in.
	f.clock.Advance(20*time.Second + 500*time.Millisecond)
	w = change(other, otherToken, testPassword)
	p = wantProblem(t, w, http.StatusTooManyRequests, "PasswordChangeRateLimited")
	if p.SessionRevoked == nil || *p.SessionRevoked || w.Header().Get("Retry-After") != "40" {
		t.Errorf("change during the cooldown: Retry-After %q, %s", w.Header().Get("Retry-After"), w.Body)
	}
	if cookies := w.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("cookie changed during the cooldown: %v", cookies)
	}
	if me := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{other}}); me.Code != http.StatusOK {
		t.Errorf("other session during the cooldown: %d %s", me.Code, me.Body)
	}
}

func TestFailedRevocationAnswersTheStorageError(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	change := func() *httptest.ResponseRecorder {
		return f.patch("/api/operator/me/password",
			f.json(map[string]string{"currentPassword": "wrong current password", "newPassword": newPassword}), session, token)
	}
	for range operator.DefaultFailureLimit - 1 {
		wantProblem(t, change(), http.StatusForbidden, "CurrentPasswordIncorrect")
	}
	f.store.fail(fmt.Errorf("disk full: %w", operator.ErrStorageUnavailable))
	w := change()
	wantProblem(t, w, http.StatusServiceUnavailable, "SessionStorageUnavailable")
	if strings.Contains(w.Body.String(), "sessionRevoked") || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("failed revocation reported as revoked: %v %s", w.Header(), w.Body)
	}
}
