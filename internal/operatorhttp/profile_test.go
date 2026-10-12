package operatorhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// commits returns the committed accounts that changed the account; session-only commits are skipped.
func (s *fakeStore) commits() []operator.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	var changes []operator.Account
	previous := s.initial
	for _, account := range s.saved {
		if account != previous {
			changes = append(changes, account)
		}
		previous = account
	}
	return changes
}

const newPassword = "new correct horse battery staple"

// patch sends an account change from the public origin with session and token.
func (f *fixture) patch(path, body string, session *http.Cookie, token string) *httptest.ResponseRecorder {
	f.t.Helper()
	var cookies []*http.Cookie
	if session != nil {
		cookies = []*http.Cookie{session}
	}
	return f.do(call{method: http.MethodPatch, path: path, body: body, cookies: cookies, csrf: token, origin: testOrigin})
}

func TestUpdateDisplayName(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	w := f.patch("/api/operator/me/display-name", `{"displayName":"  Смена  "}`, session, token)
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	var profile operatorView
	if err := json.Unmarshal(body["operator"], &profile); err != nil || profile.DisplayName != "Смена" || len(body) != 1 {
		t.Errorf("body = %s", w.Body)
	}
	if commits := f.store.commits(); len(commits) != 1 || commits[0].DisplayName != "Смена" {
		t.Errorf("commits = %+v", commits)
	}
}

func TestUpdateDisplayNameRejections(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	for _, tc := range []struct {
		name          string
		body          string
		session       *http.Cookie
		token, origin string
		status        int
		code          string
		field         string
	}{
		{"no session", `{"displayName":"Смена"}`, nil, token, testOrigin, http.StatusUnauthorized, "Unauthenticated", ""},
		{"wrong token", `{"displayName":"Смена"}`, session, "tok-999", testOrigin, http.StatusForbidden, "InvalidCsrfToken", ""},
		{"no origin", `{"displayName":"Смена"}`, session, token, "", http.StatusForbidden, "InvalidOrigin", ""},
		{"too short", `{"displayName":"Я"}`, session, token, testOrigin, http.StatusUnprocessableEntity, "InvalidDisplayName", "TooShort"},
		{"blank", `{"displayName":"   "}`, session, token, testOrigin, http.StatusUnprocessableEntity, "InvalidDisplayName", "Required"},
		{"control character", `{"displayName":"Сме\tна"}`, session, token, testOrigin, http.StatusUnprocessableEntity, "InvalidDisplayName", "InvalidCharacters"},
		{"missing field", `{}`, session, token, testOrigin, http.StatusBadRequest, "InvalidRequest", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tc.session != nil {
				cookies = []*http.Cookie{tc.session}
			}
			w := f.do(call{method: http.MethodPatch, path: "/api/operator/me/display-name", body: tc.body,
				cookies: cookies, csrf: tc.token, origin: tc.origin})
			p := wantProblem(t, w, tc.status, tc.code)
			if got := p.FieldErrors["displayName"]; got != tc.field || (tc.field == "") != (p.FieldErrors == nil) {
				t.Errorf("fieldErrors = %v, want displayName %q", p.FieldErrors, tc.field)
			}
		})
	}
	if commits := f.store.commits(); len(commits) != 0 {
		t.Errorf("rejected changes were committed: %+v", commits)
	}
}

func TestUpdateDisplayNameStorageOutcomes(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	f.store.fail(fmt.Errorf("create temp file: %w", operator.ErrStorageUnavailable))
	wantProblem(t, f.patch("/api/operator/me/display-name", `{"displayName":"Смена"}`, session, token),
		http.StatusServiceUnavailable, "AccountStorageUnavailable")
	// A definite failure changed nothing: the session still works, even while the store keeps failing.
	if me := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}}); me.Code != http.StatusOK {
		t.Fatalf("me after a definite failure: %d %s", me.Code, me.Body)
	}
	f.store.fail(errors.New("rename outcome unknown"))
	wantProblem(t, f.patch("/api/operator/me/display-name", `{"displayName":"Смена"}`, session, token),
		http.StatusServiceUnavailable, "AccountUpdateOutcomeUnknown")
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}}),
		http.StatusServiceUnavailable, "AuthUnavailable")
}

func TestChangePasswordRevokesTheSession(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	w := f.patch("/api/operator/me/password", f.json(map[string]string{"currentPassword": testPassword, "newPassword": newPassword}), session, token)
	if cleared := cookiesOf(t, w)["umir_operator_session"]; w.Code != http.StatusNoContent || cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("change: %d %v %s", w.Code, w.Header().Values("Set-Cookie"), w.Body)
	}
	wantProblem(t, f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}}),
		http.StatusUnauthorized, "Unauthenticated")
	wantProblem(t, f.signIn(testPassword), http.StatusUnauthorized, "InvalidCredentials")
	if w := f.signIn(newPassword); w.Code != http.StatusOK {
		t.Errorf("login with the new password: %d %s", w.Code, w.Body)
	}
}

func TestChangePasswordRejections(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	change := func(current, next string) *httptest.ResponseRecorder {
		return f.patch("/api/operator/me/password", f.json(map[string]string{"currentPassword": current, "newPassword": next}), session, token)
	}
	wantProblem(t, change("wrong current password", newPassword), http.StatusForbidden, "CurrentPasswordIncorrect")
	for next, code := range map[string]string{"short12": "TooShort", strings.Repeat("я", 33): "TooLong"} {
		p := wantProblem(t, change(testPassword, next), http.StatusUnprocessableEntity, "PasswordRejected")
		if p.FieldErrors["newPassword"] != code || p.Message == "" {
			t.Errorf("%d code points: %+v", len([]rune(next)), p)
		}
	}
	wantProblem(t, f.patch("/api/operator/me/password", `{"currentPassword":"x"}`, session, token), http.StatusBadRequest, "InvalidRequest")
	wantProblem(t, f.patch("/api/operator/me/password", f.json(map[string]string{"currentPassword": testPassword, "newPassword": newPassword}), session, ""),
		http.StatusForbidden, "InvalidCsrfToken")
	// None of the rejections changed the password or ended the session.
	if me := f.do(call{method: http.MethodGet, path: "/api/operator/me", cookies: []*http.Cookie{session}}); me.Code != http.StatusOK {
		t.Errorf("me: %d", me.Code)
	}
	if commits := f.store.commits(); len(commits) != 0 {
		t.Errorf("commits = %+v", commits)
	}
}

func TestLogsCarryNoSecrets(t *testing.T) {
	f := loopbackFixture(t)
	var secrets []string
	collect := func(w *httptest.ResponseRecorder) {
		for _, cookie := range cookiesOf(t, w) {
			if cookie.Value != "" {
				secrets = append(secrets, cookie.Value)
			}
		}
	}
	wrong := f.signIn("wrong password!")
	collect(wrong)
	session, token := f.login()
	secrets = append(secrets, session.Value, token, testPassword, newPassword, "wrong password!", fakeHash(testPassword), fakeHash(newPassword))
	collect(f.patch("/api/operator/me/display-name", `{"displayName":"Я"}`, session, token))
	collect(f.patch("/api/operator/me/display-name", `{"displayName":"Смена"}`, session, "tok-999"))
	collect(f.patch("/api/operator/me/password", f.json(map[string]string{"currentPassword": "wrong current password", "newPassword": newPassword}), session, token))
	collect(f.patch("/api/operator/me/password", f.json(map[string]string{"currentPassword": testPassword, "newPassword": newPassword}), session, token))
	logs := f.logs.String()
	if !strings.Contains(logs, "InvalidCredentials") || !strings.Contains(logs, "req-1") {
		t.Fatalf("expected rejections in the log:\n%s", logs)
	}
	for _, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Errorf("log contains %q:\n%s", secret, logs)
		}
	}
}

func TestBodiesWithMalformedTextAreRejected(t *testing.T) {
	f := loopbackFixture(t)
	session, token := f.login()
	// A literal U+FFFD is valid text; an unpaired surrogate escape or invalid UTF-8 would silently
	// become one, so those bodies are rejected before decoding.
	if w := f.patch("/api/operator/me/display-name", `{"displayName":"Опе\ufffdратор"}`, session, token); w.Code != http.StatusOK {
		t.Fatalf("literal U+FFFD: %d %s", w.Code, w.Body)
	}
	for _, body := range []string{`{"displayName":"Опе\ud800ратор"}`, "{\"displayName\":\"bad\xff name\"}"} {
		wantProblem(t, f.patch("/api/operator/me/display-name", body, session, token), http.StatusBadRequest, "InvalidRequest")
	}
	preauth, anonymous := f.anonymous()
	login := f.do(call{
		method: http.MethodPost, path: "/api/operator/session",
		body:    `{"login":"operator","password":"correct horse battery stapl\ud800"}`,
		cookies: []*http.Cookie{preauth}, csrf: anonymous, origin: testOrigin,
	})
	wantProblem(t, login, http.StatusBadRequest, "InvalidRequest")
	if commits := f.store.commits(); len(commits) != 1 || commits[0].DisplayName != "Опе\uFFFDратор" {
		t.Errorf("commits = %+v", commits)
	}
}
