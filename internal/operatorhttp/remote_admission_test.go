package operatorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type admissionFailAuth struct{ calls int }
type recordingAdmission struct {
	rule     AdmissionRule
	subjects AdmissionSubjects
	attempt  AdmissionAttempt
	verdict  AdmissionVerdict
	err      error
}

func (a *recordingAdmission) Admit(_ context.Context, rule AdmissionRule, subjects AdmissionSubjects, attempt AdmissionAttempt) (AdmissionVerdict, error) {
	a.rule, a.subjects, a.attempt = rule, subjects, attempt
	return a.verdict, a.err
}

type fixedClient string

func (c fixedClient) Client(*http.Request) string { return string(c) }

func (a *admissionFailAuth) CSRF(context.Context, BrowserContext) (CSRFResult, error) {
	a.calls++
	return CSRFResult{}, nil
}
func (*admissionFailAuth) Login(context.Context, BrowserContext, LoginInput) (SessionIssued, error) {
	return SessionIssued{}, nil
}
func (*admissionFailAuth) Logout(context.Context, BrowserContext) error { return nil }
func (*admissionFailAuth) Me(context.Context, BrowserContext) (AuthView, error) {
	return AuthView{}, nil
}
func (*admissionFailAuth) DisplayName(context.Context, BrowserContext, DisplayNameInput) (AuthUser, error) {
	return AuthUser{}, nil
}
func (*admissionFailAuth) Password(context.Context, BrowserContext, PasswordInput) error { return nil }
func (a *admissionFailAuth) Public(context.Context, BrowserContext, FacadeRequest) (json.RawMessage, error) {
	a.calls++
	return json.RawMessage(`{"csrfToken":"csrf"}`), nil
}

type unavailableAdmission struct{}

func (unavailableAdmission) Admit(context.Context, AdmissionRule, AdmissionSubjects, AdmissionAttempt) (AdmissionVerdict, error) {
	return AdmissionVerdict{}, errors.New("limiter unavailable")
}

func TestRemoteCSRFAdmissionFailureFailsClosedBeforeAuth(t *testing.T) {
	auth := &admissionFailAuth{}
	api, err := NewRemote(RemoteOptions{
		Auth: auth, Mode: ModeLoopback, PublicOrigin: testOrigin, Logger: log.New(httptest.NewRecorder(), "", 0),
		Now: time.Now, NewCommandID: func() string { return "command" }, Admission: unavailableAdmission{},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v2/csrf", nil))
	if w.Code != http.StatusServiceUnavailable || auth.calls != 0 {
		t.Fatalf("admission failure reached Auth or returned wrong status: status=%d auth_calls=%d body=%s", w.Code, auth.calls, w.Body)
	}
}

func TestRemoteRegistrationAdmissionUsesConfiguredBudgetsBeforeAuth(t *testing.T) {
	auth := &admissionFailAuth{}
	limiter := &recordingAdmission{verdict: AdmissionVerdict{RetryAfter: 7 * time.Second}}
	api, err := NewRemote(RemoteOptions{
		Auth: auth, Mode: ModeLoopback, PublicOrigin: testOrigin, Logger: log.New(httptest.NewRecorder(), "", 0),
		Now: time.Now, NewCommandID: func() string { return "command" }, Clients: fixedClient("203.0.113.10"), Admission: limiter,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v2/email-challenges", strings.NewReader(`{"commandID":"registration-command","email":"new@umir.invalid","purpose":"registration"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", testOrigin)
	r.Header.Set(CSRFHeader, "csrf")
	r.AddCookie(&http.Cookie{Name: "umir_operator_preauth", Value: "preauth-token"})
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "7" || auth.calls != 0 {
		t.Fatalf("registration was not refused before Auth: status=%d retry=%q auth_calls=%d body=%s", w.Code, w.Header().Get("Retry-After"), auth.calls, w.Body)
	}
	if limiter.rule != AdmissionRegistration || limiter.subjects != (AdmissionSubjects{Client: "203.0.113.10", Preauth: "preauth-token", Global: true}) || limiter.attempt.ID != "registration-command" {
		t.Fatalf("wrong admission request: rule=%q subjects=%+v attempt=%+v", limiter.rule, limiter.subjects, limiter.attempt)
	}
	var result struct {
		Details struct {
			RetryAfterSeconds int `json:"retryAfterSeconds"`
		} `json:"details"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Details.RetryAfterSeconds != 7 {
		t.Fatalf("missing retryAfterSeconds: %s (%v)", w.Body, err)
	}
}
