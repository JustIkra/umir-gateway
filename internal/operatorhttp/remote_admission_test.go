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

	"github.com/JustIkra/umir-gateway/internal/admission"
	"github.com/JustIkra/umir-gateway/tests/testsupport/memredis"
)

type admissionFailAuth struct {
	calls     int
	publicErr error
}

type recordingAdmission struct {
	rule     AdmissionRule
	subjects AdmissionSubjects
	attempt  AdmissionAttempt
	verdict  AdmissionVerdict
	err      error
}

type serviceAdmission struct{ service *admission.Service }

func (a serviceAdmission) Admit(ctx context.Context, rule AdmissionRule, subjects AdmissionSubjects, attempt AdmissionAttempt) (AdmissionVerdict, error) {
	verdict, err := a.service.Admit(ctx, admission.Rule(rule), admission.Subjects{Client: subjects.Client, Preauth: subjects.Preauth, Global: subjects.Global}, admission.Attempt{ID: attempt.ID, Fingerprint: attempt.Fingerprint})
	if errors.Is(err, admission.ErrConflict) {
		return AdmissionVerdict{}, ErrAdmissionConflict
	}
	return AdmissionVerdict{Allowed: verdict.Allowed, RetryAfter: verdict.RetryAfter}, err
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
	if a.publicErr != nil {
		return nil, a.publicErr
	}
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
	if limiter.rule != AdmissionRegistration || limiter.subjects != (AdmissionSubjects{Client: "203.0.113.10", Preauth: "preauth-token", Global: true}) || limiter.attempt.ID == "" || limiter.attempt.ID == "registration-command" {
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

func TestRemoteChallengeAdmissionMatchesAuthCommandScopeAndFingerprint(t *testing.T) {
	for _, purpose := range []string{"registration", "password_reset"} {
		t.Run(purpose, func(t *testing.T) {
			store := memredis.New(time.Now())
			budgets := map[string]admission.Budget{
				"csrf_client": {Limit: 60, Window: time.Minute, Strict: 20}, "csrf_global": {Limit: 5000, Window: 10 * time.Minute, Strict: 1500},
				"login_client":        {Limit: 20, Window: time.Minute, Strict: 5},
				"registration_client": {Limit: 10, Window: 10 * time.Minute, Strict: 2}, "registration_preauth": {Limit: 1, Window: 10 * time.Minute, Strict: 1}, "registration_global": {Limit: 300, Window: 10 * time.Minute, Strict: 60},
				"reset_client":    {Limit: 10, Window: 10 * time.Minute, Strict: 2},
				"feedback_client": {Limit: 20, Window: time.Hour, Strict: 4}, "feedback_preauth": {Limit: 5, Window: 10 * time.Minute, Strict: 1}, "feedback_global": {Limit: 200, Window: time.Hour, Strict: 40},
				"order_user": {Limit: 60, Window: time.Minute, Strict: 20}, "order_restaurant": {Limit: 600, Window: time.Minute, Strict: 200},
				"sse_session": {Limit: 8, Strict: 4}, "sse_org": {Limit: 200, Strict: 50}, "sse_cell": {Limit: 2000, Strict: 500},
			}
			service, err := admission.New(admission.Options{Limiter: store.Limiter(), Continuity: store.Continuity(), Budgets: budgets, Key: []byte("gateway-test-admission-key-0123456789")})
			if err != nil {
				t.Fatal(err)
			}
			auth := &admissionFailAuth{publicErr: errors.New("Auth fixture unavailable")}
			api, err := NewRemote(RemoteOptions{
				Auth: auth, Mode: ModeLoopback, PublicOrigin: testOrigin, Logger: log.New(httptest.NewRecorder(), "", 0),
				Now: time.Now, NewCommandID: func() string { return "alias-command" }, Clients: fixedClient("203.0.113.10"), Admission: serviceAdmission{service},
			})
			if err != nil {
				t.Fatal(err)
			}
			body := `{"commandID":"shared-command","email":"first@umir.invalid","purpose":"` + purpose + `"}`
			reordered := `{ "purpose":"` + purpose + `", "email":"first@umir.invalid", "commandID":"shared-command" }`
			for i, attempt := range []struct{ body, preauth string }{{body, "preauth-a"}, {reordered, "preauth-a"}, {body, "preauth-b"}} {
				response := serveChallenge(t, api, attempt.body, attempt.preauth)
				if response.Code != http.StatusServiceUnavailable {
					t.Fatalf("request %d admission rejected an owner-valid retry/scope: status=%d body=%s", i, response.Code, response.Body)
				}
			}
			if auth.calls != 3 {
				t.Fatalf("accepted attempts reached Auth %d times", auth.calls)
			}
			changed := strings.Replace(body, "first@umir.invalid", "second@umir.invalid", 1)
			response := serveChallenge(t, api, changed, "preauth-a")
			if response.Code != http.StatusConflict || auth.calls != 3 {
				t.Fatalf("changed input should conflict before Auth: status=%d auth_calls=%d body=%s", response.Code, auth.calls, response.Body)
			}
		})
	}
}

func serveChallenge(t *testing.T, api *RemoteAPI, body, preauth string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v2/email-challenges", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", testOrigin)
	r.Header.Set(CSRFHeader, "csrf")
	r.AddCookie(&http.Cookie{Name: "umir_operator_preauth", Value: preauth})
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	return w
}
