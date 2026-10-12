package operatorhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/operator"
)

type operatorView struct {
	ID          string `json:"id"`
	Login       string `json:"login"`
	DisplayName string `json:"displayName"`
}

type sessionView struct {
	ExpiresAt         string `json:"expiresAt"`
	IdleExpiresAt     string `json:"idleExpiresAt"`
	AbsoluteExpiresAt string `json:"absoluteExpiresAt"`
	RememberMe        bool   `json:"rememberMe"`
	CSRFToken         string `json:"csrfToken"`
}

type accountView struct {
	Operator operatorView `json:"operator"`
	Session  *sessionView `json:"session,omitempty"`
}

type csrfView struct {
	CSRFToken string `json:"csrfToken"`
}

// moscow is the +03:00 offset the contract requires in timestamps.
var moscow = time.FixedZone("MSK", 3*60*60)

func timestamp(t time.Time) string { return t.In(moscow).Format(time.RFC3339) }

func accountOf(p operator.Profile, s *operator.Session) accountView {
	view := accountView{Operator: operatorView{ID: p.ID, Login: p.Login, DisplayName: p.DisplayName}}
	if s != nil {
		view.Session = &sessionView{
			ExpiresAt: timestamp(s.ExpiresAt), IdleExpiresAt: timestamp(s.IdleExpiresAt),
			AbsoluteExpiresAt: timestamp(s.AbsoluteExpiresAt), RememberMe: s.RememberMe, CSRFToken: s.CSRFToken,
		}
	}
	return view
}

func (a *API) writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		a.logger.Printf("operator %s response: %v", httpapi.RequestID(r), err)
	}
}

func (a *API) problem(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	a.reject(w, r, status, httpapi.Problem{Code: code, Message: message})
}

// reject logs the request ID, route and code, never the request itself, and answers with p. The path is
// quoted, so a decoded newline in it cannot forge another log line.
func (a *API) reject(w http.ResponseWriter, r *http.Request, status int, p httpapi.Problem) {
	a.logger.Printf("operator %s %s %q: %d %s", httpapi.RequestID(r), r.Method, r.URL.Path, status, p.Code)
	httpapi.WriteProblem(w, r, status, p)
}

// challenge answers every 401, as RFC 9110 requires. No scheme is registered for cookie sessions, and
// browsers show no sign-in prompt for an unknown one.
const challenge = `Session realm="umir-operator"`

// fieldMessages are the developer messages of the 422 codes.
var fieldMessages = map[string]string{
	"InvalidDisplayName": "display name must contain 2 to 80 characters without control characters",
	"PasswordRejected":   "new password must contain 8 to 32 characters",
}

// fail answers an error of the account module. invalid is the 422 code of a field error on this route.
func (a *API) fail(w http.ResponseWriter, r *http.Request, err error, invalid string) {
	var field *operator.FieldError
	var limited *operator.RateLimitError
	var changeLimited *operator.PasswordChangeLimitError
	switch {
	case errors.As(err, &field) && invalid != "":
		a.reject(w, r, http.StatusUnprocessableEntity, httpapi.Problem{
			Code: invalid, Message: fieldMessages[invalid], FieldErrors: map[string]string{field.Field: string(field.Code)},
		})
	case errors.As(err, &limited):
		w.Header().Set("Retry-After", strconv.Itoa(int(limited.RetryAfter/time.Second)))
		a.problem(w, r, http.StatusTooManyRequests, "LoginRateLimited", "too many login attempts")
	case errors.As(err, &changeLimited):
		// The revocation is already stored, so the cookie is cleared with the answer that reports it.
		revoked := changeLimited.SessionRevoked
		if revoked {
			a.clearCookie(w, a.cookies.session)
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(changeLimited.RetryAfter/time.Second)))
		a.reject(w, r, http.StatusTooManyRequests, httpapi.Problem{
			Code: "PasswordChangeRateLimited", Message: "too many wrong current passwords; password changes are paused",
			SessionRevoked: &revoked,
		})
	case errors.Is(err, operator.ErrInvalidCredentials):
		w.Header().Set("WWW-Authenticate", challenge)
		a.problem(w, r, http.StatusUnauthorized, "InvalidCredentials", "login or password is incorrect")
	case errors.Is(err, operator.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", challenge)
		a.problem(w, r, http.StatusUnauthorized, "Unauthenticated", "sign in to continue")
	case errors.Is(err, operator.ErrInvalidCSRFToken):
		a.problem(w, r, http.StatusForbidden, "InvalidCsrfToken", "CSRF token is missing or invalid")
	case errors.Is(err, operator.ErrCurrentPasswordIncorrect):
		a.problem(w, r, http.StatusForbidden, "CurrentPasswordIncorrect", "current password is incorrect")
	case errors.Is(err, operator.ErrAuthUnavailable):
		a.problem(w, r, http.StatusServiceUnavailable, "AuthUnavailable", "authentication is unavailable until the account is recovered")
	// Session errors wrap the storage errors, so they are matched first.
	case errors.Is(err, operator.ErrSessionUpdateOutcomeUnknown):
		a.problem(w, r, http.StatusServiceUnavailable, "SessionUpdateOutcomeUnknown", "session change outcome is unknown; authentication stops until recovery")
	case errors.Is(err, operator.ErrSessionStorageUnavailable):
		a.problem(w, r, http.StatusServiceUnavailable, "SessionStorageUnavailable", "session storage failed; the session was not changed")
	case errors.Is(err, operator.ErrUpdateOutcomeUnknown):
		a.problem(w, r, http.StatusServiceUnavailable, "AccountUpdateOutcomeUnknown", "account change outcome is unknown; authentication stops until recovery")
	case errors.Is(err, operator.ErrStorageUnavailable):
		a.problem(w, r, http.StatusServiceUnavailable, "AccountStorageUnavailable", "account storage failed; nothing was changed")
	default:
		// Client cancellation and unexpected failures; the cause goes to the log only.
		a.logger.Printf("operator %s %s %q: %v", httpapi.RequestID(r), r.Method, r.URL.Path, err)
		a.problem(w, r, http.StatusServiceUnavailable, "AuthUnavailable", "authentication is temporarily unavailable")
	}
}
