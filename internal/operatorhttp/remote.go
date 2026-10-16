package operatorhttp

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/strictjson"
)

type RemoteOptions struct {
	Auth         AuthClient
	Mode         CookieMode
	PublicOrigin string
	Logger       *log.Logger
	Now          func() time.Time
	NewCommandID func() string
	// Clients tells which client a request comes from, for the limits kept per client; nil means the
	// peer address.
	Clients ClientResolver
}

// ClientResolver names the client of a request.
type ClientResolver interface{ Client(*http.Request) string }

type RemoteAPI struct {
	boundary     *API
	auth         AuthClient
	newCommandID func() string
	registration *registrationLimits
	clients      ClientResolver
}

func NewRemote(opts RemoteOptions) (*RemoteAPI, error) {
	if opts.Auth == nil || opts.Logger == nil || opts.Now == nil || opts.NewCommandID == nil {
		return nil, errors.New("operatorhttp: Auth, logger, clock and command IDs are required")
	}
	a := &API{origin: opts.PublicOrigin, logger: opts.Logger, now: opts.Now}
	switch {
	case opts.Mode == ModeSecure && strings.HasPrefix(opts.PublicOrigin, "https://"):
		a.secure, a.cookies = true, secureCookies
	case opts.Mode == ModeLoopback && strings.HasPrefix(opts.PublicOrigin, "http://"):
		a.cookies = loopbackCookies
	default:
		return nil, errors.New("operatorhttp: cookie mode and public origin do not match")
	}
	return &RemoteAPI{boundary: a, auth: opts.Auth, newCommandID: opts.NewCommandID, registration: &registrationLimits{}, clients: opts.Clients}, nil
}

func (a *RemoteAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(r.URL.Path, "/api/v2/") {
		a.serveFacade(w, r)
		return
	}
	const prefix = "/api/operator"
	path := strings.TrimPrefix(r.URL.Path, prefix)
	allowed := map[string]string{
		"/csrf": "GET, HEAD", "/session": "POST, DELETE", "/me": "GET, HEAD", "/me/display-name": "PATCH", "/me/password": "PATCH",
	}[path]
	if allowed == "" || !strings.HasPrefix(r.URL.Path, prefix+"/") {
		a.boundary.problem(w, r, http.StatusNotFound, "NotFound", "unknown account route")
		return
	}
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	if !strings.Contains(", "+allowed+", ", ", "+r.Method+", ") {
		w.Header().Set("Allow", allowed)
		a.boundary.problem(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "method is not allowed for this route")
		return
	}
	if forbiddenCredentials(r) {
		a.boundary.problem(w, r, http.StatusForbidden, "InvalidRequest", "internal credentials are not browser inputs")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		a.boundary.problem(w, r, http.StatusBadRequest, "InvalidRequest", "account route has no query parameters")
		return
	}
	browser := BrowserContext{SessionToken: a.boundary.cookie(r, a.boundary.cookies.session), PreauthToken: a.boundary.cookie(r, a.boundary.cookies.preauth), CSRFToken: r.Header.Get(CSRFHeader), Activity: "foreground"}
	if background(r) || path == "/csrf" {
		browser.Activity = "background"
	}
	if method != http.MethodGet {
		if !a.boundary.admitOrigin(w, r) {
			return
		}
		if len(r.Header.Values(CSRFHeader)) != 1 || browser.CSRFToken == "" {
			a.boundary.problem(w, r, http.StatusForbidden, "InvalidCsrfToken", "CSRF token is missing or invalid")
			return
		}
	}
	var result any
	var err error
	switch path {
	case "/csrf":
		var value CSRFResult
		value, err = a.auth.CSRF(r.Context(), browser)
		if err != nil && browser.SessionToken != "" && confirmedUnauthenticated(err) {
			a.boundary.clearCookie(w, a.boundary.cookies.session)
			browser.SessionToken = ""
			value, err = a.auth.CSRF(r.Context(), browser)
		}
		if err == nil {
			if value.PreauthToken != "" {
				a.boundary.setCookie(w, a.boundary.cookies.preauth, value.PreauthToken, time.Time{})
			}
			result = csrfView{CSRFToken: value.CSRFToken}
		}
	case "/session":
		if method == http.MethodDelete {
			err = a.auth.Logout(r.Context(), browser)
			if err == nil {
				a.boundary.clearCookie(w, a.boundary.cookies.session)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		} else {
			var input LoginInput
			if !a.decodeInput(w, r, &input, []string{"login", "password"}, []string{"rememberMe"}) {
				return
			}
			input.CommandID = a.newCommandID()
			var issued SessionIssued
			issued, err = a.auth.Login(r.Context(), browser, input)
			if err == nil {
				var expires time.Time
				if issued.View.Session.RememberMe {
					expires = issued.View.Session.AbsoluteExpiresAt
				}
				a.boundary.setCookie(w, a.boundary.cookies.session, issued.SessionToken, expires)
				if browser.PreauthToken != "" {
					a.boundary.clearCookie(w, a.boundary.cookies.preauth)
				}
				result = operatorViewOf(issued.View)
			}
		}
	case "/me":
		var view AuthView
		view, err = a.auth.Me(r.Context(), browser)
		if err == nil {
			result = operatorViewOf(view)
		}
	case "/me/display-name":
		var input DisplayNameInput
		if !a.decodeInput(w, r, &input, []string{"displayName"}, nil) {
			return
		}
		input.CommandID = a.newCommandID()
		if input.CommandID == "" || strings.HasPrefix(input.CommandID, "expiration/") {
			a.boundary.problem(w, r, http.StatusBadRequest, "InvalidRequest", "commandID is required")
			return
		}
		var user AuthUser
		user, err = a.auth.DisplayName(r.Context(), browser, input)
		if err == nil {
			result = accountView{Operator: operatorView{ID: user.UserID, Login: user.Login, DisplayName: user.DisplayName}}
		}
	case "/me/password":
		var input PasswordInput
		if !a.decodeInput(w, r, &input, []string{"currentPassword", "newPassword"}, nil) {
			return
		}
		input.CommandID = a.newCommandID()
		if input.CommandID == "" || strings.HasPrefix(input.CommandID, "expiration/") {
			a.boundary.problem(w, r, http.StatusBadRequest, "InvalidRequest", "commandID is required")
			return
		}
		err = a.auth.Password(r.Context(), browser, input)
		if err == nil {
			a.boundary.clearCookie(w, a.boundary.cookies.session)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	if err != nil {
		a.fail(w, r, err, true, path)
		return
	}
	a.boundary.writeJSON(w, r, http.StatusOK, result)
}

func forbiddenCredentials(r *http.Request) bool {
	for key := range r.Header {
		lower := strings.ToLower(key)
		if lower == "authorization" || lower == "proxy-authorization" || lower == "x-service-key" || (strings.HasPrefix(lower, "x-umir-") && lower != strings.ToLower(ActivityHeader)) {
			return true
		}
	}
	return false
}

func (a *RemoteAPI) decodeInput(w http.ResponseWriter, r *http.Request, input any, required, optional []string) bool {
	body, ok := a.boundary.readJSON(w, r, maxBody)
	if !ok {
		return false
	}
	fields, err := strictjson.Object(body)
	valid := err == nil && exactFields(body, append(append([]string{}, required...), optional...))
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			valid = false
		}
	}
	if !valid || json.Unmarshal(body, input) != nil {
		a.boundary.problem(w, r, http.StatusBadRequest, "InvalidRequest", "request body is not the expected JSON object")
		return false
	}
	return true
}

func operatorViewOf(view AuthView) accountView {
	s := view.Session
	return accountView{Operator: operatorView{ID: view.User.UserID, Login: view.User.Login, DisplayName: view.User.DisplayName}, Session: &sessionView{
		ExpiresAt: s.ExpiresAt.In(moscow).Format(time.RFC3339Nano), IdleExpiresAt: s.IdleExpiresAt.In(moscow).Format(time.RFC3339Nano), AbsoluteExpiresAt: s.AbsoluteExpiresAt.In(moscow).Format(time.RFC3339Nano), RememberMe: s.RememberMe, CSRFToken: s.CSRFToken,
	}}
}

func (a *RemoteAPI) fail(w http.ResponseWriter, r *http.Request, err error, alias bool, path string) {
	var failure *AuthFailure
	if !errors.As(err, &failure) {
		a.boundary.problem(w, r, http.StatusServiceUnavailable, "AuthUnavailable", "authentication is unavailable")
		return
	}
	code := failure.Code
	if alias && (code == "AuthStorageUnavailable" || code == "AuthUpdateOutcomeUnknown" || (failure.Cause != nil && failure.Outcome == "unknown")) {
		prefix := "Session"
		if path == "/me/display-name" || path == "/me/password" {
			prefix = "Account"
		}
		if code == "AuthStorageUnavailable" {
			code = prefix + "StorageUnavailable"
		} else {
			code = prefix + "UpdateOutcomeUnknown"
		}
	}
	if failure.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(failure.RetryAfter))
	}
	if failure.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	if failure.Code == "PasswordChangeRateLimited" && failure.SessionRevoked != nil && *failure.SessionRevoked {
		a.boundary.clearCookie(w, a.boundary.cookies.session)
	}
	if alias {
		a.boundary.reject(w, r, failure.Status, httpapi.Problem{Code: code, Message: "authentication request failed", FieldErrors: failure.FieldErrors, SessionRevoked: failure.SessionRevoked})
		return
	}
	a.boundary.writeJSON(w, r, failure.Status, struct {
		Code           string            `json:"code"`
		Outcome        string            `json:"outcome"`
		Message        string            `json:"message"`
		Retryable      bool              `json:"retryable"`
		FieldErrors    map[string]string `json:"fieldErrors,omitempty"`
		Details        json.RawMessage   `json:"details,omitempty"`
		SessionRevoked *bool             `json:"sessionRevoked,omitempty"`
	}{Code: code, Outcome: failure.Outcome, Message: "authentication request failed", Retryable: failure.Retryable, FieldErrors: failure.FieldErrors, Details: failure.Details, SessionRevoked: failure.SessionRevoked})
}

func confirmedUnauthenticated(err error) bool {
	var failure *AuthFailure
	return errors.As(err, &failure) && failure.Status == http.StatusUnauthorized && failure.Code == "Unauthenticated" && failure.Outcome == "not_committed"
}
