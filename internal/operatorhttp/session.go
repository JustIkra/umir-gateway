package operatorhttp

import (
	"net/http"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// csrf returns the token of a live session, or of an anonymous pre-auth context for login and logout.
// It never extends a session and never creates one.
func (a *API) csrf(w http.ResponseWriter, r *http.Request) {
	if token, ok := a.accounts.SessionCSRF(a.cookie(r, a.cookies.session)); ok {
		a.writeJSON(w, r, http.StatusOK, csrfView{CSRFToken: token})
		return
	}
	previous := a.cookie(r, a.cookies.preauth)
	id, token, err := a.accounts.AnonymousCSRF(previous)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	if id != previous {
		a.setCookie(w, a.cookies.preauth, id, time.Time{})
	}
	a.writeJSON(w, r, http.StatusOK, csrfView{CSRFToken: token})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.admitOrigin(w, r) {
		return
	}
	sessionID, preauthID := a.cookie(r, a.cookies.session), a.cookie(r, a.cookies.preauth)
	if !a.bootstrapToken(sessionID, preauthID, r.Header.Get(CSRFHeader)) {
		a.problem(w, r, http.StatusForbidden, "InvalidCsrfToken", "CSRF token is missing or invalid")
		return
	}
	var body struct {
		Login    *string `json:"login"`
		Password *string `json:"password"`
		// RememberMe keeps the session cookie across browser restarts until the absolute deadline.
		RememberMe bool `json:"rememberMe"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	if body.Login == nil || body.Password == nil {
		a.problem(w, r, http.StatusBadRequest, "InvalidRequest", "login and password are required")
		return
	}
	profile, session, err := a.accounts.Login(r.Context(), *body.Login, *body.Password, sessionID)
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	if preauthID != "" {
		a.accounts.DiscardAnonymous(preauthID)
		a.clearCookie(w, a.cookies.preauth)
	}
	var expires time.Time
	if body.RememberMe {
		expires = session.AbsoluteExpiresAt
	}
	a.setCookie(w, a.cookies.session, session.ID, expires)
	a.writeJSON(w, r, http.StatusOK, accountOf(profile, &session))
}

// bootstrapToken accepts the token of the caller's pre-auth context, or of its live session when an
// operator who is still signed in signs in again.
func (a *API) bootstrapToken(sessionID, preauthID, token string) bool {
	if a.accounts.CheckAnonymousCSRF(preauthID, token) {
		return true
	}
	sessionToken, ok := a.accounts.SessionCSRF(sessionID)
	return ok && operator.MatchToken(sessionToken, token)
}

// logout revokes a live session with its own token. Without one, an anonymous token is enough to clear
// the cookie, so the call is idempotent, also during recovery.
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if !a.admitOrigin(w, r) {
		return
	}
	sessionID, token := a.cookie(r, a.cookies.session), r.Header.Get(CSRFHeader)
	if sessionToken, ok := a.accounts.SessionCSRF(sessionID); ok {
		if !operator.MatchToken(sessionToken, token) {
			a.problem(w, r, http.StatusForbidden, "InvalidCsrfToken", "CSRF token is missing or invalid")
			return
		}
	} else if !a.accounts.CheckAnonymousCSRF(a.cookie(r, a.cookies.preauth), token) {
		a.problem(w, r, http.StatusForbidden, "InvalidCsrfToken", "CSRF token is missing or invalid")
		return
	}
	a.accounts.Logout(sessionID)
	a.clearCookie(w, a.cookies.session)
	w.WriteHeader(http.StatusNoContent)
}

// me returns the profile and session; like every authenticated request, it extends the idle deadline.
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	profile, session, err := a.accounts.Authenticate(a.cookie(r, a.cookies.session))
	if err != nil {
		a.fail(w, r, err, "")
		return
	}
	a.writeJSON(w, r, http.StatusOK, accountOf(profile, &session))
}
