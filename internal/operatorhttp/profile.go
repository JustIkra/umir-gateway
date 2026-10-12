package operatorhttp

import "net/http"

// authorize admits an account change: exact Origin, live session and its CSRF token. It returns the
// session ID, or answers and returns false.
func (a *API) authorize(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !a.admitOrigin(w, r) {
		return "", false
	}
	id := a.cookie(r, a.cookies.session)
	if _, _, err := a.accounts.Authorize(id, r.Header.Get(CSRFHeader)); err != nil {
		a.fail(w, r, err, "")
		return "", false
	}
	return id, true
}

func (a *API) updateDisplayName(w http.ResponseWriter, r *http.Request) {
	id, ok := a.authorize(w, r)
	if !ok {
		return
	}
	var body struct {
		DisplayName *string `json:"displayName"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	if body.DisplayName == nil {
		a.problem(w, r, http.StatusBadRequest, "InvalidRequest", "displayName is required")
		return
	}
	profile, err := a.accounts.UpdateDisplayName(id, *body.DisplayName)
	if err != nil {
		a.fail(w, r, err, "InvalidDisplayName")
		return
	}
	a.writeJSON(w, r, http.StatusOK, accountOf(profile, nil))
}

// changePassword revokes every session on success, this one included, and clears its cookie.
func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	id, ok := a.authorize(w, r)
	if !ok {
		return
	}
	var body struct {
		CurrentPassword *string `json:"currentPassword"`
		NewPassword     *string `json:"newPassword"`
	}
	if !a.decode(w, r, &body) {
		return
	}
	if body.CurrentPassword == nil || body.NewPassword == nil {
		a.problem(w, r, http.StatusBadRequest, "InvalidRequest", "currentPassword and newPassword are required")
		return
	}
	if err := a.accounts.ChangePassword(r.Context(), id, *body.CurrentPassword, *body.NewPassword); err != nil {
		a.fail(w, r, err, "PasswordRejected")
		return
	}
	a.clearCookie(w, a.cookies.session)
	w.WriteHeader(http.StatusNoContent)
}
