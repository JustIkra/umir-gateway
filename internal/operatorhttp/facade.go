package operatorhttp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

func (a *RemoteAPI) serveFacade(w http.ResponseWriter, r *http.Request) {
	requestAPI, boundary := *a, *a.boundary
	boundary.v2 = true
	requestAPI.boundary = &boundary
	a = &requestAPI
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	op, allowed, err := facadeRoute(method, r.URL.Path)
	if err != nil {
		a.boundary.problem(w, r, 503, "AuthUnavailable", "Auth contract is unavailable")
		return
	}
	if op == nil {
		status, code := http.StatusNotFound, "NotFound"
		if len(allowed) != 0 {
			status, code = http.StatusMethodNotAllowed, "MethodNotAllowed"
			w.Header().Set("Allow", strings.Join(allowed, ", "))
		}
		a.boundary.problem(w, r, status, code, "unknown Auth operation")
		return
	}
	if forbiddenCredentials(r) {
		a.boundary.problem(w, r, 403, "Forbidden", "internal credentials are not browser inputs")
		return
	}
	if r.URL.RawPath != "" || r.URL.ForceQuery && r.URL.RawQuery == "" {
		a.boundary.problem(w, r, 400, "InvalidArgument", "use a canonical Auth path and query")
		return
	}
	browser, ok := a.facadeBrowser(w, r)
	if !ok {
		return
	}
	if method != http.MethodGet {
		if len(r.Header.Values("Sec-Fetch-Site")) > 1 || !a.boundary.admitOrigin(w, r) {
			if len(r.Header.Values("Sec-Fetch-Site")) > 1 {
				a.boundary.problem(w, r, 403, "InvalidOrigin", "ambiguous fetch metadata")
			}
			return
		}
		if len(r.Header.Values(CSRFHeader)) != 1 || browser.CSRFToken == "" {
			a.boundary.problem(w, r, 403, "InvalidCsrfToken", "CSRF token is required")
			return
		}
	}
	var body []byte
	if op.request != nil {
		body, ok = a.boundary.readJSON(w, r, 1<<20)
		if !ok {
			return
		}
	} else {
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
		if err != nil || len(body) != 0 {
			a.boundary.problem(w, r, 400, "InvalidArgument", "this Auth operation has no request body")
			return
		}
	}
	in := FacadeRequest{Method: method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Body: body}
	if _, err := ValidateFacadeRequest(in); err != nil {
		a.boundary.problem(w, r, 400, "InvalidArgument", "invalid Auth input")
		return
	}
	result, err := a.auth.Public(r.Context(), browser, in)
	if err != nil {
		a.fail(w, r, err, false, strings.TrimPrefix(r.URL.Path, "/api/v2"))
		return
	}
	switch op.id {
	case "csrf":
		var value CSRFResult
		if json.Unmarshal(result, &value) != nil {
			a.boundary.problem(w, r, 503, "AuthUnavailable", "invalid Auth result")
			return
		}
		if value.PreauthToken != "" {
			a.boundary.setCookie(w, a.boundary.cookies.preauth, value.PreauthToken, time.Time{})
		}
		result, err = json.Marshal(csrfView{value.CSRFToken})
	case "login", "completeInvitedUser", "completeEmailChallenge":
		var issued SessionIssued
		if json.Unmarshal(result, &issued) != nil {
			a.boundary.problem(w, r, 503, "AuthUnavailable", "invalid Auth result")
			return
		}
		var expires time.Time
		if issued.View.Session.RememberMe {
			expires = issued.View.Session.AbsoluteExpiresAt
		}
		a.boundary.setCookie(w, a.boundary.cookies.session, issued.SessionToken, expires)
		if browser.PreauthToken != "" {
			a.boundary.clearCookie(w, a.boundary.cookies.preauth)
		}
		result, err = json.Marshal(issued.View)
	case "logout", "logoutAll", "password":
		a.boundary.clearCookie(w, a.boundary.cookies.session)
	}
	if err != nil {
		a.boundary.problem(w, r, 503, "AuthUnavailable", "Auth projection is unavailable")
		return
	}
	if op.Status == http.StatusNoContent {
		w.WriteHeader(op.Status)
		return
	}
	a.boundary.writeJSON(w, r, op.Status, result)
}

func (a *RemoteAPI) facadeBrowser(w http.ResponseWriter, r *http.Request) (BrowserContext, bool) {
	browser := BrowserContext{CSRFToken: r.Header.Get(CSRFHeader), Activity: "foreground"}
	seen := map[string]bool{}
	for _, cookie := range r.Cookies() {
		if cookie.Name != a.boundary.cookies.session && cookie.Name != a.boundary.cookies.preauth {
			continue
		}
		if seen[cookie.Name] || cookie.Value == "" {
			a.boundary.problem(w, r, 403, "Unauthenticated", "ambiguous browser context")
			return BrowserContext{}, false
		}
		seen[cookie.Name] = true
		if cookie.Name == a.boundary.cookies.session {
			browser.SessionToken = cookie.Value
		} else {
			browser.PreauthToken = cookie.Value
		}
	}
	if background(r) || r.URL.Path == "/api/v2/csrf" {
		browser.Activity = "background"
	}
	return browser, true
}
