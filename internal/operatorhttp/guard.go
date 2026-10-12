package operatorhttp

import (
	"net/http"
	"strings"
)

// reserved holds the lowercased cookie names of both modes: no upstream may receive or set them.
var reserved = map[string]bool{
	strings.ToLower(secureCookies.session):   true,
	strings.ToLower(secureCookies.preauth):   true,
	strings.ToLower(loopbackCookies.session): true,
	strings.ToLower(loopbackCookies.preauth): true,
}

// Protect admits a business request only with the operator's live session. GET, HEAD and OPTIONS need
// the session; POST, PUT, PATCH and DELETE also need the exact Origin and the session's CSRF token.
// Other methods are refused. Nothing reaches next before these checks pass, and a session that
// expires after that does not affect the dispatched request.
func (a *API) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := a.cookie(r, a.cookies.session)
		var err error
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			_, _, err = a.accounts.Authenticate(id)
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if !a.admitOrigin(w, r) {
				return
			}
			_, _, err = a.accounts.Authorize(id, r.Header.Get(CSRFHeader))
		default:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE")
			a.problem(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "method is not supported")
			return
		}
		if err != nil {
			a.fail(w, r, err, "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// StripCredentials removes the operator cookies and the CSRF header before a request leaves the
// gateway. Other cookies keep their original text; the caller's request is not modified.
func StripCredentials(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Clone()
		header.Del(CSRFHeader)
		header.Del("Cookie")
		for _, line := range r.Header.Values("Cookie") {
			var kept []string
			for _, pair := range strings.Split(line, ";") {
				pair = strings.TrimSpace(pair)
				name, _, _ := strings.Cut(pair, "=")
				if pair != "" && !reserved[strings.ToLower(strings.TrimSpace(name))] {
					kept = append(kept, pair)
				}
			}
			if len(kept) > 0 {
				header.Add("Cookie", strings.Join(kept, "; "))
			}
		}
		out := r.WithContext(r.Context())
		out.Header = header
		next.ServeHTTP(w, out)
	})
}

// DropReservedCookies removes upstream Set-Cookie lines that would replace an operator cookie. It fits
// httputil.ReverseProxy.ModifyResponse.
func DropReservedCookies(response *http.Response) error {
	lines := response.Header.Values("Set-Cookie")
	response.Header.Del("Set-Cookie")
	for _, line := range lines {
		name, _, _ := strings.Cut(line, "=")
		if !reserved[strings.ToLower(strings.TrimSpace(name))] {
			response.Header.Add("Set-Cookie", line)
		}
	}
	return nil
}
