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
// gateway. Other cookies keep their original text; the caller's request is not modified. Informational
// answers written through it, which a reverse proxy forwards without ModifyResponse, lose the Set-Cookie
// lines of the operator cookies.
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
		next.ServeHTTP(informational{w}, out)
	})
}

// informational drops reserved Set-Cookie lines from 1xx answers; the final answer is left to
// DropReservedCookies.
type informational struct{ http.ResponseWriter }

func (w informational) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		header := w.Header()
		lines := header.Values("Set-Cookie")
		header.Del("Set-Cookie")
		for _, line := range lines {
			if !reservedSetCookie(line) {
				header.Add("Set-Cookie", line)
			}
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the flushing and deadline methods of the wrapped writer.
func (w informational) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// DropReservedCookies removes upstream Set-Cookie lines that would replace an operator cookie. A
// nameless cookie goes too: browsers send it back as its bare value, which can read as a reserved
// name=value pair. It fits httputil.ReverseProxy.ModifyResponse.
func DropReservedCookies(response *http.Response) error {
	lines := response.Header.Values("Set-Cookie")
	response.Header.Del("Set-Cookie")
	for _, line := range lines {
		if !reservedSetCookie(line) {
			response.Header.Add("Set-Cookie", line)
		}
	}
	return nil
}

// reservedSetCookie reports a Set-Cookie line that would replace an operator cookie, or a nameless one,
// which browsers send back as its bare value and can read as a reserved name=value pair.
func reservedSetCookie(line string) bool {
	name, _, _ := strings.Cut(line, "=")
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "" || reserved[name]
}
