package operatorhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

// CSRFHeader carries the synchronizer token of every unsafe request.
const CSRFHeader = "X-CSRF-Token"

const (
	// maxBody bounds an account request body; a 32-code-point password takes at most 128 bytes.
	maxBody = 8 << 10
	// bodyTimeout bounds how long a client may take to send that body.
	bodyTimeout = 10 * time.Second
)

type cookieNames struct{ session, preauth string }

var (
	// Browsers accept __Host- cookies only with Secure, Path=/ and no Domain.
	secureCookies   = cookieNames{session: "__Host-umir_operator_session", preauth: "__Host-umir_operator_preauth"}
	loopbackCookies = cookieNames{session: "umir_operator_session", preauth: "umir_operator_preauth"}
)

func (a *API) cookie(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func (a *API) setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", Secure: a.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (a *API) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Path: "/", MaxAge: -1, Secure: a.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// admitOrigin lets a state-changing request through only from the configured public origin, with
// Fetch Metadata, when the browser sends it, agreeing. It answers 403 otherwise.
func (a *API) admitOrigin(w http.ResponseWriter, r *http.Request) bool {
	origins := r.Header.Values("Origin")
	site := r.Header.Get("Sec-Fetch-Site")
	if len(origins) == 1 && origins[0] == a.origin && (site == "" || site == "same-origin") {
		return true
	}
	a.problem(w, r, http.StatusForbidden, "InvalidOrigin", "request origin is not allowed")
	return false
}

// decode reads exactly one JSON object into dst. It answers 415, 413 or 400 and returns false when
// the body is not one.
func (a *API) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		a.problem(w, r, http.StatusUnsupportedMediaType, "UnsupportedMediaType", "send the body as application/json")
		return false
	}
	// A request without a body has nothing to bound, and the server already reads its connection.
	if r.Body != http.NoBody {
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			a.fail(w, r, fmt.Errorf("body read deadline: %w", err), "")
			return false
		}
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(dst)
	if err == nil {
		if extra := decoder.Decode(&struct{}{}); !errors.Is(extra, io.EOF) {
			err = extra
			if err == nil {
				err = errors.New("data after the JSON object")
			}
		}
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		a.problem(w, r, http.StatusRequestEntityTooLarge, "PayloadTooLarge", "request body is too large")
		return false
	case err != nil:
		a.problem(w, r, http.StatusBadRequest, "InvalidRequest", "request body is not the expected JSON object")
		return false
	}
	return true
}
