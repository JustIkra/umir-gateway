package operatorhttp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// maxFeedbackBody bounds a post of the public feedback form (gateway#10).
const maxFeedbackBody = 16 << 10

// GuardFeedback admits a post of the public feedback form: POST from the public origin with the CSRF
// token of the operator's session or of an anonymous context, within the feedback limits, and with one
// JSON object of at most 16 KiB. Nothing reaches next otherwise, and no session is extended. next gets
// the body already read, without cookies or the CSRF header; the feedback service validates the rest.
func (a *API) GuardFeedback(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			a.problem(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "use POST")
			return
		}
		if !a.admitOrigin(w, r) {
			return
		}
		if err := a.accounts.AdmitFeedback(a.cookie(r, a.cookies.session), a.cookie(r, a.cookies.preauth), r.Header.Get(CSRFHeader)); err != nil {
			a.fail(w, r, err, "")
			return
		}
		body, ok := a.readJSON(w, r, maxFeedbackBody)
		if !ok {
			return
		}
		if !json.Valid(body) || !bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("{")) {
			a.problem(w, r, http.StatusBadRequest, "InvalidRequest", "request body is not a JSON object")
			return
		}
		out := r.Clone(r.Context())
		out.Header.Del("Cookie")
		out.Header.Del(CSRFHeader)
		out.Body, out.ContentLength, out.TransferEncoding = io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
		next.ServeHTTP(w, out)
	})
}
