package operatorhttp

import (
	"net/http"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// GuardLive admits GET /api/live with a live session that Peek checks, so opening a stream never extends
// it, and with Fetch Metadata, when the browser sends it, from the same origin. Nothing reaches next
// otherwise; next gets the session ID and the session as Peek saw it.
func (a *API) GuardLive(next func(w http.ResponseWriter, r *http.Request, id string, session operator.Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			a.problem(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "use GET")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			a.problem(w, r, http.StatusForbidden, "InvalidOrigin", "request origin is not allowed")
			return
		}
		id := a.cookie(r, a.cookies.session)
		_, session, err := a.accounts.Peek(id)
		if err != nil {
			a.fail(w, r, err, "")
			return
		}
		next(w, r, id, session)
	})
}
