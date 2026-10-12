package operatorhttp

import (
	"net/http"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// ActivityHeader marks a request the operator did not cause, such as a re-read after a live signal.
// Only the exact value background has meaning: such a request is checked without extending the session.
const ActivityHeader = "X-Umir-Activity"

// background reports a request that carries exactly one ActivityHeader with the value background.
func background(r *http.Request) bool {
	values := r.Header.Values(ActivityHeader)
	return len(values) == 1 && values[0] == "background"
}

// peekAuthorized admits an unsafe background request as Authorize would, without extending the session.
func (a *API) peekAuthorized(id, csrfToken string) error {
	_, session, err := a.accounts.Peek(id)
	if err == nil && !operator.MatchToken(session.CSRFToken, csrfToken) {
		err = operator.ErrInvalidCSRFToken
	}
	return err
}
