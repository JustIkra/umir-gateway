// Package operatorhttp maps the operator account module to HTTP: the /api/operator routes, the guard
// of business routes and the operator cookies. Account rules stay in package operator.
package operatorhttp

import (
	"context"
	"errors"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// Sessions is the session-authorization port of the business-route guard.
type Sessions interface {
	// Authenticate admits a safe request and extends the session's idle deadline.
	Authenticate(id string) (operator.Profile, operator.Session, error)
	// Authorize admits an unsafe request that carries the session's CSRF token.
	Authorize(id, csrfToken string) (operator.Profile, operator.Session, error)
}

// Accounts is what the account routes need besides Sessions; *operator.Service implements it.
type Accounts interface {
	Sessions
	AnonymousCSRF(id string) (contextID, token string, err error)
	CheckAnonymousCSRF(id, token string) bool
	DiscardAnonymous(id string)
	SessionCSRF(id string) (string, bool)
	Login(ctx context.Context, login, password, previousID string) (operator.Profile, operator.Session, error)
	Logout(id string)
	UpdateDisplayName(id, raw string) (operator.Profile, error)
	ChangePassword(ctx context.Context, id, current, next string) error
}

// CookieMode selects cookie names and the Secure attribute; configuration checks it against the origin.
type CookieMode string

const (
	ModeSecure   CookieMode = "secure"
	ModeLoopback CookieMode = "loopback-development"
)

type Options struct {
	Accounts Accounts
	Mode     CookieMode
	// PublicOrigin is the exact Origin header browsers send to the frontend edge.
	PublicOrigin string
	// Logger receives request IDs, routes and error codes, never credentials or bodies.
	Logger *log.Logger
}

// API serves /api/operator/ and guards business routes.
type API struct {
	accounts Accounts
	cookies  cookieNames
	secure   bool
	origin   string
	logger   *log.Logger
}

func New(opts Options) (*API, error) {
	if opts.Accounts == nil || opts.Logger == nil {
		return nil, errors.New("operatorhttp: accounts and logger are required")
	}
	api := &API{accounts: opts.Accounts, origin: opts.PublicOrigin, logger: opts.Logger}
	switch {
	case opts.Mode == ModeSecure && strings.HasPrefix(opts.PublicOrigin, "https://"):
		api.secure, api.cookies = true, secureCookies
	case opts.Mode == ModeLoopback && strings.HasPrefix(opts.PublicOrigin, "http://"):
		api.cookies = loopbackCookies
	default:
		return nil, errors.New("operatorhttp: cookie mode and public origin do not match")
	}
	return api, nil
}

type handlerFunc func(*API, http.ResponseWriter, *http.Request)

// routes maps each operator path to its methods; HEAD is served as GET.
var routes = map[string]map[string]handlerFunc{
	"/api/operator/csrf":            {http.MethodGet: (*API).csrf},
	"/api/operator/session":         {http.MethodPost: (*API).login, http.MethodDelete: (*API).logout},
	"/api/operator/me":              {http.MethodGet: (*API).me},
	"/api/operator/me/display-name": {http.MethodPatch: (*API).updateDisplayName},
	"/api/operator/me/password":     {http.MethodPatch: (*API).changePassword},
}

// ServeHTTP serves /api/operator/. No response of these routes may be cached.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	methods, ok := routes[r.URL.Path]
	if !ok {
		a.problem(w, r, http.StatusNotFound, "NotFound", "unknown operator route")
		return
	}
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	handle, ok := methods[method]
	if !ok {
		allowed := slices.Sorted(maps.Keys(methods))
		if methods[http.MethodGet] != nil {
			allowed = append(allowed, http.MethodHead)
		}
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		a.problem(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "method is not allowed for this route")
		return
	}
	handle(a, w, r)
}
