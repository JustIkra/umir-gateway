package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type AuthorizationRequest struct {
	SessionToken string   `json:"sessionToken"`
	RestaurantID string   `json:"restaurantID"`
	Operation    string   `json:"operation"`
	Audiences    []string `json:"audiences"`
	Activity     string   `json:"activity"`
}

type ScopeSettings struct {
	TimeZone        string `json:"timeZone"`
	SettingsVersion string `json:"settingsVersion"`
}

type ScopeSession struct {
	ExpiresAt         time.Time `json:"expiresAt"`
	IdleExpiresAt     time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt time.Time `json:"absoluteExpiresAt"`
	RememberMe        bool      `json:"rememberMe"`
	CSRFToken         string    `json:"csrfToken"`
}

type AuthorizationResult struct {
	UserID            string        `json:"userID"`
	SessionID         string        `json:"sessionID"`
	SessionVersion    string        `json:"sessionVersion"`
	CredentialVersion string        `json:"credentialVersion"`
	AccessVersion     string        `json:"accessVersion"`
	OrgID             string        `json:"orgID"`
	TenantID          string        `json:"tenantID"`
	Permissions       []string      `json:"permissions"`
	Settings          ScopeSettings `json:"settings"`
	LifecycleVersion  string        `json:"lifecycleVersion"`
	Token             string        `json:"token"`
	ExpiresAt         time.Time     `json:"expiresAt"`
	Session           ScopeSession  `json:"session"`
}

type AccessCheckRequest struct {
	SessionToken string `json:"sessionToken"`
	RestaurantID string `json:"restaurantID"`
	Operation    string `json:"operation"`
}

type RestaurantAccess struct {
	OrgID            string        `json:"orgID"`
	RestaurantID     string        `json:"restaurantID"`
	Roles            []string      `json:"roles"`
	OrgRoles         []string      `json:"orgRoles"`
	Permissions      []string      `json:"permissions"`
	Settings         ScopeSettings `json:"settings"`
	LifecycleVersion string        `json:"lifecycleVersion"`
}

type ScopeToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ScopedAuth interface {
	Authorize(context.Context, AuthorizationRequest) (AuthorizationResult, error)
	AccessCheck(context.Context, AccessCheckRequest) (RestaurantAccess, error)
	AnonymousToken(context.Context) (ScopeToken, error)
	CheckCSRF(context.Context, string, string, string) error
}

type BusinessRequest struct {
	Service  string
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Body     []byte
}

type BusinessResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

type BusinessClient interface {
	Do(context.Context, BusinessRequest) (BusinessResponse, error)
}

type ScopeError struct {
	Status     int            `json:"-"`
	Code       string         `json:"code"`
	Outcome    string         `json:"outcome"`
	Message    string         `json:"message"`
	Retryable  bool           `json:"retryable"`
	RetryAfter int            `json:"-"`
	Details    map[string]any `json:"details,omitempty"`
	Cause      error          `json:"-"`
}

func (e *ScopeError) Error() string {
	return fmt.Sprintf("scoped request failed: %s (%s)", e.Code, e.Outcome)
}
func (e *ScopeError) Unwrap() error { return e.Cause }
