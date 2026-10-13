package operatorhttp

import (
	"context"
	"fmt"
	"time"
)

type BrowserContext struct {
	SessionToken string
	PreauthToken string
	CSRFToken    string
	Activity     string
}

type AuthUser struct {
	UserID            string `json:"userID"`
	Login             string `json:"login"`
	DisplayName       string `json:"displayName"`
	Email             string `json:"email,omitempty"`
	CredentialVersion string `json:"credentialVersion"`
}

type AuthSession struct {
	ExpiresAt         time.Time `json:"expiresAt"`
	IdleExpiresAt     time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt time.Time `json:"absoluteExpiresAt"`
	RememberMe        bool      `json:"rememberMe"`
	CSRFToken         string    `json:"csrfToken"`
}

type AuthView struct {
	User    AuthUser    `json:"user"`
	Session AuthSession `json:"session"`
}

type SessionIssued struct {
	View         AuthView `json:"view"`
	SessionToken string   `json:"sessionToken"`
}

type CSRFResult struct {
	CSRFToken    string    `json:"csrfToken"`
	PreauthToken string    `json:"preauthToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitempty"`
}

type LoginInput struct {
	Login      string `json:"login"`
	Password   string `json:"password"`
	RememberMe bool   `json:"rememberMe,omitempty"`
	CommandID  string `json:"commandID"`
}

type DisplayNameInput struct {
	DisplayName string `json:"displayName"`
	CommandID   string `json:"commandID"`
}

type PasswordInput struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	CommandID       string `json:"commandID"`
}

type AuthClient interface {
	CSRF(context.Context, BrowserContext) (CSRFResult, error)
	Login(context.Context, BrowserContext, LoginInput) (SessionIssued, error)
	Logout(context.Context, BrowserContext) error
	Me(context.Context, BrowserContext) (AuthView, error)
	DisplayName(context.Context, BrowserContext, DisplayNameInput) (AuthUser, error)
	Password(context.Context, BrowserContext, PasswordInput) error
}

type AuthFailure struct {
	Status         int
	Code           string
	Outcome        string
	Retryable      bool
	RetryAfter     int
	FieldErrors    map[string]string
	SessionRevoked *bool
	Cause          error
}

func (e *AuthFailure) Error() string {
	return fmt.Sprintf("Auth request failed: %s (%s)", e.Code, e.Outcome)
}

func (e *AuthFailure) Unwrap() error { return e.Cause }
