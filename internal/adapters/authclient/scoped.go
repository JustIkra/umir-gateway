package authclient

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

func (c *Client) Authorize(ctx context.Context, input httpapi.AuthorizationRequest) (httpapi.AuthorizationResult, error) {
	var result httpapi.AuthorizationResult
	err := c.scopeCall(ctx, "/authorize", input, "AuthorizationResult", &result)
	if err == nil && (result.TenantID != input.RestaurantID || validateScopeSession(result.Session) != nil) {
		return httpapi.AuthorizationResult{}, scopeUnavailable(errors.New("inconsistent authorization"))
	}
	return result, err
}

func validateScopeSession(s httpapi.ScopeSession) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return validateSession(data)
}

func (c *Client) AccessCheck(ctx context.Context, input httpapi.AccessCheckRequest) (httpapi.RestaurantAccess, error) {
	var result httpapi.RestaurantAccess
	err := c.scopeCall(ctx, "/access-check", input, "RestaurantAccess", &result)
	if err == nil && result.RestaurantID != input.RestaurantID {
		return httpapi.RestaurantAccess{}, scopeUnavailable(errors.New("inconsistent access"))
	}
	return result, err
}

func (c *Client) AnonymousToken(ctx context.Context) (httpapi.ScopeToken, error) {
	var result httpapi.ScopeToken
	err := c.scopeCall(ctx, "/anonymous-feedback-token", struct {
		Operation string `json:"operation"`
	}{"feedback.anonymous.submit"}, "Token", &result)
	return result, err
}

func (c *Client) CheckCSRF(ctx context.Context, session, preauth, token string) error {
	if session == "" && preauth == "" {
		// Auth would issue a new preauth record for the empty context only to see the token refused.
		return &httpapi.ScopeError{Status: 403, Code: "InvalidCsrfToken", Outcome: "not_committed", Message: "invalid CSRF token"}
	}
	result, err := c.CSRF(ctx, operatorhttp.BrowserContext{SessionToken: session, PreauthToken: preauth, Activity: "background"})
	if err != nil {
		var failure *operatorhttp.AuthFailure
		if errors.As(err, &failure) {
			result := &httpapi.ScopeError{Status: failure.Status, Code: failure.Code, Outcome: failure.Outcome, Retryable: failure.Retryable, RetryAfter: failure.RetryAfter, Message: "authentication request failed", Cause: failure.Cause}
			if failure.RetryAfter > 0 {
				result.Details = map[string]any{"retryAfterSeconds": failure.RetryAfter}
			}
			return result
		}
		return scopeUnavailable(err)
	}
	if result.PreauthToken != "" || token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(result.CSRFToken)) != 1 {
		return &httpapi.ScopeError{Status: 403, Code: "InvalidCsrfToken", Outcome: "not_committed", Message: "invalid CSRF token"}
	}
	return nil
}

func scopeUnavailable(err error) *httpapi.ScopeError {
	return &httpapi.ScopeError{Status: 503, Code: "AuthUnavailable", Outcome: "unavailable", Message: "authorization is unavailable", Cause: err}
}

func (c *Client) scopeCall(ctx context.Context, path string, input any, schema string, result any) error {
	return c.scopeExchange(ctx, http.MethodPost, path, input, schema, result)
}

func (c *Client) scopeExchange(ctx context.Context, method, path string, input any, schema string, result any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body, err := json.Marshal(input)
	if err != nil {
		return scopeUnavailable(err)
	}
	target := c.target
	target.Path, target.RawPath = "/internal/auth/v1"+path, ""
	if input == nil {
		body = nil
	}
	r, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return scopeUnavailable(err)
	}
	r.Header.Set("X-Umir-Service-Key", c.key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if id := httpapi.RequestIDFromContext(ctx); id != "" {
		r.Header.Set("X-Request-ID", id)
	}
	r.GetBody = nil
	response, err := c.transport.RoundTrip(r)
	if err != nil {
		return scopeUnavailable(httpapi.Classed(httpapi.ClassTransport, err))
	}
	if response == nil || response.Body == nil {
		return scopeUnavailable(errors.New("missing authorization response"))
	}
	limit := maxResponse
	if schema == "Registry" {
		limit = 32 << 20
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	closeErr := response.Body.Close()
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if readErr != nil || closeErr != nil || mediaErr != nil || media != "application/json" || len(data) > limit {
		return scopeUnavailable(errors.New("invalid authorization response"))
	}
	if response.StatusCode != 200 {
		if response.StatusCode < 400 || response.StatusCode > 599 || httpapi.ValidateScopeWire("Error", data) != nil {
			return scopeUnavailable(errors.New("invalid authorization error"))
		}
		var failure httpapi.ScopeError
		if err := json.Unmarshal(data, &failure); err != nil {
			return scopeUnavailable(err)
		}
		failure.Status = response.StatusCode
		var metadata struct {
			Details struct{ RetryAfterSeconds int } `json:"details"`
		}
		if err := json.Unmarshal(data, &metadata); err != nil {
			return scopeUnavailable(err)
		}
		failure.RetryAfter = metadata.Details.RetryAfterSeconds
		if header := response.Header.Get("Retry-After"); header != "" {
			seconds, err := strconv.Atoi(header)
			if err != nil || seconds < 1 || strconv.Itoa(seconds) != header || (failure.RetryAfter != 0 && failure.RetryAfter != seconds) {
				return scopeUnavailable(errors.New("invalid authorization retry delay"))
			}
			failure.RetryAfter = seconds
		}
		if failure.Status == http.StatusTooManyRequests && failure.RetryAfter == 0 {
			return scopeUnavailable(errors.New("missing authorization retry delay"))
		}
		return &failure
	}
	if err := httpapi.ValidateScopeWire(schema, data); err != nil {
		return scopeUnavailable(httpapi.Classed(httpapi.ClassSchema, err))
	}
	if err := json.Unmarshal(data, result); err != nil {
		return scopeUnavailable(err)
	}
	return nil
}
