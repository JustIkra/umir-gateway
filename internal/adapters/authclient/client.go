package authclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

const maxResponse = 1 << 20

type Options struct {
	URL        *url.URL
	ServiceKey string
	Timeout    time.Duration
	Transport  http.RoundTripper
	Now        func() time.Time
}

type Client struct {
	target           url.URL
	key              string
	timeout          time.Duration
	transport        http.RoundTripper
	now              func() time.Time
	keysMu           sync.Mutex
	keys             map[string]ed25519.PublicKey
	keysAt           time.Time
	unknownRefreshed bool
	registry         registryCache
}

func New(opts Options) (*Client, error) {
	if opts.URL == nil || opts.URL.Host == "" || opts.URL.User != nil || opts.URL.RawQuery != "" || opts.URL.ForceQuery || opts.URL.Fragment != "" ||
		(opts.URL.Scheme != "http" && opts.URL.Scheme != "https") || (opts.URL.Path != "" && opts.URL.Path != "/") ||
		opts.ServiceKey == "" || strings.ContainsAny(opts.ServiceKey, " \t\r\n") || opts.Timeout <= 0 || opts.Transport == nil {
		return nil, errors.New("authclient: origin URL, transport, credential and positive timeout are required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Client{target: *opts.URL, key: opts.ServiceKey, timeout: opts.Timeout, transport: opts.Transport, now: opts.Now}, nil
}

func (c *Client) CSRF(ctx context.Context, browser operatorhttp.BrowserContext) (operatorhttp.CSRFResult, error) {
	var result operatorhttp.CSRFResult
	err := c.call(ctx, http.MethodGet, "/csrf", browser, nil, http.StatusOK, &result, validateCSRF)
	return result, err
}

func (c *Client) Login(ctx context.Context, browser operatorhttp.BrowserContext, input operatorhttp.LoginInput) (operatorhttp.SessionIssued, error) {
	var result operatorhttp.SessionIssued
	err := c.call(ctx, http.MethodPost, "/session", browser, input, http.StatusOK, &result, validateIssued)
	return result, err
}

func (c *Client) Logout(ctx context.Context, browser operatorhttp.BrowserContext) error {
	return c.call(ctx, http.MethodDelete, "/session", browser, nil, http.StatusNoContent, nil, nil)
}

func (c *Client) Me(ctx context.Context, browser operatorhttp.BrowserContext) (operatorhttp.AuthView, error) {
	var result operatorhttp.AuthView
	err := c.call(ctx, http.MethodGet, "/me", browser, nil, http.StatusOK, &result, validateView)
	return result, err
}

func (c *Client) DisplayName(ctx context.Context, browser operatorhttp.BrowserContext, input operatorhttp.DisplayNameInput) (operatorhttp.AuthUser, error) {
	var result operatorhttp.AuthUser
	err := c.call(ctx, http.MethodPatch, "/me/display-name", browser, input, http.StatusOK, &result, validateUser)
	return result, err
}

func (c *Client) Password(ctx context.Context, browser operatorhttp.BrowserContext, input operatorhttp.PasswordInput) error {
	return c.call(ctx, http.MethodPatch, "/me/password", browser, input, http.StatusNoContent, nil, nil)
}

func unavailable(method string, cause error) *operatorhttp.AuthFailure {
	outcome := "unknown"
	if method == http.MethodGet {
		outcome = "unavailable"
	}
	return &operatorhttp.AuthFailure{Status: http.StatusServiceUnavailable, Code: "AuthUnavailable", Outcome: outcome, Cause: cause}
}

func (c *Client) call(ctx context.Context, method, path string, browser operatorhttp.BrowserContext, input any, status int, result any, validate func([]byte) error) error {
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return unavailable(method, err)
		}
	}
	return c.exchange(ctx, method, path, "", browser, body, status, result, validate, decodeFailure, true)
}

func (c *Client) Public(ctx context.Context, browser operatorhttp.BrowserContext, in operatorhttp.FacadeRequest) (json.RawMessage, error) {
	op, err := operatorhttp.ValidateFacadeRequest(in)
	if err != nil {
		return nil, unavailable(in.Method, err)
	}
	var result json.RawMessage
	err = c.exchange(ctx, in.Method, strings.TrimPrefix(in.Path, "/api/v2"), in.RawQuery, browser, in.Body, op.Status, &result, func(data []byte) error {
		if err := op.ValidateResponse(in, data); err != nil {
			return err
		}
		switch in.Path {
		case "/api/v2/csrf":
			return validateCSRF(data)
		case "/api/v2/session":
			return validateIssued(data)
		}
		if strings.HasSuffix(op.Path, "/complete") {
			return validateIssued(data)
		}
		return nil
	}, decodeFacadeFailure, false)
	return result, err
}

func (c *Client) exchange(ctx context.Context, method, path, query string, browser operatorhttp.BrowserContext, body []byte, status int, result any, validate func([]byte) error, decodeError func([]byte, int) (*operatorhttp.AuthFailure, error), requireRetryAfter bool) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	target := c.target
	target.Path, target.RawPath, target.RawQuery = "/internal/auth/v1/public"+path, "", query
	r, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return unavailable(method, err)
	}
	r.Header.Set("X-Umir-Service-Key", c.key)
	r.Header.Set("Accept", "application/json")
	if len(body) != 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	for key, value := range map[string]string{"X-Umir-Session": browser.SessionToken, "X-Umir-Preauth": browser.PreauthToken, "X-Umir-CSRF-Token": browser.CSRFToken, "X-Umir-Activity": browser.Activity} {
		if value != "" {
			r.Header.Set(key, value)
		}
	}
	// RoundTrip has no redirect or application retry policy. A modifying request has no replay body.
	r.GetBody = nil
	response, err := c.transport.RoundTrip(r)
	if err != nil {
		return unavailable(method, err)
	}
	if response == nil || response.Body == nil {
		return unavailable(method, errors.New("missing Auth response"))
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(data) > maxResponse {
		return unavailable(method, errors.Join(readErr, closeErr, errors.New("auth response unavailable")))
	}
	if response.StatusCode == status && status == http.StatusNoContent {
		if len(bytes.TrimSpace(data)) != 0 {
			return unavailable(method, errors.New("unexpected Auth response body"))
		}
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return unavailable(method, errors.New("unexpected Auth response type"))
	}
	if response.StatusCode != status {
		failure, err := decodeError(data, response.StatusCode)
		if err != nil {
			return unavailable(method, err)
		}
		if header := response.Header.Get("Retry-After"); header != "" {
			seconds, err := strconv.Atoi(header)
			if err != nil || seconds < 1 || strconv.Itoa(seconds) != header || (failure.RetryAfter != 0 && failure.RetryAfter != seconds) {
				return unavailable(method, errInvalidResult)
			}
			failure.RetryAfter = seconds
		}
		if requireRetryAfter && failure.Status == http.StatusTooManyRequests && failure.RetryAfter == 0 {
			return unavailable(method, errInvalidResult)
		}
		return failure
	}
	if err := validate(data); err != nil {
		return unavailable(method, err)
	}
	if err := json.Unmarshal(data, result); err != nil {
		return unavailable(method, errors.New("invalid Auth result"))
	}
	return nil
}
