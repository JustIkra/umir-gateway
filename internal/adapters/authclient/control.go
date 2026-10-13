package authclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

func (c *Client) ControlToken(ctx context.Context, raw string) (httpapi.ServiceClaims, error) {
	header, claims, message, signature, err := httpapi.ParseServiceToken(raw, c.now())
	if err != nil {
		return httpapi.ServiceClaims{}, invalidControl(err)
	}
	c.keysMu.Lock()
	defer c.keysMu.Unlock()
	now := c.now()
	periodic := c.keysAt.IsZero() || now.Sub(c.keysAt) >= 30*time.Second
	refresh := periodic
	if !refresh && c.keys[header.KeyID] == nil && !c.unknownRefreshed {
		refresh = true
	}
	if refresh {
		var jwks struct {
			Keys []struct {
				ID string `json:"kid"`
				X  string `json:"x"`
			} `json:"keys"`
		}
		if err := c.scopeExchange(ctx, http.MethodGet, "/jwks", nil, "JWKS", &jwks); err != nil {
			return httpapi.ServiceClaims{}, scopeUnavailable(err)
		}
		keys := map[string]ed25519.PublicKey{}
		for _, key := range jwks.Keys {
			data, err := base64.RawURLEncoding.Strict().DecodeString(key.X)
			if err != nil || len(data) != ed25519.PublicKeySize || keys[key.ID] != nil {
				return httpapi.ServiceClaims{}, scopeUnavailable(errors.New("invalid discovery"))
			}
			keys[key.ID] = ed25519.PublicKey(data)
		}
		c.keys = keys
		c.keysAt = now
		c.unknownRefreshed = !periodic
	}
	key := c.keys[header.KeyID]
	if key == nil || !ed25519.Verify(key, message, signature) || c.now().Unix() >= claims.Expires {
		return httpapi.ServiceClaims{}, invalidControl(errors.New("invalid signature"))
	}
	return claims, nil
}
func invalidControl(cause error) *httpapi.ScopeError {
	return &httpapi.ScopeError{Status: 401, Code: "InvalidToken", Outcome: "not_committed", Message: "invalid internal token", Cause: cause}
}
