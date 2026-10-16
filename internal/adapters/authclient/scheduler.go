package authclient

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

func (c *Client) Registry(ctx context.Context) (expiration.Registry, error) {
	return c.readRegistry(ctx, c.registry.begin())
}

// readRegistry performs one registry read recorded under the sequence given by begin.
func (c *Client) readRegistry(ctx context.Context, sequence uint64) (expiration.Registry, error) {
	var result expiration.Registry
	err := c.scopeExchange(ctx, http.MethodGet, "/registry", nil, "Registry", &result)
	if err == nil {
		if validateErr := result.Validate(); validateErr != nil {
			return expiration.Registry{}, scopeUnavailable(validateErr)
		}
		if result.Complete {
			c.registry.store(sequence, result, c.now())
		}
	}
	return result, err
}
func (c *Client) ServiceToken(ctx context.Context, input expiration.ServiceRequest) (expiration.Credential, error) {
	if input.Operation != "expiry.due" {
		return expiration.Credential{}, errors.New("scheduler operation forbidden")
	}
	if cached, ok := c.tokens.get(input.RestaurantID, input.Epoch, c.now()); ok {
		return cached, nil
	}
	var result expiration.Credential
	err := c.scopeCall(ctx, "/service-tokens", input, "Token", &result)
	if err != nil {
		return expiration.Credential{}, err
	}
	now := c.now()
	if err := httpapi.ValidateSchedulerToken(result.Token, input.RestaurantID, input.Epoch, now); err != nil {
		return expiration.Credential{}, scopeUnavailable(err)
	}
	_, claims, _, _, err := httpapi.ParseServiceToken(result.Token, now)
	if err != nil || !result.ExpiresAt.Equal(time.Unix(claims.Expires, 0)) {
		return expiration.Credential{}, scopeUnavailable(errors.New("inconsistent token expiry"))
	}
	c.tokens.put(input.RestaurantID, input.Epoch, result, now)
	return result, nil
}
