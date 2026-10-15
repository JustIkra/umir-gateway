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
	sequence := c.registry.begin()
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
	return result, nil
}
