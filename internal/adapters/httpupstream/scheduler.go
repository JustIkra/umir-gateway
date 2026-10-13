package httpupstream

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

func (c *ScopedClient) Status(ctx context.Context) (expiration.RuntimeStatus, error) {
	response, err := c.Do(ctx, httpapi.BusinessRequest{Service: "warehouse", Method: http.MethodGet, Path: "/internal/warehouse/v2/runtime", Header: http.Header{"Accept": []string{"application/json"}}})
	if err != nil {
		return expiration.RuntimeStatus{}, err
	}
	if err := schedulerResponse(response, "RuntimeStatus"); err != nil {
		return expiration.RuntimeStatus{}, err
	}
	var result expiration.RuntimeStatus
	err = json.Unmarshal(response.Body, &result)
	return result, err
}
func (c *ScopedClient) Due(ctx context.Context, input expiration.DueRequest) (expiration.DueResult, error) {
	body, err := json.Marshal(struct {
		RunID string `json:"runID"`
	}{input.RunID})
	if err != nil {
		return expiration.DueResult{}, err
	}
	response, err := c.Do(ctx, httpapi.BusinessRequest{Service: "warehouse", Method: http.MethodPost, Path: "/internal/warehouse/v2/r/" + input.RestaurantID + "/expiry-runs", Header: http.Header{"Authorization": []string{"Bearer " + input.Token}, "Content-Type": []string{"application/json"}, "Accept": []string{"application/json"}, "X-Umir-Runtime-Epoch": []string{input.Epoch}}, Body: body})
	if err != nil {
		return expiration.DueResult{}, err
	}
	if response.Status >= 400 && response.Status <= 599 && httpapi.ValidateScopeWire("Error", response.Body) == nil {
		var failure httpapi.ScopeError
		if err := json.Unmarshal(response.Body, &failure); err != nil {
			return expiration.DueResult{}, err
		}
		return expiration.DueResult{}, &expiration.DueFailure{Status: response.Status, Outcome: failure.Outcome, Cause: &failure}
	}
	if err := schedulerResponse(response, "ScopedDueExpiryResult"); err != nil {
		return expiration.DueResult{}, err
	}
	var wire struct {
		Context struct {
			OrgID    string `json:"orgID"`
			TenantID string `json:"tenantID"`
			Epoch    string `json:"runtimeEpoch"`
			Version  string `json:"stateVersion"`
		} `json:"context"`
		Result struct {
			Version        string   `json:"committedVersion"`
			Invalidation   bool     `json:"invalidationRequired"`
			FinalWriteoffs int      `json:"finalWriteoffs"`
			Transitioned   []string `json:"transitionedBatchIDs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body, &wire); err != nil {
		return expiration.DueResult{}, err
	}
	if wire.Context.OrgID != input.OrgID || wire.Context.TenantID != input.RestaurantID || wire.Context.Epoch != input.Epoch || wire.Context.Version != wire.Result.Version || wire.Result.Invalidation != (len(wire.Result.Transitioned) > 0) {
		return expiration.DueResult{}, errors.New("inconsistent scheduler result")
	}
	return expiration.DueResult{Epoch: wire.Context.Epoch, Version: wire.Result.Version, Invalidation: wire.Result.Invalidation, FinalWriteoffs: wire.Result.FinalWriteoffs}, nil
}
func schedulerResponse(response httpapi.BusinessResponse, schema string) error {
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || response.Status != http.StatusOK {
		return errors.New("scheduler response unavailable")
	}
	return httpapi.ValidateScopeWire(schema, response.Body)
}
