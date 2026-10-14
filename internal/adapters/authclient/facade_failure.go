package authclient

import (
	"encoding/json"
	"slices"

	"github.com/JustIkra/umir-gateway/internal/operatorhttp"
)

func decodeFacadeFailure(data []byte, status int) (*operatorhttp.AuthFailure, error) {
	return decodeOperationFailure(data, status, false)
}

func decodeCollectionFailure(data []byte, status int) (*operatorhttp.AuthFailure, error) {
	return decodeOperationFailure(data, status, true)
}

func decodeOperationFailure(data []byte, status int, collection bool) (*operatorhttp.AuthFailure, error) {
	if operatorhttp.ValidateFacadeFailure(data) != nil {
		return nil, errInvalidResult
	}
	var wire struct {
		Code           string            `json:"code"`
		Outcome        string            `json:"outcome"`
		Retryable      bool              `json:"retryable"`
		FieldErrors    map[string]string `json:"fieldErrors"`
		SessionRevoked *bool             `json:"sessionRevoked"`
		Details        json.RawMessage   `json:"details"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	allowed := map[string]int{
		"InvalidArgument": 400, "InvalidRequest": 400, "InvalidCredentials": 401, "Unauthenticated": 401,
		"InvalidOrigin": 403, "InvalidCsrfToken": 403, "Forbidden": 403, "CurrentPasswordIncorrect": 400,
		"CommandConflict": 409, "LastAdmin": 409, "ScopeDeleted": 409, "SettingsChanged": 409,
		"UnknownTimeZone": 422, "TimeZoneDataUnavailable": 503, "RuntimeNotReady": 503,
		"NotFound": 404, "InvitationExpired": 404, "InvitationRevoked": 404, "InvalidProof": 400,
		"ChallengeLocked": 400, "DeliveryUnavailable": 503, "RateLimited": 429, "LoginRateLimited": 429,
		"PasswordChangeRateLimited": 429, "InvalidDisplayName": 422, "PasswordRejected": 422,
		"AuthUnavailable": 503, "AuthStorageUnavailable": 503, "AuthUpdateOutcomeUnknown": 503,
	}
	if collection {
		allowed["RefreshRequired"] = 409
		allowed["LimitExceeded"] = 503
		allowed["ScopeDeleted"] = 410
	}
	if allowed[wire.Code] != status || (wire.SessionRevoked != nil && wire.Code != "PasswordChangeRateLimited") ||
		(wire.Code == "PasswordChangeRateLimited" && wire.SessionRevoked == nil) {
		return nil, errInvalidResult
	}
	if wire.Code == "AuthUpdateOutcomeUnknown" {
		if wire.Outcome != "unknown" {
			return nil, errInvalidResult
		}
	} else if wire.Code == "InvalidArgument" && wire.Outcome == "committed" {
		// A wrong OTP attempt updates the durable challenge attempt count.
	} else if !slices.Contains([]string{"not_committed", "unavailable"}, wire.Outcome) {
		return nil, errInvalidResult
	}
	var details struct {
		RetryAfter int `json:"retryAfterSeconds"`
	}
	if len(wire.Details) > 0 {
		if err := json.Unmarshal(wire.Details, &details); err != nil {
			return nil, err
		}
	}
	return &operatorhttp.AuthFailure{Status: status, Code: wire.Code, Outcome: wire.Outcome, Retryable: wire.Retryable, FieldErrors: wire.FieldErrors, Details: wire.Details, SessionRevoked: wire.SessionRevoked, RetryAfter: details.RetryAfter}, nil
}
