package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/JustIkra/umir-gateway/internal/strictjson"
)

type ServiceClaims struct {
	Issuer           string   `json:"iss"`
	Audience         []string `json:"aud"`
	Issued           int64    `json:"iat"`
	NotBefore        int64    `json:"nbf"`
	Expires          int64    `json:"exp"`
	JTI              string   `json:"jti"`
	Operation        string   `json:"operation"`
	Permissions      []string `json:"permissions"`
	Kind             string   `json:"kind"`
	Subject          string   `json:"sub"`
	OrgID            string   `json:"org_id"`
	TenantID         string   `json:"tenant_id"`
	Epoch            string   `json:"runtime_epoch"`
	LifecycleVersion string   `json:"lifecycle_version"`
	Caller           string   `json:"azp"`
}
type ServiceHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

func ParseServiceToken(raw string, now time.Time) (ServiceHeader, ServiceClaims, []byte, []byte, error) {
	var header ServiceHeader
	var claims ServiceClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 16384 {
		return header, claims, nil, nil, errors.New("invalid service token")
	}
	h, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return header, claims, nil, nil, err
	}
	fields, err := strictjson.Object(h)
	if err != nil || len(fields) != 3 {
		return header, claims, nil, nil, errors.New("invalid token header")
	}
	if err := json.Unmarshal(h, &header); err != nil || header.Algorithm != "EdDSA" || header.Type != "JWT" || header.KeyID == "" {
		return header, claims, nil, nil, errors.New("invalid token header")
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return header, claims, nil, nil, err
	}
	if err := ValidateScopeWire("ServiceClaims", data); err != nil {
		return header, claims, nil, nil, err
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return header, claims, nil, nil, err
	}
	if claims.NotBefore != claims.Issued || claims.Expires-claims.Issued != 60 || claims.Issued > now.Unix() || now.Unix() >= claims.Expires {
		return header, claims, nil, nil, errors.New("invalid token lifetime")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return header, claims, nil, nil, errors.New("invalid token signature encoding")
	}
	return header, claims, []byte(parts[0] + "." + parts[1]), signature, nil
}
func ValidateSchedulerToken(raw, tenant, epoch string, now time.Time) error {
	_, claims, _, _, err := ParseServiceToken(raw, now)
	if err != nil {
		return err
	}
	if claims.Kind != "service" || claims.Subject != "service:gateway" || claims.Caller != "umir-gateway" || claims.TenantID != tenant || claims.Epoch != epoch || claims.Operation != "expiry.due" || !slices.Equal(claims.Audience, []string{"umir-warehouse"}) || !slices.Equal(claims.Permissions, []string{"expiry.due"}) {
		return errors.New("invalid scheduler scope")
	}
	return nil
}
