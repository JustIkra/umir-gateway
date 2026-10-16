package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// serviceTokenAt builds a signed service token with the given issue time and the fixed 60 s lifetime.
func serviceTokenAt(t *testing.T, issued int64) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "synthetic-key"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := json.Marshal(map[string]any{"iss": "urn:umir:auth", "aud": []string{"umir-warehouse"}, "iat": issued, "nbf": issued, "exp": issued + 60, "jti": "55555555-5555-4555-8555-555555555555", "operation": "expiry.due", "permissions": []string{"expiry.due"}, "kind": "service", "sub": "service:gateway", "org_id": "22222222-2222-4222-8222-222222222222", "tenant_id": "33333333-3333-4333-8333-333333333333", "runtime_epoch": "44444444-4444-4444-8444-444444444444", "lifecycle_version": "1", "azp": "umir-gateway"})
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))
}

// The lifetime check has no clock skew allowance (R12): a token issued one second ahead of this clock
// is refused, and one issued now is accepted until the second it expires.
func TestW1ServiceTokenHasNoIssuedAtSkewAllowance(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		issued int64
		at     time.Time
		valid  bool
	}{
		"issued now":              {now.Unix(), now, true},
		"issued one second ahead": {now.Unix() + 1, now, false},
		"last valid second":       {now.Unix(), now.Add(59 * time.Second), true},
		"expires at exp":          {now.Unix(), now.Add(60 * time.Second), false},
		"issued a second ago":     {now.Unix() - 1, now, true},
		"expired a second before": {now.Unix() - 61, now, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateSchedulerToken(serviceTokenAt(t, tc.issued), "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", tc.at)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error %v", tc.valid, err)
			}
		})
	}
}
