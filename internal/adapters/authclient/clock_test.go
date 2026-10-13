package authclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

const clockTenant = "11111111-1111-4111-8111-111111111111"
const clockEpoch = "22222222-2222-4222-8222-222222222222"

func clockToken(t *testing.T, key ed25519.PrivateKey, now time.Time, scheduler bool) string {
	t.Helper()
	claims := httpapi.ServiceClaims{Issuer: "urn:umir:auth", Audience: []string{"umir-gateway"}, Issued: now.Unix(), NotBefore: now.Unix(), Expires: now.Unix() + 60, JTI: clockEpoch, Operation: "runtime.register", Permissions: []string{"runtime.register"}, Kind: "service", Subject: "service:auth", OrgID: clockTenant, TenantID: clockTenant, Epoch: clockEpoch, LifecycleVersion: "1", Caller: "umir-auth"}
	if scheduler {
		claims.Audience, claims.Operation, claims.Permissions = []string{"umir-warehouse"}, "expiry.due", []string{"expiry.due"}
		claims.Subject, claims.Caller = "service:gateway", "umir-gateway"
	}
	h, err := json.Marshal(httpapi.ServiceHeader{Algorithm: "EdDSA", Type: "JWT", KeyID: "clock-key"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpapi.ValidateScopeWire("ServiceClaims", b); err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))
}

func TestInjectedClockControlsTokenValidationAndKeyRefresh(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initial := time.Date(2050, 1, 2, 9, 0, 0, 0, time.FixedZone("fixture", 3*60*60))
	var seconds atomic.Int64
	var reads atomic.Int64
	now := func() time.Time { return initial.Add(time.Duration(seconds.Load()) * time.Second) }
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Umir-Service-Key") != "private-key" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var value any
		switch r.URL.Path {
		case "/internal/auth/v1/jwks":
			reads.Add(1)
			value = map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "clock-key", "x": base64.RawURLEncoding.EncodeToString(public)}}}
		case "/internal/auth/v1/service-tokens":
			value = expiration.Credential{Token: clockToken(t, key, initial, true), ExpiresAt: initial.Add(time.Minute)}
		default:
			w.WriteHeader(404)
			return
		}
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}))
	defer peer.Close()
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{URL: target, ServiceKey: "private-key", Timeout: time.Second, Transport: http.DefaultTransport, Now: now}
	client, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("scheduler credential uses owner time", func(t *testing.T) {
		if _, err := client.ServiceToken(t.Context(), expiration.ServiceRequest{RestaurantID: clockTenant, Epoch: clockEpoch, Operation: "expiry.due"}); err != nil {
			t.Fatalf("controlled scheduler token rejected: %v", err)
		}
	})
	token := clockToken(t, key, initial, false)
	if _, err := client.ControlToken(t.Context(), token); err != nil {
		t.Fatalf("controlled-clock control token rejected: %v", err)
	}
	seconds.Store(29)
	if _, err := client.ControlToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 {
		t.Fatal("key refresh used another clock")
	}
	seconds.Store(30)
	if _, err := client.ControlToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 2 {
		t.Fatal("controlled key refresh did not run")
	}
	if _, err := client.ServiceToken(t.Context(), expiration.ServiceRequest{RestaurantID: clockTenant, Epoch: clockEpoch, Operation: "expiry.due"}); err != nil {
		t.Fatalf("controlled scheduler token rejected: %v", err)
	}
	seconds.Store(60)
	if _, err := client.ControlToken(t.Context(), token); err == nil {
		t.Fatal("expired control token accepted")
	}
	if _, err := client.ServiceToken(t.Context(), expiration.ServiceRequest{RestaurantID: clockTenant, Epoch: clockEpoch, Operation: "expiry.due"}); err == nil {
		t.Fatal("expired scheduler token accepted")
	}
}

type clockTransport func(*http.Request) (*http.Response, error)

func (f clockTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDefaultClockRejectsPastToken(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse("http://auth:8080")
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "private-key", Timeout: time.Second, Transport: clockTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("expired token reached transport")
		return nil, io.EOF
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ControlToken(context.Background(), clockToken(t, key, time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), false)); err == nil {
		t.Fatal("default system clock disabled")
	}
}
