package authclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

// tokenPeer mints a scheduler service token valid for 60 s from the injected clock for whatever
// restaurant and epoch the request names, and counts the requests.
type tokenPeer struct {
	*httptest.Server
	requests atomic.Int64
	now      func() time.Time
}

func newTokenPeer(t *testing.T, key ed25519.PrivateKey, now func() time.Time) *tokenPeer {
	t.Helper()
	p := &tokenPeer{now: now}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/auth/v1/service-tokens" {
			w.WriteHeader(404)
			return
		}
		p.requests.Add(1)
		var input expiration.ServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		issued := p.now()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(expiration.Credential{Token: schedulerTokenFor(t, key, issued, input.RestaurantID, input.Epoch), ExpiresAt: issued.Add(time.Minute)}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func schedulerTokenFor(t *testing.T, key ed25519.PrivateKey, now time.Time, tenant, epoch string) string {
	t.Helper()
	claims := httpapi.ServiceClaims{Issuer: "urn:umir:auth", Audience: []string{"umir-warehouse"}, Issued: now.Unix(), NotBefore: now.Unix(), Expires: now.Unix() + 60, JTI: clockEpoch, Operation: "expiry.due", Permissions: []string{"expiry.due"}, Kind: "service", Subject: "service:gateway", OrgID: clockTenant, TenantID: tenant, Epoch: epoch, LifecycleVersion: "1", Caller: "umir-gateway"}
	h, err := json.Marshal(httpapi.ServiceHeader{Algorithm: "EdDSA", Type: "JWT", KeyID: "clock-key"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))
}

func TestW1ServiceTokenIsReusedWhileValid(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initial := time.Date(2050, 1, 2, 9, 0, 0, 0, time.UTC)
	var seconds atomic.Int64
	now := func() time.Time { return initial.Add(time.Duration(seconds.Load()) * time.Second) }
	peer := newTokenPeer(t, key, now)
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "private-key", Timeout: time.Second, Transport: http.DefaultTransport, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	const other = "33333333-3333-4333-8333-333333333333"
	const newEpoch = "44444444-4444-4444-8444-444444444444"
	request := func(restaurant, epoch string) expiration.Credential {
		t.Helper()
		credential, err := client.ServiceToken(t.Context(), expiration.ServiceRequest{RestaurantID: restaurant, Epoch: epoch, Operation: "expiry.due"})
		if err != nil {
			t.Fatal(err)
		}
		return credential
	}
	expect := func(want int64, what string) {
		t.Helper()
		if got := peer.requests.Load(); got != want {
			t.Fatalf("%s: %d token requests, want %d", what, got, want)
		}
	}
	first := request(clockTenant, clockEpoch)
	expect(1, "first token")
	seconds.Store(49)
	if again := request(clockTenant, clockEpoch); again.Token != first.Token {
		t.Fatal("a token valid for another 11 s was not reused")
	}
	expect(1, "reuse")
	request(other, clockEpoch)
	expect(2, "another restaurant")
	request(clockTenant, newEpoch)
	expect(3, "another epoch")
	seconds.Store(50)
	renewed := request(clockTenant, clockEpoch)
	expect(4, "ten seconds before expiry")
	seconds.Store(50 + 49)
	if again := request(clockTenant, clockEpoch); again.Token != renewed.Token {
		t.Fatal("the renewed token was not reused")
	}
	expect(4, "reuse of the renewed token")
	seconds.Store(50 + 50)
	request(clockTenant, clockEpoch)
	expect(5, "renewal of the renewed token")
	if !renewed.ExpiresAt.After(now()) {
		t.Fatal("renewed token already expired")
	}
}

func TestW1ServiceTokenCacheKeepsConcurrentCallsSafe(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Date(2050, 1, 2, 9, 0, 0, 0, time.UTC) }
	peer := newTokenPeer(t, key, now)
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "private-key", Timeout: time.Second, Transport: http.DefaultTransport, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := client.ServiceToken(t.Context(), expiration.ServiceRequest{RestaurantID: clockTenant, Epoch: clockEpoch, Operation: "expiry.due"}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}
