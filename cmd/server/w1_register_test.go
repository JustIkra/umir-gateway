package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// w1Register drives the private registration route against an Auth peer that counts registry reads.
type w1Register struct {
	t        *testing.T
	app      components
	clock    *w1Clock
	key      ed25519.PrivateKey
	epoch    string
	fetches  atomic.Int64
	gate     chan struct{} // when non-nil, registry reads wait for it to close
	settings atomic.Value  // settingsVersion the registry reports
	present  atomic.Bool   // whether the registry has the restaurant
	state    atomic.Value  // lifecycle the registry reports
}

func newW1Register(t *testing.T, gated bool) *w1Register {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &w1Register{t: t, key: key}
	if gated {
		f.gate = make(chan struct{})
	}
	f.settings.Store("1")
	f.state.Store("registering")
	f.present.Store(true)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/auth/v1/jwks":
			writeScopedJSON(t, w, map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "synthetic-key", "x": base64.RawURLEncoding.EncodeToString(public)}}})
		case "/internal/auth/v1/registry":
			f.fetches.Add(1)
			if f.gate != nil {
				select {
				case <-f.gate:
				case <-r.Context().Done():
					return
				}
			}
			entries := []any{}
			if f.present.Load() {
				entries = append(entries, map[string]any{"restaurant": map[string]any{"restaurantID": scopedRestaurant, "orgID": scopedOrg, "name": "Synthetic", "lifecycle": f.state.Load(), "lifecycleVersion": "1"}, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": f.settings.Load()}, "services": []any{}})
			}
			writeScopedJSON(t, w, map[string]any{"registryRevision": "1", "complete": true, "entries": entries, "tombstones": []any{}})
		default:
			t.Errorf("unexpected control path %s", r.URL.Path)
			w.WriteHeader(503)
		}
	}))
	t.Cleanup(func() {
		if f.gate != nil {
			select {
			case <-f.gate:
			default:
				close(f.gate)
			}
		}
		peer.Close()
	})
	// Tokens are signed with the real time, so the injected clock starts just after it.
	start := time.Now().Add(20 * time.Second)
	f.clock = &w1Clock{}
	now := func() time.Time { return start.Add(time.Duration(f.clock.offset.Load())) }
	values := map[string]string{"AUTH_URL": peer.URL, "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "AUTH_SERVICE_KEY": w1AuthKey, "SERVING_SERVICE_KEY": "w1-serving-key", "WAREHOUSE_SERVICE_KEY": "w1-warehouse-key", "FEEDBACK_SERVICE_KEY": "w1-feedback-key", "AUTH_RUNTIME_SERVICE_KEY": w1RuntimeKey, "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}
	f.app, err = newAuthComponentsWith(loadConfig(t, values), log.New(io.Discard, "", 0), componentEnv{now: now, newTicker: (&w1Tickers{}).NewTicker})
	if err != nil {
		t.Fatal(err)
	}
	status := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/internal/gateway/v2/runtime", nil)
	request.Header.Set("X-Umir-Service-Key", w1RuntimeKey)
	f.app.privateHandler.ServeHTTP(status, request)
	var runtime struct {
		Epoch string `json:"epoch"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &runtime); err != nil || runtime.Epoch == "" {
		t.Fatalf("runtime status: %v", err)
	}
	f.epoch = runtime.Epoch
	return f
}

// put registers the restaurant with the settings version the call carries and returns the status.
func (f *w1Register) put(settingsVersion string) int {
	f.t.Helper()
	token := g5Signed(f.t, f.key, scopedRestaurant, f.epoch, "runtime.register", "service:auth", "umir-auth", []string{"runtime.register"})
	data, err := json.Marshal(map[string]any{"operationID": "55555555-5555-4555-8555-555555555555", "expectedEpoch": f.epoch, "lifecycleVersion": "1", "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": settingsVersion}})
	if err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPut, "/internal/gateway/v2/r/"+scopedRestaurant+"/registry", bytes.NewReader(data))
	r.Header.Set("X-Umir-Service-Key", w1RuntimeKey)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.app.privateHandler.ServeHTTP(w, r)
	return w.Code
}

func TestW1RegisterReusesFreshSnapshotAndCoalescesFetch(t *testing.T) {
	t.Run("sequential registrations share one read", func(t *testing.T) {
		f := newW1Register(t, false)
		for i := range 100 {
			if code := f.put("1"); code != http.StatusOK {
				t.Fatalf("registration %d: %d", i, code)
			}
		}
		if got := f.fetches.Load(); got > 1 {
			t.Fatalf("100 registrations read the registry %d times", got)
		}
		// A snapshot older than 2 s is not used for registration, though readiness would still accept it.
		f.clock.Advance(3 * time.Second)
		if code := f.put("1"); code != http.StatusOK {
			t.Fatalf("registration after the snapshot aged: %d", code)
		}
		if got := f.fetches.Load(); got != 2 {
			t.Fatalf("a snapshot older than 2 s was reused or the read repeated: %d reads", got)
		}
	})
	t.Run("parallel registrations of an unknown restaurant share one read", func(t *testing.T) {
		f := newW1Register(t, true)
		const callers = 12
		codes := make([]int, callers)
		var wg sync.WaitGroup
		for i := range callers {
			wg.Go(func() { codes[i] = f.put("1") })
		}
		// Let every caller reach the gated read before Auth answers.
		time.Sleep(200 * time.Millisecond)
		close(f.gate)
		wg.Wait()
		for i, code := range codes {
			if code != http.StatusOK {
				t.Fatalf("caller %d: %d", i, code)
			}
		}
		if got := f.fetches.Load(); got != 1 {
			t.Fatalf("%d parallel registrations read the registry %d times, want 1", callers, got)
		}
	})
}

func TestW1RegisterRechecksDivergenceBeforeRefusing(t *testing.T) {
	f := newW1Register(t, false)
	if code := f.put("1"); code != http.StatusOK {
		t.Fatalf("first registration: %d", code)
	}
	// Auth changed the settings after the snapshot was taken; a registration carrying the new version
	// must not be refused with 409 on the strength of the stale snapshot.
	f.settings.Store("2")
	if code := f.put("2"); code != http.StatusOK {
		t.Fatalf("registration with the new settings refused from a stale snapshot: %d", code)
	}
	// A registration whose settings really are stale is still refused, now after a confirming read.
	before := f.fetches.Load()
	if code := f.put("1"); code != http.StatusConflict {
		t.Fatalf("stale settings: %d", code)
	}
	if f.fetches.Load() == before {
		t.Fatal("the conflict was answered without confirming it by a read")
	}
	// A restaurant missing from the snapshot is read for, not refused.
	f.present.Store(false)
	f.clock.Advance(3 * time.Second)
	if code := f.put("2"); code != http.StatusGone {
		t.Fatalf("restaurant absent from Auth: %d", code)
	}
	f.present.Store(true)
	if code := f.put("2"); code != http.StatusOK {
		t.Fatalf("restaurant that appeared after the snapshot: %d", code)
	}
}
