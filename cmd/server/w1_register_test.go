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
			// The answer reflects Auth at the moment the read starts, as a slow read of a big registry does.
			present, lifecycle, settings := f.present.Load(), f.state.Load(), f.settings.Load()
			if f.gate != nil {
				select {
				case <-f.gate:
				case <-r.Context().Done():
					return
				}
			}
			entries := []any{}
			if present {
				entries = append(entries, map[string]any{"restaurant": map[string]any{"restaurantID": scopedRestaurant, "orgID": scopedOrg, "name": "Synthetic", "lifecycle": lifecycle, "lifecycleVersion": "1"}, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": settings}, "services": []any{}})
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
	cfg := loadConfig(t, values)
	f.app, err = newAuthComponentsWith(cfg, log.New(io.Discard, "", 0), componentEnv{now: now, newTicker: (&w1Tickers{}).NewTicker, admission: testAdmission(t, cfg)})
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

// N parallel registrations of a restaurant Auth does not have are all refused with 410, and the
// confirming reads are shared too: the cost is a few reads, not one per caller.
func TestW1RegisterOfAbsentRestaurantCoalescesConfirmingReads(t *testing.T) {
	f := newW1Register(t, true)
	f.present.Store(false)
	const callers = 12
	codes := make([]int, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() { codes[i] = f.put("1") })
	}
	time.Sleep(200 * time.Millisecond)
	close(f.gate)
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusGone {
			t.Fatalf("caller %d: %d, want 410", i, code)
		}
	}
	if got := f.fetches.Load(); got > 3 {
		t.Fatalf("%d parallel refusals read the registry %d times, want at most 3", callers, got)
	}
}

// A refusal is never given on the strength of a read that started before the request arrived: a
// read already in progress when Auth registered the restaurant must not turn the registration into 410.
func TestW1RegisterIgnoresReadStartedBeforeTheRequest(t *testing.T) {
	f := newW1Register(t, true)
	f.present.Store(false)
	first := make(chan int, 1)
	go func() { first <- f.put("1") }()
	for f.fetches.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	// The read in flight saw no restaurant. Auth registers it, then calls Gateway.
	f.present.Store(true)
	second := make(chan int, 1)
	go func() { second <- f.put("1") }()
	time.Sleep(200 * time.Millisecond)
	close(f.gate)
	if code := <-second; code != http.StatusOK {
		t.Fatalf("registration of a restaurant that appeared after the shared read started: %d", code)
	}
	if code := <-first; code != http.StatusGone {
		t.Fatalf("the caller whose own read saw no restaurant: %d, want 410", code)
	}
}

// Accepted behaviour of the specification: a snapshot up to 2 s old answers a registration, so a
// restaurant Auth deleted a moment ago is still accepted when the request matches the snapshot. Auth
// closes it with the next call; past 2 s the registration reads again and is refused.
func TestW1RegisterSnapshotWindowAcceptsRecentDeletionOnly(t *testing.T) {
	f := newW1Register(t, false)
	if code := f.put("1"); code != http.StatusOK {
		t.Fatalf("first registration: %d", code)
	}
	f.state.Store("deleting")
	f.clock.Advance(time.Second)
	if code := f.put("1"); code != http.StatusOK {
		t.Fatalf("inside the 2 s window: %d, want 200 (snapshot answer)", code)
	}
	f.clock.Advance(2 * time.Second)
	if code := f.put("1"); code != http.StatusGone {
		t.Fatalf("past the 2 s window: %d, want 410", code)
	}
}
