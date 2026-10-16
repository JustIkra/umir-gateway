package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
)

const (
	w1AuthKey    = "w1-auth-service-key"
	w1RuntimeKey = "w1-auth-runtime-key"
)

// w1Clock is the injected process clock.
type w1Clock struct{ offset atomic.Int64 }

var w1Start = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func (c *w1Clock) Now() time.Time { return w1Start.Add(time.Duration(c.offset.Load())) }
func (c *w1Clock) Advance(d time.Duration) {
	c.offset.Add(int64(d))
}

// w1Tickers hands out one unbuffered channel per period: a send completes only when the owning loop
// is waiting again, so a second send proves that the first tick was fully handled.
type w1Tickers struct {
	mu       sync.Mutex
	channels map[time.Duration]chan time.Time
}

func (k *w1Tickers) NewTicker(d time.Duration) (<-chan time.Time, func()) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.channels == nil {
		k.channels = map[time.Duration]chan time.Time{}
	}
	ch := make(chan time.Time)
	k.channels[d] = ch
	return ch, func() {}
}

func (k *w1Tickers) tick(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		k.mu.Lock()
		ch := k.channels[d]
		k.mu.Unlock()
		if ch != nil {
			select {
			case ch <- time.Time{}:
				return
			case <-time.After(5 * time.Second):
				t.Fatalf("loop with period %s did not accept a tick", d)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no loop with period %s was started", d)
		}
		time.Sleep(time.Millisecond)
	}
}

// settle makes the loop finish the previous tick: the second send is accepted only after it.
func (k *w1Tickers) settle(t *testing.T, d time.Duration) {
	t.Helper()
	k.tick(t, d)
	k.tick(t, d)
}

type w1Harness struct {
	t         *testing.T
	app       components
	clock     *w1Clock
	tickers   *w1Tickers
	authFail  atomic.Bool
	authCalls atomic.Int64
	whCalls   atomic.Int64
	whGate    chan struct{}
	whBlock   atomic.Bool
	authURL   string
}

func newW1Harness(t *testing.T, extra map[string]string) *w1Harness {
	t.Helper()
	h := &w1Harness{t: t, clock: &w1Clock{}, tickers: &w1Tickers{}, whGate: make(chan struct{})}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/auth/v1/registry" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		h.authCalls.Add(1)
		if h.authFail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"registryRevision":"1","complete":true,"entries":[],"tombstones":[]}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(auth.Close)
	warehouse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.whCalls.Add(1)
		if h.whBlock.Load() {
			select {
			case <-h.whGate:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"service":"warehouse","epoch":"22222222-2222-4222-8222-222222222222","ready":true,"tzdataVersion":"go1.26.9"}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(warehouse.Close)
	t.Cleanup(func() {
		select {
		case <-h.whGate:
		default:
			close(h.whGate)
		}
	})
	h.authURL = auth.URL
	values := map[string]string{"AUTH_URL": auth.URL, "SERVING_URL": warehouse.URL, "WAREHOUSE_URL": warehouse.URL, "FEEDBACK_URL": warehouse.URL, "AUTH_SERVICE_KEY": w1AuthKey, "SERVING_SERVICE_KEY": "w1-serving-key", "WAREHOUSE_SERVICE_KEY": "w1-warehouse-key", "FEEDBACK_SERVICE_KEY": "w1-feedback-key", "AUTH_RUNTIME_SERVICE_KEY": w1RuntimeKey, "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin, "EXPIRATION_RUN_INTERVAL": "30s"}
	for key, value := range extra {
		values[key] = value
	}
	cfg := loadConfig(t, values)
	app, err := newAuthComponentsWith(cfg, log.New(io.Discard, "", 0), componentEnv{now: h.clock.Now, newTicker: h.tickers.NewTicker, admission: testAdmission(t, cfg)})
	if err != nil {
		t.Fatal(err)
	}
	h.app = app
	return h
}

// start runs a background loop of the process and stops it, waiting for completion, with the test.
func (h *w1Harness) start(loop interface{ Run(context.Context) }) {
	h.t.Helper()
	if loop == nil {
		h.t.Fatal("the process has no such background loop")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); loop.Run(ctx) }()
	h.t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			h.t.Error("background loop did not stop")
		}
	})
}

func (h *w1Harness) startRefresher() {
	h.t.Helper()
	if h.app.refresher == nil {
		h.t.Fatal("the process has no registry refresher")
	}
	h.start(h.app.refresher)
}

func (h *w1Harness) ready() bool {
	h.t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/internal/gateway/v2/runtime", nil)
	request.Header.Set("X-Umir-Service-Key", w1RuntimeKey)
	response := httptest.NewRecorder()
	h.app.privateHandler.ServeHTTP(response, request)
	var status struct {
		Ready bool `json:"ready"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil {
		h.t.Fatalf("runtime status %d %s", response.Code, response.Body)
	}
	return status.Ready
}

func (h *w1Harness) waitReady(want bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.ready() != want {
		if time.Now().After(deadline) {
			h.t.Fatalf("ready did not become %v", want)
		}
		time.Sleep(time.Millisecond)
	}
}

type w1Readyz struct {
	Instance     string            `json:"instance"`
	Capabilities map[string]string `json:"capabilities"`
}

func (h *w1Harness) readyz() (int, w1Readyz, string) {
	h.t.Helper()
	response := httptest.NewRecorder()
	h.app.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	var body w1Readyz
	decoder := json.NewDecoder(strings.NewReader(response.Body.String()))
	decoder.DisallowUnknownFields()
	if response.Code == http.StatusOK {
		if err := decoder.Decode(&body); err != nil {
			h.t.Fatalf("readyz body: %v: %s", err, response.Body)
		}
	}
	return response.Code, body, response.Body.String()
}

func (h *w1Harness) waitScheduler(want string) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, body, _ := h.readyz(); body.Capabilities["scheduler"] == want {
			return
		}
		if time.Now().After(deadline) {
			_, body, _ := h.readyz()
			h.t.Fatalf("scheduler capability %q, want %q", body.Capabilities["scheduler"], want)
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *w1Harness) waitWarehouseCalls(n int64) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for h.whCalls.Load() < n {
		if time.Now().After(deadline) {
			h.t.Fatalf("Warehouse received %d requests, want %d", h.whCalls.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestW1ReadyIgnoresSchedulerPace(t *testing.T) {
	h := newW1Harness(t, map[string]string{"UPSTREAM_TIMEOUT": "5s"})
	h.startRefresher()
	h.waitReady(true)
	h.whBlock.Store(true)
	h.start(h.app.expiry)
	h.waitWarehouseCalls(1)
	// The scheduler is stuck inside its first iteration and ticks only every 30 s of the injected clock.
	h.clock.Advance(10 * time.Second)
	if !h.ready() {
		t.Fatal("a slow scheduler iteration closed the business routes")
	}
	h.tickers.settle(t, 2*time.Second)
	if !h.ready() {
		t.Fatal("readiness did not hold across refreshes")
	}
}

func TestW1ReadySurvivesOneFailedRegistryFetch(t *testing.T) {
	h := newW1Harness(t, nil)
	h.startRefresher()
	h.waitReady(true)
	h.authFail.Store(true)
	before := h.authCalls.Load()
	h.clock.Advance(3 * time.Second)
	h.tickers.tick(t, 2*time.Second)
	h.tickers.tick(t, 2*time.Second)
	if h.authCalls.Load() <= before {
		t.Fatal("the failed fetch did not happen")
	}
	if !h.ready() {
		t.Fatal("one failed registry fetch made the Gateway not ready")
	}
}

func TestW1ReadyFalseAfterMaxAge(t *testing.T) {
	h := newW1Harness(t, nil)
	h.startRefresher()
	h.waitReady(true)
	h.authFail.Store(true)
	h.clock.Advance(29 * time.Second)
	h.tickers.settle(t, 2*time.Second)
	if !h.ready() {
		t.Fatal("snapshot inside MAX_AGE rejected")
	}
	h.clock.Advance(2 * time.Second)
	h.tickers.settle(t, 2*time.Second)
	if h.ready() {
		t.Fatal("snapshot older than MAX_AGE accepted")
	}
	h.authFail.Store(false)
	h.tickers.settle(t, 2*time.Second)
	if !h.ready() {
		t.Fatal("readiness did not recover without a restart")
	}
}

func TestW1SchedulerHealthShowsLag(t *testing.T) {
	h := newW1Harness(t, map[string]string{"EXPIRATION_RUN_INTERVAL": "1s", "UPSTREAM_TIMEOUT": "5s"})
	h.startRefresher()
	h.waitReady(true)
	h.start(h.app.expiry)
	h.waitScheduler("ok")
	calls := h.whCalls.Load()
	h.whBlock.Store(true)
	h.tickers.tick(t, time.Second)
	h.waitWarehouseCalls(calls + 1)
	h.clock.Advance(5 * time.Second)
	code, body, _ := h.readyz()
	if code != http.StatusOK || body.Capabilities["scheduler"] != "degraded" || body.Capabilities["http"] != "ok" {
		t.Fatalf("paused iteration: %d %+v", code, body)
	}
	if !h.ready() {
		t.Fatal("a paused iteration changed runtime readiness")
	}
	h.clock.Advance(6 * time.Second)
	code, body, _ = h.readyz()
	if code != http.StatusOK || body.Capabilities["scheduler"] != "down" || !h.ready() {
		t.Fatalf("stalled iteration: %d %+v", code, body)
	}
}

func TestW1ReadyzBodyShape(t *testing.T) {
	h := newW1Harness(t, map[string]string{"GATEWAY_INSTANCE_ID": "gateway-1"})
	code, body, raw := h.readyz()
	if code != http.StatusOK || body.Instance != "gateway-1" || len(body.Capabilities) != 2 || body.Capabilities["http"] != "ok" {
		t.Fatalf("%d %s", code, raw)
	}
	switch body.Capabilities["scheduler"] {
	case "ok", "degraded", "down":
	default:
		t.Fatalf("scheduler capability %q", body.Capabilities["scheduler"])
	}
	for _, secret := range []string{h.authURL, "127.0.0.1", w1AuthKey, w1RuntimeKey, "w1-warehouse-key", "http://"} {
		if strings.Contains(raw, secret) {
			t.Fatal("readyz exposes an address or a secret")
		}
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &generic); err != nil || len(generic) != 2 {
		t.Fatalf("body is not exactly {instance, capabilities}: %s", raw)
	}
	response := httptest.NewRecorder()
	h.app.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", response.Header())
	}
}

func TestW1ReadyzRoutes(t *testing.T) {
	h := newW1Harness(t, nil)
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/readyz", 200},
		{http.MethodHead, "/readyz", 200},
		{http.MethodPost, "/readyz", 405},
		{http.MethodGet, "/readyz/scheduler", 404},
		{http.MethodGet, "/readyz/", 404},
		{http.MethodGet, "/healthz", 200},
	} {
		response := httptest.NewRecorder()
		h.app.handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, response.Code, tc.want)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	h.app.privateHandler.ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatal("private listener serves /readyz")
	}
}

func TestW1InstanceIDDefaultsToARandomUUID(t *testing.T) {
	first := newW1Harness(t, nil)
	second := newW1Harness(t, nil)
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	_, a, _ := first.readyz()
	_, b, _ := second.readyz()
	if !uuid.MatchString(a.Instance) || !uuid.MatchString(b.Instance) || a.Instance == b.Instance {
		t.Fatalf("default instance IDs %q %q", a.Instance, b.Instance)
	}
}

func TestW1SchedulerPoolSettingsReachTheRunner(t *testing.T) {
	runner := func(h *w1Harness) *expiration.ScopedRunner {
		r, ok := h.app.expiry.(*expiration.ScopedRunner)
		if !ok {
			t.Fatalf("scheduler is %T", h.app.expiry)
		}
		return r
	}
	defaults := runner(newW1Harness(t, nil))
	if defaults.Concurrency() != 8 || defaults.IterationBudget() != 10*time.Second {
		t.Fatalf("defaults: %d %s", defaults.Concurrency(), defaults.IterationBudget())
	}
	custom := runner(newW1Harness(t, map[string]string{"GATEWAY_EXPIRATION_CONCURRENCY": "3", "GATEWAY_EXPIRATION_ITERATION_BUDGET": "4s"}))
	if custom.Concurrency() != 3 || custom.IterationBudget() != 4*time.Second {
		t.Fatalf("configured: %d %s", custom.Concurrency(), custom.IterationBudget())
	}
}
