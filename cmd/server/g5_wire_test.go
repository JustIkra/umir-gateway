package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
)

func g5Signed(t *testing.T, key ed25519.PrivateKey, tenant, epoch, operation, subject, caller string, permissions []string) string {
	t.Helper()
	now := time.Now().Unix()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "synthetic-key"})
	if err != nil {
		t.Fatal(err)
	}
	audience := "umir-warehouse"
	if subject == "service:auth" {
		audience = "umir-gateway"
	}
	claims, err := json.Marshal(map[string]any{"iss": "urn:umir:auth", "aud": []string{audience}, "iat": now, "nbf": now, "exp": now + 60, "jti": "55555555-5555-4555-8555-555555555555", "operation": operation, "permissions": permissions, "kind": "service", "sub": subject, "org_id": scopedOrg, "tenant_id": tenant, "runtime_epoch": epoch, "lifecycle_version": "1", "azp": caller})
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))
}

func TestG5SchedulerWireFailuresAndRecovery(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	mode := "denied"
	runs, tokens := 0, 0
	var ids []string
	progress := make(chan string, 100)
	epoch := "44444444-4444-4444-8444-444444444444"
	gatewayEpoch := epoch
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/auth/v1/registry":
			if r.Method != "GET" || r.Header.Get("X-Umir-Service-Key") != "auth-key" || r.Header.Get("Cookie") != "" {
				t.Error("registry identity")
			}
			lifecycle := "ready"
			if mode == "deleted" {
				lifecycle = "deleting"
			}
			writeScopedJSON(t, w, map[string]any{"registryRevision": "1", "complete": true, "entries": []any{map[string]any{"restaurant": map[string]any{"restaurantID": scopedRestaurant, "orgID": scopedOrg, "name": "Synthetic", "lifecycle": lifecycle, "lifecycleVersion": "1"}, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "1"}, "services": []any{map[string]any{"restaurantID": scopedRestaurant, "service": "warehouse", "epoch": epoch, "state": "ready", "lifecycleVersion": "1"}, map[string]any{"restaurantID": scopedRestaurant, "service": "serving", "epoch": epoch, "state": "ready", "lifecycleVersion": "1"}, map[string]any{"restaurantID": scopedRestaurant, "service": "gateway", "epoch": gatewayEpoch, "state": "ready", "lifecycleVersion": "1"}}}}, "tombstones": []any{}})
			if mode == "deleted" {
				progress <- mode
			}
		case "/internal/warehouse/v2/runtime":
			if r.Method != "GET" || r.Header.Get("X-Umir-Service-Key") != "warehouse-key" {
				t.Error("runtime identity")
			}
			writeScopedJSON(t, w, map[string]any{"service": "warehouse", "epoch": epoch, "ready": true, "tzdataVersion": "go1.26.9"})
		case "/internal/auth/v1/service-tokens":
			tokens++
			var input map[string]string
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if len(input) != 3 || input["operation"] != "expiry.due" || input["restaurantID"] != scopedRestaurant || input["epoch"] != epoch || r.Header.Get("X-Umir-Service-Key") != "auth-key" || r.Header.Get("X-Umir-Session") != "" {
				t.Errorf("scheduler identity %v", input)
			}
			if mode == "denied" || mode == "outage" {
				status := 403
				if mode == "outage" {
					status = 503
				}
				w.WriteHeader(status)
				writeScopedJSON(t, w, map[string]any{"code": "AuthUnavailable", "outcome": "unavailable", "message": "Synthetic", "retryable": false})
				progress <- mode
				return
			}
			permissions := []string{"expiry.due"}
			if mode == "writeoff" {
				permissions = append(permissions, "writeoff.confirm")
			}
			writeScopedJSON(t, w, map[string]any{"token": g5Signed(t, key, scopedRestaurant, epoch, "expiry.due", "service:gateway", "umir-gateway", permissions), "expiresAt": time.Unix(time.Now().Unix()+60, 0).In(time.FixedZone("MSK", 10800)).Format(time.RFC3339Nano)})
			if mode == "writeoff" {
				progress <- mode
			}
		case "/internal/warehouse/v2/r/" + scopedRestaurant + "/expiry-runs":
			runs++
			var input map[string]string
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if len(input) != 1 || input["runID"] == "" || r.Method != "POST" || r.Header.Get("X-Umir-Service-Key") != "warehouse-key" || r.Header.Get("X-Umir-Runtime-Epoch") != epoch || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || r.Header.Get("Cookie") != "" {
				t.Errorf("due request %v", input)
			}
			ids = append(ids, input["runID"])
			writeScopedJSON(t, w, map[string]any{"context": map[string]any{"orgID": scopedOrg, "tenantID": scopedRestaurant, "runtimeEpoch": epoch, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "1"}, "evaluatedAt": "2026-10-13T01:00:00+03:00", "stateVersion": "1"}, "result": map[string]any{"transitionedBatchIDs": []string{}, "finalWriteoffs": 0, "committedVersion": "1", "invalidationRequired": false}})
			progress <- "ready"
		default:
			t.Errorf("unexpected scheduler path %s", r.URL.Path)
			w.WriteHeader(503)
		}
	}))
	defer peer.Close()
	cfg := loadConfig(t, map[string]string{"AUTH_URL": peer.URL, "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "AUTH_SERVICE_KEY": "auth-key", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin})
	cfg.ExpirationRunInterval = 20 * time.Millisecond
	cfg.RegistryRefreshInterval = 20 * time.Millisecond
	app, err := newComponents(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	statusRequest := httptest.NewRequest("GET", "/internal/gateway/v2/runtime", nil)
	statusRequest.Header.Set("X-Umir-Service-Key", cfg.AuthRuntimeServiceKey)
	statusResponse := httptest.NewRecorder()
	app.privateHandler.ServeHTTP(statusResponse, statusRequest)
	var runtime struct {
		Epoch string `json:"epoch"`
	}
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gatewayEpoch = runtime.Epoch
	mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var loops sync.WaitGroup
	loops.Go(func() { app.refresher.Run(ctx) })
	loops.Go(func() { app.expiry.Run(ctx) })
	go func() { defer close(done); loops.Wait() }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("scheduler shutdown")
		}
	}()
	await := func(expected string) {
		t.Helper()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case m := <-progress:
				if m == expected {
					return
				}
			case <-timer.C:
				t.Fatalf("missed tick did not recover %s", expected)
			}
		}
	}
	for _, next := range []string{"denied", "outage", "writeoff"} {
		mu.Lock()
		mode = next
		mu.Unlock()
		await(next)
		mu.Lock()
		if runs != 0 {
			t.Errorf("%s dispatched %d", next, runs)
		}
		mu.Unlock()
	}
	mu.Lock()
	mode = "ready"
	mu.Unlock()
	await("ready")
	await("ready")
	mu.Lock()
	mode = "deleted"
	mu.Unlock()
	// The scheduler reads the refresher's snapshot, so an iteration that began before the deleted
	// registry was stored may still dispatch. The refresher is sequential: the third read starts only
	// after the second one stored its snapshot, so the snapshot is deleting once the third is served.
	await("deleted")
	await("deleted")
	await("deleted")
	// Iterations never overlap. One that started after this point sees the deleted snapshot, and
	// the first start different from the one in flight proves the in-flight iteration ended.
	runner, ok := app.expiry.(*expiration.ScopedRunner)
	if !ok {
		t.Fatal("scheduler type")
	}
	inFlight := runner.Health().LastStart
	awaitIteration := func(after time.Time) time.Time {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			h := runner.Health()
			if h.LastStart.After(after) && !h.LastSuccess.Before(h.LastStart) {
				return h.LastStart
			}
			if time.Now().After(deadline) {
				t.Fatal("scheduler iteration did not complete")
			}
			time.Sleep(time.Millisecond)
		}
	}
	first := awaitIteration(inFlight)
	mu.Lock()
	before := runs
	mu.Unlock()
	awaitIteration(first)
	mu.Lock()
	defer mu.Unlock()
	if runs != before || tokens < runs || runs < 2 {
		t.Errorf("tenant isolation/recovery tokens=%d runs=%d", tokens, runs)
	}
	unique := map[string]bool{}
	for _, id := range ids {
		if unique[id] {
			t.Error("duplicate run ID")
		}
		unique[id] = true
	}
}
