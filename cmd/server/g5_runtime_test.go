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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

func TestG5PrivateRuntimeNeedsSeparateAuthIdentity(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer peer.Close()
	cfg := loadConfig(t, map[string]string{"AUTH_URL": peer.URL, "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "AUTH_SERVICE_KEY": "auth-key", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "AUTH_RUNTIME_SERVICE_KEY": "auth-runtime-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin})
	app, err := newComponents(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		request := httptest.NewRequest(method, "/internal/gateway/v2/runtime", strings.NewReader(`{}`))
		request.Header.Set("X-Umir-Service-Key", "auth-key")
		w := httptest.NewRecorder()
		app.handler.ServeHTTP(w, request)
		if w.Code != 404 {
			t.Errorf("public listener exposes private runtime %d", w.Code)
		}
	}
	if app.privateHandler == nil {
		t.Fatal("private runtime listener absent")
	}
	request := httptest.NewRequest("GET", "/internal/gateway/v2/runtime", nil)
	request.Header.Set("X-Umir-Service-Key", "auth-key")
	w := httptest.NewRecorder()
	app.privateHandler.ServeHTTP(w, request)
	if w.Code != 401 {
		t.Fatalf("Gateway credential impersonates Auth runtime caller %d", w.Code)
	}
	request.Header.Set("X-Umir-Service-Key", "auth-runtime-key")
	w = httptest.NewRecorder()
	app.privateHandler.ServeHTTP(w, request)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"service":"gateway"`) {
		t.Fatalf("runtime status %d %s", w.Code, w.Body)
	}
}

func TestG5RuntimeRegisterCloseAndTombstone(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var deleted atomic.Bool
	var settingsChanged atomic.Bool
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/auth/v1/jwks":
			writeScopedJSON(t, w, map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "synthetic-key", "x": base64.RawURLEncoding.EncodeToString(public)}}})
		case "/internal/auth/v1/registry":
			settingsVersion := "1"
			if settingsChanged.Load() {
				settingsVersion = "2"
			}
			lifecycle := "registering"
			if deleted.Load() {
				lifecycle = "deleting"
			}
			writeScopedJSON(t, w, map[string]any{"registryRevision": "1", "complete": true, "entries": []any{map[string]any{"restaurant": map[string]any{"restaurantID": scopedRestaurant, "orgID": scopedOrg, "name": "Synthetic", "lifecycle": lifecycle, "lifecycleVersion": "1"}, "settings": map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": settingsVersion}, "services": []any{}}}, "tombstones": []any{}})
		default:
			t.Errorf("unexpected control path %s", r.URL.Path)
			w.WriteHeader(503)
		}
	}))
	defer peer.Close()
	app, err := newComponents(loadConfig(t, map[string]string{"AUTH_URL": peer.URL, "SERVING_URL": peer.URL, "WAREHOUSE_URL": peer.URL, "FEEDBACK_URL": peer.URL, "AUTH_SERVICE_KEY": "auth-key", "SERVING_SERVICE_KEY": "serving-key", "WAREHOUSE_SERVICE_KEY": "warehouse-key", "FEEDBACK_SERVICE_KEY": "feedback-key", "AUTH_RUNTIME_SERVICE_KEY": "auth-runtime-key", "OPERATOR_COOKIE_MODE": "loopback-development", "OPERATOR_PUBLIC_ORIGIN": testOrigin}), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	status := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/internal/gateway/v2/runtime", nil)
	request.Header.Set("X-Umir-Service-Key", "auth-runtime-key")
	app.privateHandler.ServeHTTP(status, request)
	var runtime struct {
		Epoch string `json:"epoch"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	call := func(method, token, epoch, id, version string) int {
		t.Helper()
		body := map[string]any{"operationID": id, "expectedEpoch": epoch, "lifecycleVersion": version}
		if method == "PUT" {
			body["settings"] = map[string]any{"timeZone": "Europe/Moscow", "settingsVersion": "1"}
		}
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "/internal/gateway/v2/r/"+scopedRestaurant+"/registry", bytes.NewReader(data))
		r.Header.Set("X-Umir-Service-Key", "auth-runtime-key")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.privateHandler.ServeHTTP(w, r)
		schema := "Error"
		if w.Code == 200 {
			schema = "RuntimeReadiness"
		}
		if err := httpapi.ValidateScopeWire(schema, w.Body.Bytes()); err != nil {
			t.Fatalf("invalid frozen runtime response %d: %v", w.Code, err)
		}
		return w.Code
	}
	token := g5Signed(t, key, scopedRestaurant, runtime.Epoch, "runtime.register", "service:auth", "umir-auth", []string{"runtime.register"})
	id := "55555555-5555-4555-8555-555555555555"
	if code := call("PUT", token, runtime.Epoch, id, "1"); code != 200 {
		t.Fatalf("register %d", code)
	}
	if code := call("PUT", token, runtime.Epoch, id, "1"); code != 200 {
		t.Fatalf("exact register %d", code)
	}
	if code := call("PUT", token, "44444444-4444-4444-8444-444444444444", id, "1"); code != 409 {
		t.Fatalf("old epoch %d", code)
	}
	if code := call("PUT", g5Signed(t, key, scopedRestaurant, runtime.Epoch, "expiry.due", "service:gateway", "umir-gateway", []string{"expiry.due"}), runtime.Epoch, id, "1"); code != 403 {
		t.Fatalf("scheduler becomes control authority %d", code)
	}
	settingsChanged.Store(true)
	if code := call("PUT", token, runtime.Epoch, id, "1"); code != 409 {
		t.Fatalf("stale registration settings accepted %d", code)
	}
	settingsChanged.Store(false)
	deleted.Store(true)
	if code := call("PUT", token, runtime.Epoch, id, "1"); code != 410 {
		t.Fatalf("deleted registry resurrected by retained signed registration %d", code)
	}
	closeToken := g5Signed(t, key, scopedRestaurant, runtime.Epoch, "runtime.close", "service:auth", "umir-auth", []string{"runtime.close"})
	if code := call("DELETE", closeToken, runtime.Epoch, id, "1"); code != 200 {
		t.Fatalf("close %d", code)
	}
	if code := call("DELETE", closeToken, runtime.Epoch, id, "1"); code != 200 {
		t.Fatalf("exact close %d", code)
	}
	if code := call("PUT", token, runtime.Epoch, id, "1"); code != 410 {
		t.Fatalf("closed runtime resurrected %d", code)
	}
}
