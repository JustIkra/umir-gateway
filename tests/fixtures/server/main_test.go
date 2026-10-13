package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/tests/fixtures/protocol"
)

const instanceID = "11111111-1111-4111-8111-111111111111"

func TestActualRunFIFOCompletionAndPrivateBoundary(t *testing.T) {
	var registries, statuses atomic.Int32
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Umir-Service-Key") != "auth-key" || r.URL.Path != "/internal/auth/v1/registry" {
			w.WriteHeader(401)
			return
		}
		if registries.Add(1) == 2 {
			entered <- struct{}{}
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"registryRevision":"1","complete":true,"entries":[],"tombstones":[]}`); err != nil {
			t.Error(err)
		}
	}))
	defer auth.Close()
	warehouse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Umir-Service-Key") != "warehouse-key" || r.URL.Path != "/internal/warehouse/v2/runtime" {
			w.WriteHeader(401)
			return
		}
		statuses.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"service":"warehouse","epoch":"22222222-2222-4222-8222-222222222222","ready":true,"tzdataVersion":"go1.26.9"}`); err != nil {
			t.Error(err)
		}
	}))
	defer warehouse.Close()
	cfg := protocol.Config{Origin: "http://127.0.0.1:3000", ServiceURLs: map[string]string{"auth": auth.URL, "warehouse": warehouse.URL, "serving": warehouse.URL, "feedback": warehouse.URL}}
	clock, err := protocol.NewClock(instanceID, instanceID, "2026-10-13T09:00:00+03:00", "1")
	if err != nil {
		t.Fatal(err)
	}
	ticks := protocol.NewTicks(clock)
	parts, err := assemble(cfg, map[string]string{"gateway-auth": "auth-key", "auth-gateway": "runtime-key", "gateway-warehouse": "warehouse-key", "gateway-serving": "serving-key", "gateway-feedback": "feedback-key"}, clock, ticks, instanceID, "go1.26.9-embedded")
	if err != nil {
		t.Fatal(err)
	}
	defer parts.transport.CloseIdleConnections()
	defer parts.streams.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); parts.runner.Run(ctx) }()
	defer func() { cancel(); <-done }()
	bound, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if !ticks.Baseline(bound) || registries.Load() != 1 || statuses.Load() != 1 {
		t.Fatalf("startup baseline did not finish both actual HTTP mechanisms: %d/%d", registries.Load(), statuses.Load())
	}
	complete := make(chan string, 1)
	go func() {
		_, code := ticks.Tick(bound, instanceID, "1", "33333333-3333-4333-8333-333333333333")
		complete <- code
	}()
	select {
	case <-entered:
	case <-bound.Done():
		t.Fatal("actual Run never received injected tick")
	}
	select {
	case <-complete:
		t.Fatal("ingress/transport callback was mistaken for completion")
	default:
	}
	close(gate)
	select {
	case code := <-complete:
		if code != "" {
			t.Fatal(code)
		}
	case <-bound.Done():
		t.Fatal("completion absent")
	}
	if statuses.Load() != 2 {
		t.Fatal("completion preceded the full tick body")
	}
	if _, code := ticks.Tick(bound, instanceID, "1", "33333333-3333-4333-8333-333333333333"); code != "FaultConflict" {
		t.Fatal("tick ID reused", code)
	}
	if _, code := ticks.Tick(bound, instanceID, "2", "44444444-4444-4444-8444-444444444444"); code != "ClockConflict" {
		t.Fatal("stale generation admitted", code)
	}
	for _, handler := range []http.Handler{parts.public, parts.private} {
		r := httptest.NewRequest("POST", "/owner-profile/v1", strings.NewReader(`{}`))
		r.Header.Set("X-Umir-Service-Key", "runtime-key")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatalf("fixture route on business listener: %d", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/internal/gateway/v2/runtime", nil)
	r.Header.Set("X-Umir-Service-Key", "runtime-key")
	w := httptest.NewRecorder()
	parts.private.ServeHTTP(w, r)
	var measured struct {
		TZ string `json:"tzdataVersion"`
	}
	if json.Unmarshal(w.Body.Bytes(), &measured) != nil || measured.TZ != "go1.26.9-embedded" {
		t.Fatalf("packaged version mismatch: %s", w.Body.String())
	}
	if !protocol.RuntimeReady(w.Body.Bytes(), instanceID) {
		t.Fatalf("real owner runtime not ready: %d", w.Code)
	}
}
func TestActualRunFailureStillCompletesWithoutReadiness(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer peer.Close()
	clock, err := protocol.NewClock(instanceID, instanceID, "2026-10-13T09:00:00+03:00", "1")
	if err != nil {
		t.Fatal(err)
	}
	ticks := protocol.NewTicks(clock)
	cfg := protocol.Config{Origin: "http://127.0.0.1:3000", ServiceURLs: map[string]string{"auth": peer.URL, "warehouse": peer.URL, "serving": peer.URL, "feedback": peer.URL}}
	parts, err := assemble(cfg, map[string]string{"gateway-auth": "auth-key", "auth-gateway": "runtime-key", "gateway-warehouse": "warehouse-key", "gateway-serving": "serving-key", "gateway-feedback": "feedback-key"}, clock, ticks, instanceID, "go1.26.9-embedded")
	if err != nil {
		t.Fatal(err)
	}
	defer parts.transport.CloseIdleConnections()
	defer parts.streams.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); parts.runner.Run(ctx) }()
	defer func() { cancel(); <-done }()
	if !ticks.Baseline(ctx) {
		t.Fatal("failed iteration did not emit baseline")
	}
	if _, code := ticks.Tick(ctx, instanceID, "1", "33333333-3333-4333-8333-333333333333"); code != "" {
		t.Fatal("failed registry iteration completion missing", code)
	}
	r := httptest.NewRequest("GET", "/internal/gateway/v2/runtime", nil)
	r.Header.Set("X-Umir-Service-Key", "runtime-key")
	w := httptest.NewRecorder()
	parts.private.ServeHTTP(w, r)
	if protocol.RuntimeReady(w.Body.Bytes(), instanceID) {
		t.Fatal("scheduler completion manufactured business readiness")
	}
}
func TestUnixControlSocketDACAndAuthentication(t *testing.T) {
	root, err := os.MkdirTemp("/private/tmp", "gi-uds-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Chown(root, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "control.sock")
	listener, err := unixListener(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	stat, err := os.Lstat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("socket DAC not private", err)
	}
	if other, err := unixListener(path); err == nil {
		if err := other.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("existing socket replaced")
	}
	clock, err := protocol.NewClock(instanceID, instanceID, "2026-10-13T09:00:00+03:00", "1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := protocol.NewHandler(protocol.HandlerOptions{Project: "umir-backend-0123456789abcdef01234567", Credential: strings.Repeat("a", 64), Clock: clock, Ticks: protocol.NewTicks(clock), BinarySHA256: strings.Repeat("0", 64), ConfigSHA256: strings.Repeat("1", 64), Ready: func(context.Context) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	defer func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		<-done
	}()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	body := `{"version":1,"project":"umir-backend-0123456789abcdef01234567","requestID":"` + instanceID + `","operation":"clock.read","data":{}}`
	for _, token := range []string{"", strings.Repeat("a", 64)} {
		r, err := http.NewRequest("POST", "http://fixture"+protocol.ControlPath, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal(readErr, closeErr)
		}
		want := 401
		if token != "" {
			want = 200
		}
		if response.StatusCode != want || !json.Valid(data) {
			t.Fatal("Unix control auth result", response.StatusCode)
		}
	}
}
