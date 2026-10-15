package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistrySnapshotIsUnavailableBeforeAReadAndAfterExpiry(t *testing.T) {
	now := time.Date(2026, 10, 14, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 3*60*60))
	var failed atomic.Bool
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if failed.Load() {
			w.WriteHeader(503)
			return
		}
		if _, err := w.Write([]byte(`{"registryRevision":"1","complete":true,"entries":[],"tombstones":[]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer peer.Close()
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "synthetic", Timeout: time.Second, Transport: http.DefaultTransport, Now: func() time.Time { return now }, MaxAge: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := client.RegistrySnapshot(); ok {
		t.Fatal("unobserved registry considered current")
	}
	if _, err := client.Registry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snapshot, ok := client.RegistrySnapshot(); !ok || !snapshot.Complete {
		t.Fatal("validated registry unavailable")
	}
	now = now.Add(-time.Second)
	if _, ok := client.RegistrySnapshot(); ok {
		t.Fatal("registry from the clock's future considered current")
	}
	now = now.Add(time.Second)
	now = now.Add(5 * time.Second)
	if _, ok := client.RegistrySnapshot(); ok {
		t.Fatal("expired registry considered current")
	}
	if _, err := client.Registry(context.Background()); err != nil {
		t.Fatal(err)
	}
	failed.Store(true)
	if _, err := client.Registry(context.Background()); err == nil {
		t.Fatal("failed registry read succeeded")
	}
	if snapshot, ok := client.RegistrySnapshot(); !ok || !snapshot.Complete {
		t.Fatal("failed registry read erased the last complete snapshot")
	}
	now = now.Add(5 * time.Second)
	if _, ok := client.RegistrySnapshot(); ok {
		t.Fatal("snapshot outlived its maximum age after failed reads")
	}
}

func TestRegistrySnapshotDoesNotRetainCallerOwnedSlices(t *testing.T) {
	const body = `{"registryRevision":"1","complete":true,"entries":[{"restaurant":{"restaurantID":"11111111-1111-4111-8111-111111111111","orgID":"22222222-2222-4222-8222-222222222222","name":"Synthetic","lifecycle":"registering","lifecycleVersion":"1"},"settings":{"timeZone":"Europe/Moscow","settingsVersion":"1"},"services":[{"restaurantID":"11111111-1111-4111-8111-111111111111","service":"gateway","epoch":"33333333-3333-4333-8333-333333333333","state":"pending","lifecycleVersion":"1"}]}],"tombstones":[{"restaurantID":"44444444-4444-4444-8444-444444444444","orgID":"22222222-2222-4222-8222-222222222222","lifecycleVersion":"2"}]}`
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	defer peer.Close()
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "synthetic", Timeout: time.Second, Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Registry(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result.Entries[0].Restaurant.RestaurantID = "44444444-4444-4444-8444-444444444444"
	result.Entries[0].Services[0].State = "ready"
	result.Tombstones[0].LifecycleVersion = "9"
	first, ok := client.RegistrySnapshot()
	if !ok || first.Entries[0].Restaurant.RestaurantID != "11111111-1111-4111-8111-111111111111" || first.Entries[0].Services[0].State != "pending" || first.Tombstones[0].LifecycleVersion != "2" {
		t.Fatal("registry result mutated the retained snapshot")
	}
	first.Entries[0].Services[0].State = "ready"
	first.Tombstones[0].LifecycleVersion = "9"
	second, ok := client.RegistrySnapshot()
	if !ok || second.Entries[0].Services[0].State != "pending" || second.Tombstones[0].LifecycleVersion != "2" {
		t.Fatal("snapshot caller mutated the cache")
	}
}

func TestLateRegistrySuccessDoesNotReplaceANewerSuccess(t *testing.T) {
	const older, newer = "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"
	var requests atomic.Int64
	entered := make(chan struct{})
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		tombstone := func(id string) string {
			return `{"registryRevision":"1","complete":true,"entries":[],"tombstones":[{"restaurantID":"` + id + `","orgID":"22222222-2222-4222-8222-222222222222","lifecycleVersion":"2"}]}`
		}
		if requests.Add(1) == 1 {
			close(entered)
			<-release
			if _, err := w.Write([]byte(tombstone(older))); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := w.Write([]byte(tombstone(newer))); err != nil {
			t.Error(err)
		}
	}))
	defer peer.Close()
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "synthetic", Timeout: time.Second, Transport: http.DefaultTransport})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := client.Registry(t.Context()); done <- err }()
	<-entered
	if _, err := client.Registry(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	snapshot, ok := client.RegistrySnapshot()
	if !ok || len(snapshot.Tombstones) != 1 || snapshot.Tombstones[0].RestaurantID != newer {
		t.Fatal("older completion replaced the newer observation")
	}
}

func TestW1FailedFetchKeepsSnapshotUntilMaxAgeAndSuccessRenewsIt(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	var failed atomic.Bool
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failed.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"registryRevision":"1","complete":true,"entries":[],"tombstones":[]}`)); err != nil {
			t.Error(err)
		}
	}))
	defer peer.Close()
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "synthetic", Timeout: time.Second, Transport: http.DefaultTransport, Now: func() time.Time { return now }, MaxAge: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Registry(t.Context()); err != nil {
		t.Fatal(err)
	}
	failed.Store(true)
	now = now.Add(9 * time.Second)
	if _, err := client.Registry(t.Context()); err == nil {
		t.Fatal("failed read succeeded")
	}
	if _, ok := client.RegistrySnapshot(); !ok {
		t.Fatal("a failed read inside MaxAge removed the snapshot")
	}
	now = now.Add(time.Second)
	if _, ok := client.RegistrySnapshot(); ok {
		t.Fatal("snapshot older than MaxAge since the last success is current")
	}
	failed.Store(false)
	if _, err := client.Registry(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.RegistrySnapshot(); !ok {
		t.Fatal("success did not renew the snapshot")
	}
}

func TestW1MaxAgeOption(t *testing.T) {
	target, err := url.Parse("http://auth:8080")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{URL: target, ServiceKey: "synthetic", Timeout: time.Second, Transport: http.DefaultTransport, MaxAge: -time.Second}); err == nil {
		t.Fatal("negative MaxAge accepted")
	}
	if DefaultRegistryMaxAge != 30*time.Second {
		t.Fatalf("default MaxAge %s", DefaultRegistryMaxAge)
	}
}
