package authclient

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// refresherTicks hands out one unbuffered tick channel: a send returns only once the refresher loop is
// back in its select, so two sends prove the first refresh finished.
type refresherTicks struct {
	ticks   chan time.Time
	stopped atomic.Bool
	period  atomic.Int64
}

func newRefresherTicks() *refresherTicks { return &refresherTicks{ticks: make(chan time.Time)} }
func (r *refresherTicks) NewTicker(d time.Duration) (<-chan time.Time, func()) {
	r.period.Store(int64(d))
	return r.ticks, func() { r.stopped.Store(true) }
}
func (r *refresherTicks) tick(t *testing.T) {
	t.Helper()
	select {
	case r.ticks <- time.Time{}:
	case <-time.After(5 * time.Second):
		t.Fatal("refresher did not accept a tick")
	}
}

type registryPeer struct {
	*httptest.Server
	requests atomic.Int64
	failed   atomic.Bool
	block    chan struct{}
}

func newRegistryPeer(t *testing.T) *registryPeer {
	t.Helper()
	p := &registryPeer{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.requests.Add(1)
		if p.block != nil {
			select {
			case <-p.block:
			case <-r.Context().Done():
				return
			}
		}
		if p.failed.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"registryRevision":"1","complete":true,"entries":[],"tombstones":[]}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func refresherClient(t *testing.T, peer *registryPeer, now func() time.Time) *Client {
	t.Helper()
	target, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "synthetic", Timeout: 5 * time.Second, Transport: http.DefaultTransport, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func runRefresher(t *testing.T, r *RegistryRefresher) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	var once atomic.Bool
	stop = func() {
		if once.Swap(true) {
			return
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("refresher did not stop after cancellation")
		}
	}
	t.Cleanup(stop)
	return stop
}

func TestW1RefresherFetchesAtStartAndOnEveryTick(t *testing.T) {
	peer := newRegistryPeer(t)
	ticks := newRefresherTicks()
	refresher, err := NewRegistryRefresher(RefresherOptions{Client: refresherClient(t, peer, nil), Interval: 2 * time.Second, NewTicker: ticks.NewTicker, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	runRefresher(t, refresher)
	ticks.tick(t)
	ticks.tick(t)
	if got := peer.requests.Load(); got < 2 {
		t.Fatalf("expected the startup fetch and the first tick, got %d requests", got)
	}
	if time.Duration(ticks.period.Load()) != 2*time.Second {
		t.Fatalf("refresh interval %s", time.Duration(ticks.period.Load()))
	}
	if _, ok := refresher.client.RegistrySnapshot(); !ok {
		t.Fatal("successful refreshes left no snapshot")
	}
}

func TestW1RefresherFailureKeepsSnapshotAndRecovers(t *testing.T) {
	peer := newRegistryPeer(t)
	ticks := newRefresherTicks()
	client := refresherClient(t, peer, nil)
	refresher, err := NewRegistryRefresher(RefresherOptions{Client: client, Interval: time.Second, NewTicker: ticks.NewTicker, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	runRefresher(t, refresher)
	ticks.tick(t)
	ticks.tick(t)
	peer.failed.Store(true)
	ticks.tick(t)
	ticks.tick(t)
	if _, ok := client.RegistrySnapshot(); !ok {
		t.Fatal("failed refresh removed the last snapshot")
	}
	if registry, err := refresher.Registry(t.Context()); err != nil || !registry.Complete {
		t.Fatalf("scheduler source lost the snapshot: %v", err)
	}
	peer.failed.Store(false)
	before := peer.requests.Load()
	ticks.tick(t)
	ticks.tick(t)
	if peer.requests.Load() <= before {
		t.Fatal("refresher stopped fetching after a failure")
	}
}

func TestW1RefresherSourceFailsWithoutSnapshot(t *testing.T) {
	peer := newRegistryPeer(t)
	peer.failed.Store(true)
	refresher, err := NewRegistryRefresher(RefresherOptions{Client: refresherClient(t, peer, nil), Interval: time.Second, NewTicker: newRefresherTicks().NewTicker, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refresher.Registry(t.Context()); err == nil {
		t.Fatal("scheduler registry source answered without any snapshot")
	}
	if got := peer.requests.Load(); got != 0 {
		t.Fatalf("the source made its own fetch: %d", got)
	}
}

func TestW1RefresherStopsOnCancelEvenDuringAFetch(t *testing.T) {
	peer := newRegistryPeer(t)
	peer.block = make(chan struct{})
	ticks := newRefresherTicks()
	refresher, err := NewRegistryRefresher(RefresherOptions{Client: refresherClient(t, peer, nil), Interval: time.Second, NewTicker: ticks.NewTicker, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	stop := runRefresher(t, refresher)
	deadline := time.After(5 * time.Second)
	for peer.requests.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("startup fetch never began")
		case <-time.After(time.Millisecond):
		}
	}
	stop()
	if !ticks.stopped.Load() {
		t.Fatal("ticker was not stopped")
	}
}

func TestW1RefresherRequiresItsDependencies(t *testing.T) {
	peer := newRegistryPeer(t)
	client := refresherClient(t, peer, nil)
	ticks := newRefresherTicks()
	logger := log.New(io.Discard, "", 0)
	for name, opts := range map[string]RefresherOptions{
		"client":   {Interval: time.Second, NewTicker: ticks.NewTicker, Logger: logger},
		"interval": {Client: client, NewTicker: ticks.NewTicker, Logger: logger},
		"ticker":   {Client: client, Interval: time.Second, Logger: logger},
		"logger":   {Client: client, Interval: time.Second, NewTicker: ticks.NewTicker},
	} {
		if _, err := NewRegistryRefresher(opts); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
}
