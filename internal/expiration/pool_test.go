package expiration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// poolPeer is a scheduler peer for many restaurants whose Due takes a set time.
type poolPeer struct {
	registry Registry
	delay    time.Duration
	// onDue runs inside every Due call, after the delay; tests use it to move an injected clock.
	onDue func()
	// failDue makes Due fail with a lost reply; failRegistry makes the registry unavailable.
	failDue, failRegistry atomic.Bool

	mu              sync.Mutex
	appended        map[string]int
	active, maximum int
	order           []string
	tokens          int
}

func poolRegistry(n int) Registry {
	registry := Registry{Complete: true}
	for i := range n {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		registry.Entries = append(registry.Entries, RegistryEntry{
			Restaurant: Restaurant{RestaurantID: id, OrgID: "22222222-2222-4222-8222-222222222222", Lifecycle: "ready", LifecycleVersion: "1"},
			Services:   []Readiness{{RestaurantID: id, Service: "warehouse", Epoch: warehouseEpoch, State: "ready", LifecycleVersion: "1"}},
		})
	}
	return registry
}

func (p *poolPeer) Registry(context.Context) (Registry, error) {
	if p.failRegistry.Load() {
		return Registry{}, errors.New("registry unavailable")
	}
	return p.registry, nil
}
func (p *poolPeer) ServiceToken(context.Context, ServiceRequest) (Credential, error) {
	p.mu.Lock()
	p.tokens++
	p.mu.Unlock()
	return Credential{Token: "synthetic", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (p *poolPeer) Status(context.Context) (RuntimeStatus, error) {
	return RuntimeStatus{Service: "warehouse", Epoch: warehouseEpoch, Ready: true}, nil
}
func (p *poolPeer) Due(_ context.Context, r DueRequest) (DueResult, error) {
	p.mu.Lock()
	p.active++
	p.maximum = max(p.maximum, p.active)
	p.order = append(p.order, r.RestaurantID)
	p.mu.Unlock()
	time.Sleep(p.delay)
	if p.onDue != nil {
		p.onDue()
	}
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	if p.failDue.Load() {
		return DueResult{}, errors.New("reply lost")
	}
	return DueResult{Epoch: warehouseEpoch, Version: "1"}, nil
}
func (p *poolPeer) Append(id string, _ []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.appended == nil {
		p.appended = map[string]int{}
	}
	p.appended[id]++
	return nil
}
func (p *poolPeer) CloseScope(string) error                     { return nil }
func (p *poolPeer) ObserveRuntime(string, string, string) error { return nil }

func newPoolRunner(t *testing.T, p *poolPeer, now func() time.Time, concurrency int, budget time.Duration) *ScopedRunner {
	t.Helper()
	r, err := NewScoped(ScopedOptions{Auth: p, Warehouse: p, Changes: p, Interval: time.Second, Timeout: time.Second, Now: now, NewRunID: func() (string, error) { return "55555555-5555-4555-8555-555555555555", nil }, NewTicker: func(time.Duration) (<-chan time.Time, func()) { return make(chan time.Time), func() {} }, Logger: log.New(io.Discard, "", 0), Concurrency: concurrency, IterationBudget: budget})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestW1SchedulerRunsDueWithinBudgetAndConcurrencyBound(t *testing.T) {
	p := &poolPeer{registry: poolRegistry(200), delay: 10 * time.Millisecond}
	r := newPoolRunner(t, p, time.Now, 8, 10*time.Second)
	started := time.Now()
	if !r.tick(context.Background()) {
		t.Fatal("iteration failed")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("200 restaurants of 10 ms took %s with 8 workers", elapsed)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.order) != 200 {
		t.Fatalf("%d restaurants dispatched, want 200", len(p.order))
	}
	if p.maximum > 8 {
		t.Fatalf("%d dispatches ran at once, the bound is 8", p.maximum)
	}
	if p.maximum < 2 {
		t.Fatalf("the pool never ran dispatches in parallel (peak %d)", p.maximum)
	}
}

func TestW1SchedulerRotatesStartWhenBudgetExhausted(t *testing.T) {
	var offset atomic.Int64
	base := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { return base.Add(time.Duration(offset.Load())) }
	p := &poolPeer{registry: poolRegistry(10), onDue: func() { offset.Add(int64(10 * time.Millisecond)) }}
	// One worker, 10 ms per restaurant on the injected clock, a 25 ms budget: three start per iteration.
	r := newPoolRunner(t, p, now, 1, 25*time.Millisecond)
	ids := make([]string, len(p.registry.Entries))
	for i, e := range p.registry.Entries {
		ids[i] = e.Restaurant.RestaurantID
	}
	if r.tick(context.Background()) {
		t.Fatal("an iteration cut by its budget counted as complete")
	}
	p.mu.Lock()
	first := append([]string(nil), p.order...)
	p.order = nil
	p.mu.Unlock()
	if len(first) != 3 || first[0] != ids[0] || first[2] != ids[2] {
		t.Fatalf("first iteration started %v", first)
	}
	r.tick(context.Background())
	p.mu.Lock()
	second := append([]string(nil), p.order...)
	p.order = nil
	p.mu.Unlock()
	if len(second) != 3 || second[0] != ids[3] || second[2] != ids[5] {
		t.Fatalf("the tail was starved: second iteration started %v", second)
	}
	// The remaining iterations wrap around and reach everyone.
	seen := map[string]bool{}
	for _, id := range append(first, second...) {
		seen[id] = true
	}
	for range 3 {
		r.tick(context.Background())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range p.order {
		seen[id] = true
	}
	if len(seen) != 10 {
		t.Fatalf("%d of 10 restaurants served after five iterations", len(seen))
	}
}

func TestW1SchedulerCompletedIterationDoesNotShiftStart(t *testing.T) {
	p := &poolPeer{registry: poolRegistry(5)}
	r := newPoolRunner(t, p, time.Now, 2, 10*time.Second)
	if !r.tick(context.Background()) {
		t.Fatal("iteration failed")
	}
	p.mu.Lock()
	p.order = nil
	p.mu.Unlock()
	r.tick(context.Background())
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.order) != 5 {
		t.Fatalf("%d dispatched in the second iteration, want 5", len(p.order))
	}
}

func TestW1SchedulerPoolFinishesBeforeIterationReturns(t *testing.T) {
	p := &poolPeer{registry: poolRegistry(20), delay: 5 * time.Millisecond}
	r := newPoolRunner(t, p, time.Now, 4, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(12 * time.Millisecond); cancel() }()
	r.tick(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active != 0 {
		t.Fatalf("%d dispatches still running after the iteration returned", p.active)
	}
}

func TestW1SchedulerConcurrencyOptionBounds(t *testing.T) {
	p := &poolPeer{registry: poolRegistry(1)}
	for _, tc := range []struct {
		name        string
		concurrency int
		budget      time.Duration
		ok          bool
	}{
		{"defaults", 0, 0, true},
		{"negative concurrency", -1, time.Second, false},
		{"negative budget", 1, -time.Second, false},
	} {
		_, err := NewScoped(ScopedOptions{Auth: p, Warehouse: p, Changes: p, Interval: time.Second, Timeout: time.Second, Now: time.Now, NewRunID: func() (string, error) { return "id", nil }, NewTicker: func(time.Duration) (<-chan time.Time, func()) { return nil, func() {} }, Logger: log.New(io.Discard, "", 0), Concurrency: tc.concurrency, IterationBudget: tc.budget})
		if (err == nil) != tc.ok {
			t.Errorf("%s: error %v", tc.name, err)
		}
	}
}

func TestW1SchedulerFinishesTwelveHundredRestaurantsInSeconds(t *testing.T) {
	p := &poolPeer{registry: poolRegistry(1200), delay: 5 * time.Millisecond}
	r := newPoolRunner(t, p, time.Now, 8, 10*time.Second)
	started := time.Now()
	if !r.tick(context.Background()) {
		t.Fatal("iteration cut or failed")
	}
	if elapsed := time.Since(started); elapsed >= 3*time.Second {
		t.Fatalf("1200 restaurants of 5 ms took %s", elapsed)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.order) != 1200 || p.maximum > 8 {
		t.Fatalf("%d dispatched, peak %d", len(p.order), p.maximum)
	}
}

func TestW1SchedulerOptionDefaults(t *testing.T) {
	r := newPoolRunner(t, &poolPeer{}, time.Now, 0, 0)
	if r.Concurrency() != DefaultConcurrency || r.IterationBudget() != DefaultIterationBudget || DefaultConcurrency != 8 || DefaultIterationBudget != 10*time.Second {
		t.Fatalf("defaults: %d %s", r.Concurrency(), r.IterationBudget())
	}
}

// Parallel dispatches keep each restaurant's own state: a lost reply invalidates it once, then a
// success invalidates it once more (recovery), and nothing is mixed up between restaurants.
func TestW1SchedulerParallelDispatchKeepsPerRestaurantState(t *testing.T) {
	p := &poolPeer{registry: poolRegistry(100), delay: time.Millisecond}
	r := newPoolRunner(t, p, time.Now, 8, 10*time.Second)
	p.failDue.Store(true)
	r.tick(context.Background())
	r.tick(context.Background())
	p.failDue.Store(false)
	r.tick(context.Background())
	r.tick(context.Background())
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.appended) != 100 {
		t.Fatalf("%d restaurants invalidated, want 100", len(p.appended))
	}
	for id, n := range p.appended {
		if n != 2 {
			t.Fatalf("restaurant %s invalidated %d times, want 2 (unknown once, recovery once)", id, n)
		}
	}
}

// An iteration cut by its budget that still served restaurants is progress, not a failure: it keeps
// the scheduler alive (never down) but is reported as degraded while the cuts continue.
func TestW1TruncatedIterationsDegradeButNeverDown(t *testing.T) {
	var offset atomic.Int64
	base := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { return base.Add(time.Duration(offset.Load())) }
	p := &poolPeer{registry: poolRegistry(10), onDue: func() { offset.Add(int64(10 * time.Millisecond)) }}
	r := newPoolRunner(t, p, now, 1, 25*time.Millisecond)
	for i := range 30 {
		r.runIteration(context.Background())
		h := r.Health()
		if h.ConsecutiveFailures != 0 || !h.Truncated || h.LastSuccess.IsZero() {
			t.Fatalf("truncated iteration %d: %+v", i, h)
		}
		if state := h.State(now(), time.Second); state != StateDegraded {
			t.Fatalf("truncated iteration %d: state %s, want degraded", i, state)
		}
		offset.Add(int64(time.Second)) // well past ten intervals over the loop
	}
	// A complete iteration clears the mark.
	r.opts.IterationBudget = time.Hour
	r.runIteration(context.Background())
	if h := r.Health(); h.Truncated || h.State(now(), time.Second) != StateOK {
		t.Fatalf("complete iteration: %+v", h)
	}
}

// Iterations that reach no restaurant stay failures under the old rules, truncated before or not.
func TestW1FailedIterationsAfterTruncationFollowTheOldRules(t *testing.T) {
	var offset atomic.Int64
	base := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { return base.Add(time.Duration(offset.Load())) }
	p := &poolPeer{registry: poolRegistry(10), onDue: func() { offset.Add(int64(10 * time.Millisecond)) }}
	r := newPoolRunner(t, p, now, 1, 25*time.Millisecond)
	r.runIteration(context.Background())
	if !r.Health().Truncated {
		t.Fatal("setup: the first iteration was not cut")
	}
	p.failRegistry.Store(true)
	r.runIteration(context.Background())
	h := r.Health()
	if h.ConsecutiveFailures != 1 || h.Truncated {
		t.Fatalf("failed iteration: %+v", h)
	}
	for range 4 {
		offset.Add(int64(3 * time.Second))
		r.runIteration(context.Background())
	}
	if state := r.Health().State(now(), time.Second); state != StateDown {
		t.Fatalf("a long run of failed iterations is %s, want down", state)
	}
}
