package expiration

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"testing"
	"time"
)

const tenantA = "33333333-3333-4333-8333-333333333333"
const warehouseEpoch = "44444444-4444-4444-8444-444444444444"

func readyRegistry() Registry {
	var r Registry
	r.Complete = true
	r.Entries = []RegistryEntry{{Restaurant: Restaurant{RestaurantID: tenantA, OrgID: "22222222-2222-4222-8222-222222222222", Lifecycle: "ready", LifecycleVersion: "1"}, Services: []Readiness{{RestaurantID: tenantA, Service: "warehouse", Epoch: warehouseEpoch, State: "ready", LifecycleVersion: "1"}}}}
	return r
}

type schedulerPeer struct {
	mu              sync.Mutex
	registry        Registry
	authErr, dueErr error
	result          DueResult
	requests        []ServiceRequest
	due             []DueRequest
	status          RuntimeStatus
	changes, closed []string
	block           <-chan struct{}
	started         chan struct{}
	active, maximum int
}

func (p *schedulerPeer) Registry(context.Context) (Registry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.registry, nil
}
func (p *schedulerPeer) ServiceToken(_ context.Context, r ServiceRequest) (Credential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, r)
	return Credential{Token: "synthetic", ExpiresAt: time.Now().Add(time.Minute)}, p.authErr
}
func (p *schedulerPeer) Status(context.Context) (RuntimeStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status, nil
}
func (p *schedulerPeer) Due(ctx context.Context, r DueRequest) (DueResult, error) {
	p.mu.Lock()
	p.due = append(p.due, r)
	p.active++
	p.maximum = max(p.maximum, p.active)
	block, started, result, err := p.block, p.started, p.result, p.dueErr
	p.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if block != nil {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-block:
		}
	}
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	return result, err
}
func (p *schedulerPeer) Append(s string, _ []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.changes = append(p.changes, s)
	return nil
}
func (p *schedulerPeer) CloseScope(s string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = append(p.closed, s)
	return nil
}
func (p *schedulerPeer) ObserveRuntime(string, string, string) error { return nil }
func newSchedulerTest(t *testing.T, p *schedulerPeer) *ScopedRunner {
	t.Helper()
	r, err := NewScoped(ScopedOptions{Auth: p, Warehouse: p, Changes: p, Interval: time.Second, Timeout: time.Second, Now: time.Now, NewRunID: func() (string, error) { return "55555555-5555-4555-8555-555555555555", nil }, NewTicker: func(time.Duration) (<-chan time.Time, func()) { return make(chan time.Time), func() {} }, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func schedulerFixture() *schedulerPeer {
	return &schedulerPeer{registry: readyRegistry(), status: RuntimeStatus{Service: "warehouse", Epoch: warehouseEpoch, Ready: true}, result: DueResult{Epoch: warehouseEpoch, Version: "1"}}
}
func TestG5CredentialFailureNeverDispatches(t *testing.T) {
	for _, reason := range []string{"rejected", "Auth outage"} {
		t.Run(reason, func(t *testing.T) {
			p := schedulerFixture()
			p.authErr = errors.New(reason)
			r := newSchedulerTest(t, p)
			r.tick(context.Background())
			if len(p.due) != 0 || len(p.changes) != 0 {
				t.Fatal("credential failure dispatched or invalidated")
			}
			if len(p.requests) != 1 || p.requests[0].Operation != "expiry.due" || p.requests[0].Epoch != warehouseEpoch || p.requests[0].RestaurantID != tenantA {
				t.Fatalf("scope %v", p.requests)
			}
		})
	}
}
func TestG5ReadinessAndDeletedTenant(t *testing.T) {
	for _, mode := range []string{"partial registry", "not ready", "stale epoch", "deleted"} {
		t.Run(mode, func(t *testing.T) {
			p := schedulerFixture()
			switch mode {
			case "partial registry":
				p.registry.Complete = false
			case "not ready":
				p.status.Ready = false
			case "stale epoch":
				p.status.Epoch = "66666666-6666-4666-8666-666666666666"
			case "deleted":
				p.registry.Entries[0].Restaurant.Lifecycle = "deleting"
			}
			r := newSchedulerTest(t, p)
			r.tick(context.Background())
			if len(p.requests) != 0 || len(p.due) != 0 {
				t.Fatal("unready/deleted tenant dispatched")
			}
			if mode == "deleted" && len(p.closed) != 1 {
				t.Fatal("deleted tenant journal remains open")
			}
		})
	}
}
func TestG5TicksAndUnknownRecovery(t *testing.T) {
	p := schedulerFixture()
	r := newSchedulerTest(t, p)
	r.tick(context.Background())
	r.tick(context.Background())
	if len(p.due) != 2 || len(p.changes) != 0 {
		t.Fatal("duplicate due poll invalidates unchanged stock")
	}
	p.dueErr = errors.New("reply lost")
	r.tick(context.Background())
	r.tick(context.Background())
	if len(p.changes) != 1 || p.changes[0] != tenantA {
		t.Fatal("unknown must invalidate its tenant once")
	}
	p.dueErr = nil
	p.result = DueResult{Epoch: warehouseEpoch, Version: "2", Invalidation: true}
	r.tick(context.Background())
	if len(p.changes) != 2 {
		t.Fatal("missed expiry did not recover")
	}
}
func TestG5UnexpectedWriteoffRejected(t *testing.T) {
	p := schedulerFixture()
	p.result.FinalWriteoffs = 1
	r := newSchedulerTest(t, p)
	r.tick(context.Background())
	if len(p.changes) != 1 {
		t.Fatal("invalid writeoff result must remain unknown")
	}
}

func TestG5RejectedWarehouseCredentialHasNoUnknownChange(t *testing.T) {
	p := schedulerFixture()
	p.dueErr = &DueFailure{Outcome: "not_committed", Status: 401, Cause: errors.New("InvalidToken")}
	r := newSchedulerTest(t, p)
	r.tick(context.Background())
	if len(p.changes) != 0 {
		t.Fatal("definite rejected credential invalidated stock")
	}
}
func TestG5RunNeverOverlapsAndStops(t *testing.T) {
	p := schedulerFixture()
	p.block = make(chan struct{})
	p.started = make(chan struct{}, 1)
	ticks := make(chan time.Time, 10)
	stopped := make(chan struct{})
	r := newSchedulerTest(t, p)
	r.opts.NewTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() { close(stopped) } }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("initial missed-tick run absent")
	}
	for range 10 {
		ticks <- time.Now()
	}
	p.mu.Lock()
	if len(p.due) != 1 || p.maximum != 1 {
		t.Error("queued ticks overlap blocked exchange")
	}
	p.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("owned runner did not finish")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("ticker not stopped")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.maximum != 1 || p.active != 0 || len(p.due) != 1 {
		t.Fatal("shutdown leaked/retried an exchange")
	}
}
func TestG5AttemptBudgetAndNextTickRecovery(t *testing.T) {
	p := schedulerFixture()
	p.block = make(chan struct{})
	r := newSchedulerTest(t, p)
	r.opts.Timeout = 20 * time.Millisecond
	started := time.Now()
	r.tick(context.Background())
	if time.Since(started) > time.Second || len(p.changes) != 1 {
		t.Fatal("due exchange did not terminate as unknown within budget")
	}
	p.block = nil
	r.tick(context.Background())
	if len(p.due) != 2 || len(p.changes) != 2 {
		t.Fatal("next due poll did not recover timeout")
	}
}

func TestG5OwnGatewayEpochRequiresReadiness(t *testing.T) {
	p := schedulerFixture()
	p.registry.Entries[0].Services = append(p.registry.Entries[0].Services, Readiness{RestaurantID: tenantA, Service: "serving", Epoch: warehouseEpoch, State: "ready", LifecycleVersion: "1"}, Readiness{RestaurantID: tenantA, Service: "gateway", Epoch: warehouseEpoch, State: "ready", LifecycleVersion: "1"})
	r := newSchedulerTest(t, p)
	r.opts.GatewayEpoch = "66666666-6666-4666-8666-666666666666"
	r.tick(context.Background())
	if len(p.due) != 0 || len(p.requests) != 0 {
		t.Fatal("Gateway restart used old ready acknowledgment")
	}
	p.registry.Entries[0].Services[2].Epoch = r.opts.GatewayEpoch
	r.tick(context.Background())
	if len(p.due) != 1 {
		t.Fatal("current Gateway epoch did not recover")
	}
}

func TestG5DeletingEntryAndDurableTombstoneCoexist(t *testing.T) {
	p := schedulerFixture()
	p.registry.Entries[0].Restaurant.Lifecycle = "deleting"
	p.registry.Tombstones = append(p.registry.Tombstones, Tombstone{RestaurantID: tenantA, OrgID: p.registry.Entries[0].Restaurant.OrgID, LifecycleVersion: "1"})
	r := newSchedulerTest(t, p)
	r.tick(context.Background())
	if len(p.closed) != 1 {
		t.Fatal("complete deletion registry did not close scope")
	}
	r.tick(context.Background())
	if len(p.closed) != 1 {
		t.Fatal("duplicate registry repeats close")
	}
}
