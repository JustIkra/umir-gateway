package expiration

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIterationObservationFollowsFinalWatermark(t *testing.T) {
	p := schedulerFixture()
	r := newSchedulerTest(t, p)
	events := make(chan uint64, 4)
	r.opts.IterationCompleted = events
	ticks := make(chan time.Time)
	r.opts.NewTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case seq := <-events:
		if seq != 1 || r.states[tenantA].version != "1" {
			t.Fatal("startup observation precedes final state")
		}
	case <-time.After(time.Second):
		t.Fatal("real Run startup iteration has no completion observation")
	}
	ticks <- time.Now()
	select {
	case seq := <-events:
		if seq != 2 {
			t.Fatalf("sequence %d", seq)
		}
	case <-time.After(time.Second):
		t.Fatal("tick completion missing")
	}
	cancel()
	<-done
	select {
	case <-events:
		t.Fatal("exit emitted a spurious completion")
	default:
	}
}

type observedPeer struct {
	*schedulerPeer
	registryErr, statusErr, closeErr, observeErr, appendErr error
	emptyToken, expiredToken                                bool
	cancel                                                  context.CancelFunc
}

func (p *observedPeer) Registry(ctx context.Context) (Registry, error) {
	if p.cancel != nil {
		p.cancel()
	}
	value, err := p.schedulerPeer.Registry(ctx)
	return value, errors.Join(err, p.registryErr)
}
func (p *observedPeer) Status(ctx context.Context) (RuntimeStatus, error) {
	value, err := p.schedulerPeer.Status(ctx)
	return value, errors.Join(err, p.statusErr)
}
func (p *observedPeer) ServiceToken(ctx context.Context, r ServiceRequest) (Credential, error) {
	value, err := p.schedulerPeer.ServiceToken(ctx, r)
	if p.emptyToken {
		value.Token = ""
	}
	if p.expiredToken {
		value.ExpiresAt = time.Time{}
	}
	return value, err
}
func (p *observedPeer) CloseScope(id string) error {
	if p.closeErr != nil {
		return p.closeErr
	}
	return p.schedulerPeer.CloseScope(id)
}
func (p *observedPeer) ObserveRuntime(string, string, string) error { return p.observeErr }
func (p *observedPeer) Append(id string, topics []string) error {
	if p.appendErr != nil {
		return p.appendErr
	}
	return p.schedulerPeer.Append(id, topics)
}
func TestIterationObservationEveryExitClass(t *testing.T) {
	for _, mode := range []string{"registry-error", "registry-incomplete", "registry-invalid", "status-error", "status-not-ready", "status-wrong-service", "status-no-epoch", "scope-close", "scope-close-error", "skipped-entry", "credential-error", "credential-empty", "credential-expired", "run-id-error", "run-id-empty", "journal-observe-error", "due-rejected", "due-unknown", "due-invalid", "append-error", "success", "cancel-in-body", "due-timeout", "cancel-in-due"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &observedPeer{schedulerPeer: schedulerFixture()}
			r := newSchedulerTest(t, p.schedulerPeer)
			r.opts.Auth = p
			r.opts.Warehouse = p
			r.opts.Changes = p
			failure := errors.New("synthetic boundary unavailable")
			switch mode {
			case "registry-error":
				p.registryErr = failure
			case "registry-incomplete":
				p.registry.Complete = false
			case "registry-invalid":
				p.registry.Entries = append(p.registry.Entries, p.registry.Entries[0])
			case "status-error":
				p.statusErr = failure
			case "status-not-ready":
				p.status.Ready = false
			case "status-wrong-service":
				p.status.Service = "serving"
			case "status-no-epoch":
				p.status.Epoch = ""
			case "scope-close", "scope-close-error":
				p.registry.Entries[0].Restaurant.Lifecycle = "deleting"
				if mode == "scope-close-error" {
					p.closeErr = failure
				}
			case "skipped-entry":
				p.registry.Entries[0].Services[0].Epoch = "old"
			case "credential-error":
				p.authErr = failure
			case "credential-empty":
				p.emptyToken = true
			case "credential-expired":
				p.expiredToken = true
			case "run-id-error":
				r.opts.NewRunID = func() (string, error) { return "", failure }
			case "run-id-empty":
				r.opts.NewRunID = func() (string, error) { return "", nil }
			case "journal-observe-error":
				p.observeErr = failure
			case "due-rejected":
				p.dueErr = &DueFailure{Outcome: "not_committed", Cause: failure}
			case "due-unknown":
				p.dueErr = failure
			case "due-invalid":
				p.result.FinalWriteoffs = 1
			case "append-error":
				p.result.Invalidation = true
				p.appendErr = failure
			case "cancel-in-body":
				p.cancel = cancel
			case "due-timeout":
				p.block = make(chan struct{})
				r.opts.Timeout = 5 * time.Millisecond
			case "cancel-in-due":
				p.block = make(chan struct{})
				p.started = make(chan struct{}, 1)
			}
			ticks := make(chan time.Time)
			events := make(chan uint64, 4)
			r.opts.IterationCompleted = events
			r.opts.NewTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
			done := make(chan struct{})
			go func() { defer close(done); r.Run(ctx) }()
			if mode == "cancel-in-due" {
				select {
				case <-p.started:
					cancel()
				case <-time.After(time.Second):
					cancel()
					<-done
					t.Fatal("due never started")
				}
			}
			select {
			case seq := <-events:
				if seq != 1 {
					t.Fatalf("sequence %d", seq)
				}
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("no completion")
			}
			if mode == "success" && r.states[tenantA].version != "1" {
				t.Error("completion precedes watermark")
			}
			if (mode == "due-unknown" || mode == "due-timeout" || mode == "cancel-in-due") && !r.states[tenantA].unknown {
				t.Error("completion precedes unknown watermark")
			}
			if mode == "scope-close" && (!r.closedScopes[tenantA] || len(p.closed) != 1) {
				t.Error("completion precedes scope close")
			}
			cancel()
			<-done
			select {
			case seq := <-events:
				t.Fatalf("duplicate completion %d", seq)
			default:
			}
		})
	}
}
func TestRunExitWithoutTickHasNoCompletion(t *testing.T) {
	for _, mode := range []string{"cancel-before-start", "closed-ticker", "cancel-idle"} {
		t.Run(mode, func(t *testing.T) {
			r := newSchedulerTest(t, schedulerFixture())
			events := make(chan uint64, 3)
			ticks := make(chan time.Time)
			r.opts.IterationCompleted = events
			r.opts.NewTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel-before-start" {
				cancel()
			}
			done := make(chan struct{})
			go func() { defer close(done); r.Run(ctx) }()
			if mode != "cancel-before-start" {
				select {
				case <-events:
				case <-time.After(time.Second):
					t.Fatal("no startup baseline")
				}
				if mode == "closed-ticker" {
					close(ticks)
				} else {
					cancel()
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Run did not exit")
			}
			select {
			case <-events:
				t.Fatal("Run exit emitted an iteration that did not run")
			default:
			}
		})
	}
}
func TestIterationObservationNeverBlocks(t *testing.T) {
	for _, mode := range []string{"nil", "unbuffered", "full", "closed"} {
		t.Run(mode, func(t *testing.T) {
			r := newSchedulerTest(t, schedulerFixture())
			ticks := make(chan time.Time)
			close(ticks)
			r.opts.NewTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
			if mode == "unbuffered" {
				r.opts.IterationCompleted = make(chan uint64)
			}
			if mode == "closed" {
				events := make(chan uint64)
				close(events)
				r.opts.IterationCompleted = events
			}
			if mode == "full" {
				events := make(chan uint64, 1)
				events <- 99
				r.opts.IterationCompleted = events
			}
			done := make(chan struct{})
			go func() { defer close(done); r.Run(context.Background()) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("observer changed scheduler liveness")
			}
			if r.states[tenantA].version != "1" {
				t.Fatal("observer changed scheduler state")
			}
		})
	}
}
