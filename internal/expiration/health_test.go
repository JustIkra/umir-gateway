package expiration

import (
	"context"
	"io"
	"log"
	"testing"
	"time"
)

// pacedPeer advances the injected clock while the Warehouse status is read, so an iteration has a
// measurable duration without sleeping.
type pacedPeer struct {
	*schedulerPeer
	clock *time.Time
	pace  time.Duration
}

func (p pacedPeer) Status(ctx context.Context) (RuntimeStatus, error) {
	*p.clock = p.clock.Add(p.pace)
	return p.schedulerPeer.Status(ctx)
}

func healthRunner(t *testing.T, peer *schedulerPeer, now *time.Time, pace time.Duration) *ScopedRunner {
	t.Helper()
	paced := pacedPeer{schedulerPeer: peer, clock: now, pace: pace}
	r, err := NewScoped(ScopedOptions{Auth: paced, Warehouse: paced, Changes: peer, Interval: time.Second, Timeout: time.Second, Now: func() time.Time { return *now }, NewRunID: func() (string, error) { return "55555555-5555-4555-8555-555555555555", nil }, NewTicker: func(time.Duration) (<-chan time.Time, func()) { return make(chan time.Time), func() {} }, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestW1HealthRecordsStartSuccessDurationAndFailures(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	peer := schedulerFixture()
	r := healthRunner(t, peer, &now, 3*time.Second)
	if h := r.Health(); !h.LastStart.IsZero() || !h.LastSuccess.IsZero() || h.ConsecutiveFailures != 0 {
		t.Fatalf("health before any iteration: %+v", h)
	}
	started := now
	r.runIteration(context.Background())
	h := r.Health()
	if !h.LastStart.Equal(started) || !h.LastSuccess.Equal(started.Add(3*time.Second)) || h.LastDuration != 3*time.Second || h.ConsecutiveFailures != 0 {
		t.Fatalf("successful iteration: %+v", h)
	}
	peer.mu.Lock()
	peer.registry.Complete = false
	peer.mu.Unlock()
	now = now.Add(time.Minute)
	failedAt := now
	for want := 1; want <= 3; want++ {
		r.runIteration(context.Background())
		h = r.Health()
		if h.ConsecutiveFailures != want || !h.LastSuccess.Equal(started.Add(3*time.Second)) {
			t.Fatalf("failure %d: %+v", want, h)
		}
	}
	if h.LastStart.Before(failedAt) {
		t.Fatalf("last start not advanced by failures: %+v", h)
	}
	peer.mu.Lock()
	peer.registry = readyRegistry()
	peer.mu.Unlock()
	r.runIteration(context.Background())
	if h = r.Health(); h.ConsecutiveFailures != 0 || !h.LastSuccess.After(failedAt) {
		t.Fatalf("recovery: %+v", h)
	}
}

func TestW1WarehouseOutageIsAFailedIteration(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	peer := schedulerFixture()
	peer.status.Ready = false
	r := healthRunner(t, peer, &now, 0)
	r.runIteration(context.Background())
	if h := r.Health(); h.ConsecutiveFailures != 1 || !h.LastSuccess.IsZero() {
		t.Fatalf("%+v", h)
	}
}

func TestW1DueFailureOfOneRestaurantDoesNotFailTheIteration(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	peer := schedulerFixture()
	peer.authErr = io.ErrUnexpectedEOF
	r := healthRunner(t, peer, &now, 0)
	r.runIteration(context.Background())
	if h := r.Health(); h.ConsecutiveFailures != 0 || h.LastSuccess.IsZero() {
		t.Fatalf("%+v", h)
	}
}

func TestW1SchedulerStateFromHealth(t *testing.T) {
	base := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	interval := 10 * time.Second
	for name, tc := range map[string]struct {
		health SchedulerHealth
		now    time.Time
		want   string
	}{
		"never started":                   {SchedulerHealth{}, base, StateDegraded},
		"fresh success":                   {SchedulerHealth{LastStart: base, LastSuccess: base}, base.Add(interval), StateOK},
		"three intervals is still fine":   {SchedulerHealth{LastStart: base, LastSuccess: base}, base.Add(3 * interval), StateOK},
		"paused iteration":                {SchedulerHealth{LastStart: base.Add(interval), LastSuccess: base}, base.Add(4 * interval), StateDegraded},
		"one failure after success":       {SchedulerHealth{LastStart: base, LastSuccess: base.Add(-time.Second), ConsecutiveFailures: 1}, base, StateDegraded},
		"ten intervals without success":   {SchedulerHealth{LastStart: base, LastSuccess: base}, base.Add(10*interval + time.Nanosecond), StateDown},
		"ten intervals is still degraded": {SchedulerHealth{LastStart: base, LastSuccess: base}, base.Add(10 * interval), StateDegraded},
		"startup failures":                {SchedulerHealth{LastStart: base, ConsecutiveFailures: 2}, base, StateDegraded},
		"startup keeps failing":           {SchedulerHealth{LastStart: base, ConsecutiveFailures: 3}, base, StateDown},
		"clock before success":            {SchedulerHealth{LastStart: base, LastSuccess: base}, base.Add(-time.Hour), StateOK},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.health.State(tc.now, interval); got != tc.want {
				t.Fatalf("state %q, want %q", got, tc.want)
			}
		})
	}
}

func TestW1RunRecordsHealthForEveryIteration(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	peer := schedulerFixture()
	ticks := make(chan time.Time)
	r := healthRunner(t, peer, &now, time.Second)
	r.opts.NewTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
	completed := make(chan uint64, 4)
	r.opts.IterationCompleted = completed
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	if got := <-completed; got != 1 {
		t.Fatalf("first iteration %d", got)
	}
	ticks <- time.Time{}
	if got := <-completed; got != 2 {
		t.Fatalf("second iteration %d", got)
	}
	cancel()
	<-done
	if h := r.Health(); h.LastSuccess.IsZero() || h.LastDuration != time.Second {
		t.Fatalf("%+v", h)
	}
}
