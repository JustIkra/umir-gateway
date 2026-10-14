package protocol

import (
	"context"
	"sync"
	"time"
)

type Ticks struct {
	Clock       *Clock
	Events      chan uint64
	ticks       chan time.Time
	mu          sync.Mutex
	baseline    bool
	sequence    uint64
	pending     string
	used        map[string]bool
	unavailable bool
	stop        chan struct{}
	once        sync.Once
}

func NewTicks(c *Clock) *Ticks {
	return &Ticks{Clock: c, Events: make(chan uint64, 1), ticks: make(chan time.Time, 1), used: map[string]bool{}, stop: make(chan struct{})}
}
func (t *Ticks) NewTicker(time.Duration) (<-chan time.Time, func()) {
	return t.ticks, func() { t.once.Do(func() { close(t.stop) }) }
}
func (t *Ticks) Baseline(ctx context.Context) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.baseline {
		return !t.unavailable
	}
	select {
	case seq := <-t.Events:
		if seq != 1 {
			t.unavailable = true
			return false
		}
		t.sequence = seq
		t.baseline = true
		return true
	case <-ctx.Done():
		return false
	case <-t.stop:
		return false
	}
}
func (t *Ticks) Available() bool {
	if !t.mu.TryLock() {
		return false
	}
	defer t.mu.Unlock()
	select {
	case <-t.stop:
		return false
	default:
	}
	return t.baseline && !t.unavailable && t.pending == ""
}
func (t *Ticks) Tick(ctx context.Context, instance, generation, id string) (ClockState, string) {
	if !t.mu.TryLock() {
		return ClockState{}, "FaultConflict"
	}
	defer t.mu.Unlock()
	if !t.Clock.Matches(instance, generation) {
		return ClockState{}, "ClockConflict"
	}
	if !t.baseline || t.unavailable {
		return ClockState{}, "NotReady"
	}
	select {
	case <-t.stop:
		return ClockState{}, "NotReady"
	default:
	}
	if t.pending != "" || t.used[id] {
		return ClockState{}, "FaultConflict"
	}
	if len(t.used) >= 256 {
		return ClockState{}, "CapacityExceeded"
	}
	select {
	case <-t.Events:
		t.unavailable = true
		return ClockState{}, "NotReady"
	default:
	}
	t.used[id] = true
	t.pending = id
	select {
	case t.ticks <- t.Clock.Now():
	case <-ctx.Done():
		t.unavailable = true
		return ClockState{}, "WaitExpired"
	}
	select {
	case seq := <-t.Events:
		if seq != t.sequence+1 {
			t.unavailable = true
			return ClockState{}, "NotReady"
		}
		t.sequence = seq
		t.pending = ""
		if !t.Clock.Matches(instance, generation) {
			return ClockState{}, "ClockConflict"
		}
		return t.Clock.Read(), ""
	case <-ctx.Done():
		t.unavailable = true
		return ClockState{}, "OutcomeUnknown"
	case <-t.stop:
		t.unavailable = true
		return ClockState{}, "OutcomeUnknown"
	}
}
