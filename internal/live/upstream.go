package live

import (
	"context"
	"sync"
)

// Upstream is whether the warehouse answers the expiration runs. It starts available; the scheduler
// changes it and every stream reports the change.
type Upstream struct {
	mu          sync.Mutex
	available   bool
	subscribers map[chan struct{}]struct{}
}

// NewUpstream starts available.
func NewUpstream() *Upstream {
	return &Upstream{available: true, subscribers: map[chan struct{}]struct{}{}}
}

// Available returns the current value.
func (u *Upstream) Available() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.available
}

// Set changes the value and wakes the subscribers when it differs. It never blocks.
func (u *Upstream) Set(available bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.available == available {
		return
	}
	u.available = available
	for ch := range u.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Subscribe returns a channel that holds one signal after any number of changes. The subscription
// ends with ctx; the channel is never closed.
func (u *Upstream) Subscribe(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	u.mu.Lock()
	u.subscribers[ch] = struct{}{}
	u.mu.Unlock()
	context.AfterFunc(ctx, func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		delete(u.subscribers, ch)
	})
	return ch
}
