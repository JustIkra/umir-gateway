package authclient

import (
	"context"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
)

// DefaultRegistryMaxAge is how long the last successful complete registry snapshot stays current
// when the client is given no explicit bound.
const DefaultRegistryMaxAge = 30 * time.Second

// registryCache keeps the last successful complete registry and when it was observed. A failed or
// incomplete read never touches it: the snapshot only ages out.
type registryCache struct {
	mu                sync.Mutex
	sequence, applied uint64
	observedAt        time.Time
	available         bool
	value             expiration.Registry
	// flight is the shared read in progress, if any.
	flight *registryFlight
}

// registryFlight is one registry read that concurrent callers of SharedRegistry wait for together.
type registryFlight struct {
	done     chan struct{}
	registry expiration.Registry
	err      error
	// abandoned is set when the caller that ran the read gave up, not Auth: waiters may try again.
	abandoned bool
}

func (r *registryCache) begin() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sequence++
	return r.sequence
}

// store records a successful complete read. An older read finishing after a newer success is dropped.
func (r *registryCache) store(sequence uint64, value expiration.Registry, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sequence < r.applied {
		return
	}
	r.applied, r.observedAt, r.available = sequence, now, true
	r.value = copyRegistry(value)
}

// RegistrySnapshot returns a copy of the last successful complete registry while it is younger than
// the client's maximum age.
func (c *Client) RegistrySnapshot() (expiration.Registry, bool) {
	return c.RegistrySnapshotWithin(c.maxAge)
}

// RegistrySnapshotWithin is RegistrySnapshot with a stricter bound: the snapshot must also be younger
// than maxAge.
func (c *Client) RegistrySnapshotWithin(maxAge time.Duration) (expiration.Registry, bool) {
	maxAge = min(maxAge, c.maxAge)
	now := c.now()
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	age := now.Sub(c.registry.observedAt)
	if !c.registry.available || age < 0 || age >= maxAge {
		return expiration.Registry{}, false
	}
	return copyRegistry(c.registry.value), true
}

// SharedRegistry reads the registry like Registry, but a caller that arrives while another read is in
// progress waits for that read instead of starting its own, so a burst of callers costs one read. The
// shared read may have started before the caller arrived: use Registry when the answer must reflect
// the moment of the call. Each caller receives an independent copy.
func (c *Client) SharedRegistry(ctx context.Context) (expiration.Registry, error) {
	for {
		c.registry.mu.Lock()
		flight := c.registry.flight
		if flight == nil {
			flight = &registryFlight{done: make(chan struct{})}
			c.registry.flight = flight
			c.registry.mu.Unlock()
			return c.runFlight(ctx, flight)
		}
		c.registry.mu.Unlock()
		select {
		case <-flight.done:
		case <-ctx.Done():
			return expiration.Registry{}, scopeUnavailable(ctx.Err())
		}
		if flight.err != nil && flight.abandoned && ctx.Err() == nil {
			continue
		}
		return copyRegistry(flight.registry), flight.err
	}
}

func (c *Client) runFlight(ctx context.Context, flight *registryFlight) (registry expiration.Registry, err error) {
	defer func() {
		// Waiters get their own copies; the leader keeps the original.
		flight.registry, flight.err, flight.abandoned = copyRegistry(registry), err, err != nil && ctx.Err() != nil
		c.registry.mu.Lock()
		c.registry.flight = nil
		c.registry.mu.Unlock()
		close(flight.done)
	}()
	return c.Registry(ctx)
}

func copyRegistry(value expiration.Registry) expiration.Registry {
	result := value
	result.Entries = append([]expiration.RegistryEntry(nil), value.Entries...)
	for i := range result.Entries {
		result.Entries[i].Services = append([]expiration.Readiness(nil), value.Entries[i].Services...)
	}
	result.Tombstones = append([]expiration.Tombstone(nil), value.Tombstones...)
	return result
}
