package authclient

import (
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

func (c *Client) RegistrySnapshot() (expiration.Registry, bool) {
	now := c.now()
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	age := now.Sub(c.registry.observedAt)
	if !c.registry.available || age < 0 || age >= c.maxAge {
		return expiration.Registry{}, false
	}
	return copyRegistry(c.registry.value), true
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
