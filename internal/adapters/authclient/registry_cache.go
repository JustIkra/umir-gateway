package authclient

import (
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
)

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

func (r *registryCache) store(sequence uint64, value expiration.Registry, now time.Time, available bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sequence < r.applied {
		return
	}
	r.applied, r.observedAt, r.available = sequence, now, available
	if available {
		r.value = copyRegistry(value)
	} else {
		r.value = expiration.Registry{}
	}
}

func (c *Client) RegistrySnapshot() (expiration.Registry, bool) {
	now := c.now()
	c.registry.mu.Lock()
	defer c.registry.mu.Unlock()
	age := now.Sub(c.registry.observedAt)
	if !c.registry.available || age < 0 || age >= 5*time.Second {
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
