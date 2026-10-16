// TEMPORARY: process-local admission limits for anonymous feedback (decision C31, gateway wave 1).
//
// Gateway has no admission store yet, so this file stands in for it, and only for this one route.
// It must not be released on its own (U5): the wave that introduces the Redis admission for this route
// deletes this file in the same commit, and no fallback "store unavailable -> memory" exists (R10, R20).
// Budgets live in this process, so with several replicas the quota would multiply by their number.
package admission

import (
	"crypto/sha256"
	"slices"
	"sync"
	"time"
)

// Budgets of the temporary limiter; the numbers come from the gateway subspecification (W1.6).
const (
	preauthLimit   = 5
	preauthWindow  = 10 * time.Minute
	clientLimit    = 20
	clientWindow   = time.Hour
	processLimit   = 200
	processWindow  = time.Hour
	maxPreauthKeys = 4096
	maxClientKeys  = 4096
	// fullWait is how long a caller waits when a table of keys is full.
	fullWait = time.Minute
)

type attempt struct {
	at          time.Time
	fingerprint [32]byte
}

// bucket is a sliding window of distinct attempts.
type bucket struct {
	limit  int
	window time.Duration
}

// TemporaryMemory limits anonymous feedback by browser context, by client and by process. The client
// budget acts only when the client address is trustworthy (PerClient).
type TemporaryMemory struct {
	// PerClient enables the client budget; set it only behind configured trusted proxies, otherwise the
	// client is the frontend address and one budget would block everybody.
	PerClient bool

	mu       sync.Mutex
	preauths map[[32]byte][]attempt
	clients  map[string][]attempt
	process  []attempt
}

// Admit decides one attempt and returns how long the caller should wait, zero when it is admitted. An
// attempt repeating a fingerprint (preauth and body) already counted in a bucket is not charged again
// there. An admitted attempt is charged to every bucket, a refused one to none.
func (m *TemporaryMemory) Admit(preauth, client string, body []byte, now time.Time) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.preauths == nil {
		m.preauths, m.clients = map[[32]byte][]attempt{}, map[string][]attempt{}
	}
	m.sweep(now)
	fingerprint := sha256.Sum256(append(append([]byte(preauth), 0), body...))
	key := sha256.Sum256([]byte(preauth))
	var wait time.Duration
	check := func(items []attempt, b bucket) {
		if slices.ContainsFunc(items, func(a attempt) bool { return a.fingerprint == fingerprint }) || len(items) < b.limit {
			return
		}
		wait = max(wait, items[0].at.Add(b.window).Sub(now))
	}
	preauthItems, known := m.preauths[key]
	check(preauthItems, bucket{preauthLimit, preauthWindow})
	if !known && len(m.preauths) >= maxPreauthKeys {
		wait = max(wait, fullWait)
	}
	clientItems, clientKnown := m.clients[client]
	if m.PerClient {
		check(clientItems, bucket{clientLimit, clientWindow})
		if !clientKnown && len(m.clients) >= maxClientKeys {
			wait = max(wait, fullWait)
		}
	}
	check(m.process, bucket{processLimit, processWindow})
	if wait > 0 {
		return wait
	}
	charge := func(items []attempt) []attempt {
		if slices.ContainsFunc(items, func(a attempt) bool { return a.fingerprint == fingerprint }) {
			return items
		}
		return append(items, attempt{now, fingerprint})
	}
	m.preauths[key] = charge(preauthItems)
	if m.PerClient {
		m.clients[client] = charge(clientItems)
	}
	m.process = charge(m.process)
	return 0
}

// sweep drops attempts older than their window and keys left empty, so memory follows the live load.
func (m *TemporaryMemory) sweep(now time.Time) {
	keep := func(items []attempt, window time.Duration) []attempt {
		return slices.DeleteFunc(items, func(a attempt) bool { return now.Sub(a.at) >= window })
	}
	for key, items := range m.preauths {
		if items = keep(items, preauthWindow); len(items) == 0 {
			delete(m.preauths, key)
		} else {
			m.preauths[key] = items
		}
	}
	for key, items := range m.clients {
		if items = keep(items, clientWindow); len(items) == 0 {
			delete(m.clients, key)
		} else {
			m.clients[key] = items
		}
	}
	m.process = keep(m.process, processWindow)
}
