package authclient

import (
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
)

// tokenRenewMargin is how long before expiry a cached service token stops being reused.
const tokenRenewMargin = 10 * time.Second

// maxCachedTokens bounds the cache by the registry's restaurant limit.
const maxCachedTokens = 10000

// tokenCache keeps the scheduler's last service token per restaurant. A token is bound to the
// Warehouse epoch it was issued for, so a different epoch is a miss.
type tokenCache struct {
	mu      sync.Mutex
	entries map[string]cachedToken
}

type cachedToken struct {
	epoch      string
	credential expiration.Credential
}

func (t *tokenCache) get(restaurantID, epoch string, now time.Time) (expiration.Credential, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[restaurantID]
	if !ok || entry.epoch != epoch || !now.Add(tokenRenewMargin).Before(entry.credential.ExpiresAt) {
		return expiration.Credential{}, false
	}
	return entry.credential, true
}

func (t *tokenCache) put(restaurantID, epoch string, credential expiration.Credential, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries == nil {
		t.entries = map[string]cachedToken{}
	}
	if _, replaces := t.entries[restaurantID]; !replaces && len(t.entries) >= maxCachedTokens {
		for id, entry := range t.entries {
			if !now.Before(entry.credential.ExpiresAt) {
				delete(t.entries, id)
			}
		}
		if len(t.entries) >= maxCachedTokens {
			return
		}
	}
	t.entries[restaurantID] = cachedToken{epoch: epoch, credential: credential}
}
