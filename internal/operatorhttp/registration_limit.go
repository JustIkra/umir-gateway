package operatorhttp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/clientaddr"
)

type registrationAttempt struct {
	at     time.Time
	digest [32]byte
}
type registrationLimits struct {
	mu              sync.Mutex
	peers, browsers map[string][]registrationAttempt
}

func (l *registrationLimits) admit(peer, preauth string, body []byte, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.peers == nil {
		l.peers = map[string][]registrationAttempt{}
		l.browsers = map[string][]registrationAttempt{}
	}
	for _, records := range []map[string][]registrationAttempt{l.peers, l.browsers} {
		for key, items := range records {
			kept := items[:0]
			for _, item := range items {
				if now.Sub(item.at) < 10*time.Minute {
					kept = append(kept, item)
				}
			}
			if len(kept) == 0 {
				delete(records, key)
			} else {
				records[key] = kept
			}
		}
	}
	digest := sha256.Sum256(append(append([]byte(preauth), 0), body...))
	browserDigest := sha256.Sum256([]byte(preauth))
	browser := hex.EncodeToString(browserDigest[:])
	ip, bound := l.peers[peer]
	client, known := l.browsers[browser]
	wait := time.Duration(0)
	for _, entry := range []struct {
		items []registrationAttempt
		limit int
	}{{ip, 30}, {client, 3}} {
		repeated := false
		for _, item := range entry.items {
			if item.digest == digest {
				repeated = true
				break
			}
		}
		if !repeated && len(entry.items) >= entry.limit {
			wait = max(wait, entry.items[0].at.Add(10*time.Minute).Sub(now))
		}
	}
	if !bound && len(l.peers) >= 1024 || !known && len(l.browsers) >= 4096 {
		wait = max(wait, time.Minute)
	}
	if wait > 0 {
		return wait
	}
	appendOnce := func(items []registrationAttempt) []registrationAttempt {
		for _, item := range items {
			if item.digest == digest {
				return items
			}
		}
		return append(items, registrationAttempt{now, digest})
	}
	l.peers[peer] = appendOnce(ip)
	l.browsers[browser] = appendOnce(client)
	return 0
}
func (a *RemoteAPI) admitRegistration(w http.ResponseWriter, r *http.Request, browser BrowserContext, body []byte) bool {
	var input struct {
		Purpose string `json:"purpose"`
	}
	if r.Method != http.MethodPost || r.URL.Path != "/api/v2/email-challenges" || json.Unmarshal(body, &input) != nil || input.Purpose != "registration" || browser.SessionToken != "" {
		return true
	}
	clients := a.clients
	if clients == nil {
		clients = clientaddr.Resolver{}
	}
	peer := clients.Client(r)
	if wait := a.registration.admit(peer, browser.PreauthToken, body, a.boundary.now()); wait > 0 {
		seconds := max(1, int((wait+time.Second-1)/time.Second))
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		a.boundary.problem(w, r, 429, "RateLimited", "registration request limit reached")
		return false
	}
	return true
}
