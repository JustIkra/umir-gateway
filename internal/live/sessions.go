package live

import (
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// SessionEvents passes committed session changes from the operator service to the streams of that
// session. It implements operator.SessionObserver and never blocks the service.
type SessionEvents struct {
	mu       sync.Mutex
	watchers map[string]map[*watcher]struct{}
}

// NewSessionEvents starts without watchers.
func NewSessionEvents() *SessionEvents {
	return &SessionEvents{watchers: map[string]map[*watcher]struct{}{}}
}

// update is the newest change of one session: either its new deadlines or its end.
type update struct {
	ended          operator.EndReason
	idle, absolute time.Time
}

// watcher keeps only the newest update of its session; an end is never replaced by an extension.
type watcher struct {
	mu      sync.Mutex
	pending *update
	ready   chan struct{}
}

func (w *watcher) offer(u update) {
	w.mu.Lock()
	if w.pending == nil || w.pending.ended == "" {
		w.pending = &u
	}
	w.mu.Unlock()
	select {
	case w.ready <- struct{}{}:
	default:
	}
}

// take returns the pending update and clears it; ok is false when another take got it first.
func (w *watcher) take() (update, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending == nil {
		return update{}, false
	}
	u := *w.pending
	w.pending = nil
	return u, true
}

// watch registers a watcher of the session with key until stop.
func (e *SessionEvents) watch(key string) (*watcher, func()) {
	w := &watcher{ready: make(chan struct{}, 1)}
	e.mu.Lock()
	if e.watchers[key] == nil {
		e.watchers[key] = map[*watcher]struct{}{}
	}
	e.watchers[key][w] = struct{}{}
	e.mu.Unlock()
	return w, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		delete(e.watchers[key], w)
		if len(e.watchers[key]) == 0 {
			delete(e.watchers, key)
		}
	}
}

func (e *SessionEvents) deliver(key string, u update) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for w := range e.watchers[key] {
		w.offer(u)
	}
}

// SessionExtended passes the new deadlines to the streams of the session.
func (e *SessionEvents) SessionExtended(key string, idleExpiresAt, absoluteExpiresAt time.Time) {
	e.deliver(key, update{idle: idleExpiresAt, absolute: absoluteExpiresAt})
}

// SessionEnded tells the streams of the session to end.
func (e *SessionEvents) SessionEnded(key string, reason operator.EndReason) {
	e.deliver(key, update{ended: reason})
}
