package operator

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Login capacity defaults from gateway#8.
const (
	DefaultMaxVerifications = 2
	DefaultMaxQueuedLogins  = 8
	DefaultFailureLimit     = 5
	DefaultFailureWindow    = 60 * time.Second
	DefaultCooldown         = 60 * time.Second
	queueFullRetryAfter     = time.Second
)

var ErrLoginRateLimited = errors.New("login rate limited")

// RateLimitError rejects a login before any password check.
type RateLimitError struct {
	// RetryAfter is a whole number of seconds, at least one.
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return ErrLoginRateLimited.Error() }

func (e *RateLimitError) Unwrap() error { return ErrLoginRateLimited }

func rateLimited(wait time.Duration) *RateLimitError {
	return &RateLimitError{RetryAfter: max(time.Second, (wait+time.Second-1)/time.Second*time.Second)}
}

// verificationGate bounds Argon2id work. Holders release their slot when the check ends; waiters
// leave when a slot frees or their context ends, so the gate owns no goroutines. Only logins count
// toward the queue bound; password changes run one at a time and wait outside it.
type verificationGate struct {
	slots     chan struct{}
	maxQueued int

	mu             sync.Mutex
	waitingLogins  int
	waitingChanges int
}

func newVerificationGate(running, queued int) *verificationGate {
	return &verificationGate{slots: make(chan struct{}, running), maxQueued: queued}
}

// acquire takes a slot. A bounded caller (login) fails fast while maxQueued callers already wait.
func (g *verificationGate) acquire(ctx context.Context, bounded bool) (release func(), err error) {
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	default:
	}
	waiting := &g.waitingChanges
	if bounded {
		waiting = &g.waitingLogins
	}
	g.mu.Lock()
	if bounded && *waiting >= g.maxQueued {
		g.mu.Unlock()
		return nil, rateLimited(queueFullRetryAfter)
	}
	*waiting++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		*waiting--
		g.mu.Unlock()
	}()
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *verificationGate) release() { <-g.slots }

// loginThrottle is the single failed-login counter; it never grows past FailureLimit entries.
type loginThrottle struct {
	failures []time.Time
	until    time.Time
}

func (s *Service) cooldownLocked(now time.Time) time.Duration {
	if now.Before(s.throttle.until) {
		return s.throttle.until.Sub(now)
	}
	return 0
}

func (s *Service) recordFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	kept := s.throttle.failures[:0]
	for _, at := range s.throttle.failures {
		if now.Sub(at) < s.opts.FailureWindow {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	if len(kept) >= s.opts.FailureLimit {
		s.throttle.until = now.Add(s.opts.Cooldown)
		kept = kept[:0]
	}
	s.throttle.failures = kept
}
