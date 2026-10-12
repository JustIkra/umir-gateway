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

var (
	ErrLoginRateLimited = errors.New("login rate limited")
	// ErrPasswordChangeRateLimited is wrapped by PasswordChangeLimitError.
	ErrPasswordChangeRateLimited = errors.New("password change rate limited")
)

// RateLimitError rejects a login before any password check.
type RateLimitError struct {
	// RetryAfter is a whole number of seconds, at least one.
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return ErrLoginRateLimited.Error() }

func (e *RateLimitError) Unwrap() error { return ErrLoginRateLimited }

func rateLimited(wait time.Duration) *RateLimitError {
	return &RateLimitError{RetryAfter: wholeSeconds(wait)}
}

// PasswordChangeLimitError refuses a password change during the operator-wide cooldown that
// FailureLimit wrong current passwords within FailureWindow start. SessionRevoked reports that this
// response revoked, and stored the revocation of, the calling session.
type PasswordChangeLimitError struct {
	// RetryAfter is a whole number of seconds, at least one.
	RetryAfter     time.Duration
	SessionRevoked bool
}

func (e *PasswordChangeLimitError) Error() string { return ErrPasswordChangeRateLimited.Error() }

func (e *PasswordChangeLimitError) Unwrap() error { return ErrPasswordChangeRateLimited }

// wholeSeconds rounds wait up to whole seconds, at least one, for Retry-After.
func wholeSeconds(wait time.Duration) time.Duration {
	return max(time.Second, (wait+time.Second-1)/time.Second*time.Second)
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

// failureThrottle counts failures in a rolling window and starts a cooldown at the limit. It never
// grows past the limit; the login and the password change each have one for the whole operator.
type failureThrottle struct {
	failures []time.Time
	until    time.Time
}

func (t *failureThrottle) wait(now time.Time) time.Duration {
	if now.Before(t.until) {
		return t.until.Sub(now)
	}
	return 0
}

// fail records a failure at now and reports whether it started a cooldown.
func (t *failureThrottle) fail(now time.Time, limit int, window, cooldown time.Duration) bool {
	kept := t.failures[:0]
	for _, at := range t.failures {
		if now.Sub(at) < window {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	if len(kept) >= limit {
		t.until = now.Add(cooldown)
		t.failures = kept[:0]
		return true
	}
	t.failures = kept
	return false
}

func (s *Service) cooldownLocked(now time.Time) time.Duration { return s.throttle.wait(now) }

func (s *Service) recordFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.throttle.fail(s.opts.Now(), s.opts.FailureLimit, s.opts.FailureWindow, s.opts.Cooldown)
}
