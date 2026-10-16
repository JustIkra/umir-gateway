// Package admission decides whether a request may proceed, from budgets kept in a shared store (Redis
// in production). The store is reached through the ports below; there is no process-local fallback:
// when the store cannot answer, the answer is ErrUnavailable and the caller refuses the request before it
// reaches an owner (R10, R20).
package admission

import (
	"context"
	"errors"
	"time"
)

// ErrUnavailable means the store did not give a verified answer: a failure, a timeout, an unreadable
// reply or doubtful continuity. It is never read as "allowed".
var ErrUnavailable = errors.New("admission: store unavailable")

// ErrConflict means an admission ID was reused with another fingerprint. Nothing was charged.
var ErrConflict = errors.New("admission: ID reused with a different fingerprint")

// Dimension is one budget of a rule: at most Limit admissions per fixed Window for the subject encoded
// in Key. Key carries the window and an HMAC of the subject, never the subject itself.
type Dimension struct {
	Key    string
	Limit  int
	Window time.Duration
}

// Request is one admission attempt. A repeat with the same ID and fingerprint inside the window is
// allowed and not charged again.
type Request struct {
	ID          string
	Fingerprint string
	Policy      string
	Dimensions  []Dimension
}

// Decision is the verdict of the store.
type Decision struct {
	Allowed bool
	// Replay is set for an allowed repeat that was not charged.
	Replay bool
	// RetryAfter is, for a refusal, the time until the exhausted dimension that frees last is free.
	RetryAfter time.Duration
	// Dimension is the index of that dimension in Request.Dimensions.
	Dimension int
}

// Limiter checks all dimensions of a request and charges them atomically, or charges none.
type Limiter interface {
	Admit(context.Context, Request) (Decision, error)
}

// Mode is the continuity state of the limiter (R7, C47).
type Mode int

const (
	// Normal: the counters are continuous.
	Normal Mode = iota
	// Strict: the marker of the limiter is lost or foreign, so the strict limits apply.
	Strict
)

// State is the answer of Continuity.
type State struct {
	Mode   Mode
	Reason string
}

// Continuity tells whether the counters of the store can be trusted.
type Continuity interface {
	Check(context.Context) (State, error)
}

// SlotLimit caps the holders of one slot key.
type SlotLimit struct {
	Key string
	Max int64
}

// SlotRequest asks for a slot in every key, or in none.
type SlotRequest struct {
	Holder string
	TTL    time.Duration
	Limits []SlotLimit
}

// SlotGrant is the answer of Slots.Acquire; Denied is the index of the first key without room.
type SlotGrant struct {
	Granted bool
	Denied  int
}

// Slots are counted leases: a holder takes a slot in several keys at once, the slots expire unless
// renewed, and a holder never frees the slot of another.
type Slots interface {
	Acquire(context.Context, SlotRequest) (SlotGrant, error)
	// Renew extends the slots; false means one has expired or was released, and the work it guards must stop.
	Renew(ctx context.Context, holder string, ttl time.Duration, keys ...string) (bool, error)
	// Release frees the slots; it is idempotent.
	Release(ctx context.Context, holder string, keys ...string) error
}

// LeaseGrant is the answer of Leader.Acquire; Fence grows with every takeover.
type LeaseGrant struct {
	Acquired bool
	Fence    int64
}

// Leader is a named lease with a fencing counter.
type Leader interface {
	Acquire(ctx context.Context, name, holder string, ttl time.Duration) (LeaseGrant, error)
	// Renew extends the lease only while holder still owns it.
	Renew(ctx context.Context, name, holder string, ttl time.Duration) (bool, error)
	// Release frees the lease only if holder owns it.
	Release(ctx context.Context, name, holder string) error
}
