// Package redisadmission joins the Redis reference adapter (package redislimiter, copied from the factory
// without changes) to the admission ports of the Gateway. It owns no logic of its own beyond translating
// types and errors: every failure of Redis becomes admission.ErrUnavailable, never an "allowed".
package redisadmission

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JustIkra/umir-gateway/internal/adapters/redislimiter"
	"github.com/JustIkra/umir-gateway/internal/admission"
)

// Config opens the adapter.
type Config struct {
	// URL is the Redis URL of the limiter; it never appears in an error.
	URL string
	// Timeout bounds every command and call; zero means the reference default (200 ms).
	Timeout time.Duration
	// Generation is the configured limiter generation compared with the marker (R7).
	Generation string
	// StrictWindow is the strict window after the marker is lost (the longest policy window, at most 1 h).
	StrictWindow time.Duration
	// KeyRoot prefixes every key; empty in production, the test prefix in tests.
	KeyRoot string
	// ClientName is shown in CLIENT LIST.
	ClientName string
	// Clock is the clock of this replica for the strict window; nil means time.Now.
	Clock func() time.Time
}

// Adapter holds the Redis client and the ports built on it.
type Adapter struct {
	client     *redislimiter.Client
	limiter    *redislimiter.Limiter
	continuity *redislimiter.Continuity
	slots      *redislimiter.Slots
	lease      *redislimiter.Lease
	generation string
}

// Open connects and builds the ports. The owner of every key is the Gateway.
func Open(ctx context.Context, cfg Config) (*Adapter, error) {
	client, err := redislimiter.Open(ctx, redislimiter.Config{URL: cfg.URL, ClientName: cfg.ClientName, Timeout: cfg.Timeout, KeyRoot: cfg.KeyRoot})
	if err != nil {
		return nil, err
	}
	a := &Adapter{client: client, generation: cfg.Generation}
	if a.limiter, err = client.Limiter(redislimiter.OwnerGateway); err == nil {
		a.slots, err = client.Slots(redislimiter.OwnerGateway)
	}
	if err == nil {
		a.lease, err = client.Lease(redislimiter.OwnerGateway)
	}
	if err == nil {
		a.continuity, err = client.Continuity(redislimiter.ContinuityConfig{Window: cfg.StrictWindow, Clock: cfg.Clock})
	}
	if err != nil {
		return nil, errors.Join(err, client.Close())
	}
	return a, nil
}

// Close closes the Redis pool.
func (a *Adapter) Close() error { return a.client.Close() }

// Ping checks that Redis answers.
func (a *Adapter) Ping(ctx context.Context) error {
	if err := a.client.Ping(ctx); err != nil {
		return errors.Join(admission.ErrUnavailable, err)
	}
	return nil
}

func unavailable(err error) error {
	if err == nil {
		return nil
	}
	return errors.Join(admission.ErrUnavailable, err)
}

// Limiter is the admission.Limiter of the adapter.
func (a *Adapter) Limiter() admission.Limiter { return limiter{a.limiter} }

// Continuity is the admission.Continuity of the adapter.
func (a *Adapter) Continuity() admission.Continuity { return continuity{a.continuity, a.generation} }

// Slots is the admission.Slots of the adapter.
func (a *Adapter) Slots() admission.Slots { return slots{a.slots} }

// Leader is the admission.Leader of the adapter.
func (a *Adapter) Leader() admission.Leader { return leader{a.lease} }

type limiter struct{ l *redislimiter.Limiter }

func (l limiter) Admit(ctx context.Context, r admission.Request) (admission.Decision, error) {
	request := redislimiter.Request{ID: r.ID, Fingerprint: r.Fingerprint, Policy: r.Policy}
	for _, d := range r.Dimensions {
		request.Dimensions = append(request.Dimensions, redislimiter.Dimension{Key: d.Key, Limit: d.Limit, Window: d.Window})
	}
	d, err := l.l.Admit(ctx, request)
	switch {
	case errors.Is(err, redislimiter.ErrAdmissionConflict):
		return admission.Decision{}, admission.ErrConflict
	case err != nil:
		return admission.Decision{}, unavailable(err)
	}
	return admission.Decision{Allowed: d.Allowed, Replay: d.Reason == redislimiter.ReasonReplay, RetryAfter: d.RetryAfter, Dimension: d.Dimension}, nil
}

type continuity struct {
	c          *redislimiter.Continuity
	generation string
}

func (c continuity) Check(ctx context.Context) (admission.State, error) {
	state, err := c.c.Check(ctx, c.generation)
	if err != nil {
		return admission.State{}, unavailable(err)
	}
	if state.Mode == redislimiter.Strict {
		return admission.State{Mode: admission.Strict, Reason: state.Reason}, nil
	}
	return admission.State{}, nil
}

type slots struct{ s *redislimiter.Slots }

func (s slots) Acquire(ctx context.Context, r admission.SlotRequest) (admission.SlotGrant, error) {
	request := redislimiter.SlotRequest{Holder: r.Holder, TTL: r.TTL}
	for _, l := range r.Limits {
		request.Dimensions = append(request.Dimensions, redislimiter.SlotDimension{Key: l.Key, MaxCount: l.Max})
	}
	g, err := s.s.Acquire(ctx, request)
	if err != nil {
		return admission.SlotGrant{}, unavailable(err)
	}
	return admission.SlotGrant{Granted: g.Granted, Denied: g.Denied}, nil
}

func (s slots) Renew(ctx context.Context, holder string, ttl time.Duration, keys ...string) (bool, error) {
	ok, err := s.s.Renew(ctx, holder, ttl, keys...)
	return ok, unavailable(err)
}

func (s slots) Release(ctx context.Context, holder string, keys ...string) error {
	return unavailable(s.s.Release(ctx, holder, keys...))
}

type leader struct{ l *redislimiter.Lease }

func (l leader) Acquire(ctx context.Context, name, holder string, ttl time.Duration) (admission.LeaseGrant, error) {
	g, err := l.l.Acquire(ctx, name, holder, ttl)
	if err != nil {
		return admission.LeaseGrant{}, unavailable(err)
	}
	return admission.LeaseGrant{Acquired: g.Acquired, Fence: g.Fence}, nil
}

func (l leader) Renew(ctx context.Context, name, holder string, ttl time.Duration) (bool, error) {
	ok, err := l.l.Renew(ctx, name, holder, ttl)
	return ok, unavailable(err)
}

func (l leader) Release(ctx context.Context, name, holder string) error {
	return unavailable(l.l.Release(ctx, name, holder))
}

// String keeps accidental formatting of the adapter free of the URL.
func (a *Adapter) String() string {
	return fmt.Sprintf("redisadmission(generation set: %t)", a.generation != "")
}

// IsUnavailable reports whether err means that the store gave no verified answer.
func IsUnavailable(err error) bool { return errors.Is(err, admission.ErrUnavailable) }
