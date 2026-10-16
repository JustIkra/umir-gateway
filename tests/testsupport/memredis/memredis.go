// Package memredis is an in-memory double of the Redis admission ports for tests: the limiter, the
// continuity marker, the counted slots and the named lease. It lives in test support only; the binary
// has no process-local admission (R10, R20). The same contract suites run on it and on the Redis adapter.
package memredis

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/admission"
)

// Store is one shared store; every port below works on it. Clock is a fake clock unless set.
type Store struct {
	mu       sync.Mutex
	now      time.Time
	counters map[string]*counter
	records  map[string]record
	slots    map[string]map[string]time.Time
	leases   map[string]*lease
	fences   map[string]int64
	state    admission.State
	// Fail, when set, makes every call fail like an unreachable Redis.
	fail error
	// Calls counts the requests that reached the store.
	calls int
}

type counter struct {
	n       int
	expires time.Time
}
type record struct {
	fingerprint string
	expires     time.Time
}
type lease struct {
	holder  string
	expires time.Time
}

// New returns an empty store whose clock starts at start.
func New(start time.Time) *Store {
	return &Store{now: start, counters: map[string]*counter{}, records: map[string]record{}, slots: map[string]map[string]time.Time{}, leases: map[string]*lease{}, fences: map[string]int64{}}
}

// Advance moves the clock.
func (s *Store) Advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

// Now is the clock of the store.
func (s *Store) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

// Fail makes the store fail every call with err; nil restores it.
func (s *Store) Fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

// SetState sets the continuity state the Continuity port reports.
func (s *Store) SetState(state admission.State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

// Calls is the number of calls that reached the store.
func (s *Store) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Holders is the number of live holders of a slot key.
func (s *Store) Holders(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, exp := range s.slots[key] {
		if exp.After(s.now) {
			n++
		}
	}
	return n
}

func (s *Store) begin() error {
	s.calls++
	if s.fail != nil {
		return errors.Join(admission.ErrUnavailable, s.fail)
	}
	return nil
}

// Limiter is the admission.Limiter of the store.
func (s *Store) Limiter() admission.Limiter { return limiter{s} }

// Continuity is the admission.Continuity of the store.
func (s *Store) Continuity() admission.Continuity { return continuity{s} }

// Slots is the admission.Slots of the store.
func (s *Store) Slots() admission.Slots { return slots{s} }

// Leader is the admission.Leader of the store.
func (s *Store) Leader() admission.Leader { return leader{s} }

type limiter struct{ s *Store }

func (l limiter) Admit(_ context.Context, r admission.Request) (admission.Decision, error) {
	s := l.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return admission.Decision{}, err
	}
	recKey := r.Policy + "\x00" + r.ID
	if rec, ok := s.records[recKey]; ok && rec.expires.After(s.now) {
		if rec.fingerprint == r.Fingerprint {
			return admission.Decision{Allowed: true, Replay: true}, nil
		}
		return admission.Decision{}, admission.ErrConflict
	}
	worst, index := time.Duration(0), -1
	for i, d := range r.Dimensions {
		c := s.counters[d.Key]
		if c == nil || !c.expires.After(s.now) {
			continue
		}
		if c.n >= d.Limit {
			if left := c.expires.Sub(s.now); index < 0 || left > worst {
				worst, index = left, i
			}
		}
	}
	if index >= 0 {
		return admission.Decision{RetryAfter: max(worst, time.Millisecond), Dimension: index}, nil
	}
	var longest time.Duration
	for _, d := range r.Dimensions {
		c := s.counters[d.Key]
		if c == nil || !c.expires.After(s.now) {
			c = &counter{expires: s.now.Add(d.Window)}
			s.counters[d.Key] = c
		}
		c.n++
		longest = max(longest, d.Window)
	}
	s.records[recKey] = record{fingerprint: r.Fingerprint, expires: s.now.Add(longest)}
	return admission.Decision{Allowed: true}, nil
}

type continuity struct{ s *Store }

func (c continuity) Check(context.Context) (admission.State, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	if err := c.s.begin(); err != nil {
		return admission.State{}, err
	}
	return c.s.state, nil
}

type slots struct{ s *Store }

func (sl slots) purge(key string) {
	for holder, exp := range sl.s.slots[key] {
		if !exp.After(sl.s.now) {
			delete(sl.s.slots[key], holder)
		}
	}
}

func (sl slots) Acquire(_ context.Context, r admission.SlotRequest) (admission.SlotGrant, error) {
	s := sl.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return admission.SlotGrant{}, err
	}
	for i, limit := range r.Limits {
		sl.purge(limit.Key)
		held := len(s.slots[limit.Key])
		if _, mine := s.slots[limit.Key][r.Holder]; mine {
			held--
		}
		if int64(held) >= limit.Max {
			return admission.SlotGrant{Denied: i}, nil
		}
	}
	for _, limit := range r.Limits {
		if s.slots[limit.Key] == nil {
			s.slots[limit.Key] = map[string]time.Time{}
		}
		s.slots[limit.Key][r.Holder] = s.now.Add(r.TTL)
	}
	return admission.SlotGrant{Granted: true}, nil
}

func (sl slots) Renew(_ context.Context, holder string, ttl time.Duration, keys ...string) (bool, error) {
	s := sl.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return false, err
	}
	for _, key := range keys {
		if exp, ok := s.slots[key][holder]; !ok || !exp.After(s.now) {
			return false, nil
		}
	}
	for _, key := range keys {
		s.slots[key][holder] = s.now.Add(ttl)
	}
	return true, nil
}

func (sl slots) Release(_ context.Context, holder string, keys ...string) error {
	s := sl.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return err
	}
	for _, key := range keys {
		delete(s.slots[key], holder)
	}
	return nil
}

type leader struct{ s *Store }

func (l leader) Acquire(_ context.Context, name, holder string, ttl time.Duration) (admission.LeaseGrant, error) {
	s := l.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return admission.LeaseGrant{}, err
	}
	cur := s.leases[name]
	switch {
	case cur == nil || !cur.expires.After(s.now):
		s.leases[name] = &lease{holder: holder, expires: s.now.Add(ttl)}
		s.fences[name]++
	case cur.holder == holder:
		cur.expires = s.now.Add(ttl)
	default:
		return admission.LeaseGrant{}, nil
	}
	return admission.LeaseGrant{Acquired: true, Fence: s.fences[name]}, nil
}

func (l leader) Renew(_ context.Context, name, holder string, ttl time.Duration) (bool, error) {
	s := l.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return false, err
	}
	cur := s.leases[name]
	if cur == nil || cur.holder != holder || !cur.expires.After(s.now) {
		return false, nil
	}
	cur.expires = s.now.Add(ttl)
	return true, nil
}

func (l leader) Release(_ context.Context, name, holder string) error {
	s := l.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.begin(); err != nil {
		return err
	}
	if cur := s.leases[name]; cur != nil && cur.holder == holder {
		delete(s.leases, name)
	}
	return nil
}
