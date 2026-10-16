// Package contract holds the behavior every implementation of the admission ports must show. The Redis
// adapter and the in-memory test double run the same suites, so the double cannot drift from Redis.
//
// It is imported by tests only; the production binary does not link it.
package contract

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/admission"
)

// Window is the base window of the suites. A real store is run with it as it is, so it is short.
const Window = 400 * time.Millisecond

// Env is what a suite needs besides the implementation: a way to let time pass. A fake clock moves at
// once, a real store sleeps.
type Env struct {
	// Advance lets d pass. It may sleep.
	Advance func(d time.Duration)
	// Prefix makes the keys of one test unique inside a shared store.
	Prefix string
}

func (e Env) key(name string) string { return e.Prefix + name }

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func admit(t *testing.T, l admission.Limiter, r admission.Request) admission.Decision {
	t.Helper()
	d, err := l.Admit(ctx(t), r)
	if err != nil {
		t.Fatalf("admit %s: %v", r.ID, err)
	}
	return d
}

func slotAcquire(t *testing.T, s admission.Slots, r admission.SlotRequest) admission.SlotGrant {
	t.Helper()
	g, err := s.Acquire(ctx(t), r)
	if err != nil {
		t.Fatalf("acquire %s: %v", r.Holder, err)
	}
	return g
}

func leaderAcquire(t *testing.T, l admission.Leader, name, holder string, ttl time.Duration) admission.LeaseGrant {
	t.Helper()
	g, err := l.Acquire(ctx(t), name, holder, ttl)
	if err != nil {
		t.Fatalf("acquire %s: %v", holder, err)
	}
	return g
}

func one(id, fingerprint string, dims ...admission.Dimension) admission.Request {
	return admission.Request{ID: id, Fingerprint: fingerprint, Policy: "contract", Dimensions: dims}
}

// Limiter runs the suite for admission.Limiter. newLimiter is called once per test.
func Limiter(t *testing.T, newLimiter func(t *testing.T) (admission.Limiter, Env)) {
	t.Run("the last slot goes to exactly one of many concurrent callers", func(t *testing.T) {
		l, env := newLimiter(t)
		dim := admission.Dimension{Key: env.key("last"), Limit: 5, Window: 10 * time.Second}
		var allowed atomic.Int64
		var wg sync.WaitGroup
		for i := range 64 {
			wg.Go(func() {
				d, err := l.Admit(ctx(t), one("id-"+string(rune('A'+i%26))+string(rune('a'+i/26)), "fp", dim))
				if err != nil {
					t.Errorf("admit: %v", err)
					return
				}
				if d.Allowed {
					allowed.Add(1)
				}
			})
		}
		wg.Wait()
		if allowed.Load() != 5 {
			t.Fatalf("allowed %d of 64, want exactly 5", allowed.Load())
		}
	})

	t.Run("a window ends on its own and a refusal does not extend it", func(t *testing.T) {
		l, env := newLimiter(t)
		dim := admission.Dimension{Key: env.key("window"), Limit: 1, Window: Window}
		if d := admit(t, l, one("a", "fp", dim)); !d.Allowed {
			t.Fatal("first attempt refused")
		}
		env.Advance(Window / 2)
		d := admit(t, l, one("b", "fp", dim))
		if d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > Window {
			t.Fatalf("second attempt: %+v", d)
		}
		env.Advance(Window/2 + Window/4)
		if d := admit(t, l, one("c", "fp", dim)); !d.Allowed {
			t.Fatalf("the window must have ended with the first charge, not with the refusal: %+v", d)
		}
	})

	t.Run("a repeat of the same attempt is not charged and not refused", func(t *testing.T) {
		l, env := newLimiter(t)
		dim := admission.Dimension{Key: env.key("replay"), Limit: 1, Window: 10 * time.Second}
		if d := admit(t, l, one("same", "fp", dim)); !d.Allowed || d.Replay {
			t.Fatalf("first: %+v", d)
		}
		for range 3 {
			if d := admit(t, l, one("same", "fp", dim)); !d.Allowed || !d.Replay {
				t.Fatalf("repeat: %+v", d)
			}
		}
		if d := admit(t, l, one("other", "fp", dim)); d.Allowed {
			t.Fatal("the budget must still be spent once")
		}
	})

	t.Run("the same ID with another fingerprint is a conflict and charges nothing", func(t *testing.T) {
		l, env := newLimiter(t)
		dim := admission.Dimension{Key: env.key("conflict"), Limit: 2, Window: 10 * time.Second}
		admit(t, l, one("id", "first", dim))
		if _, err := l.Admit(ctx(t), one("id", "second", dim)); !errors.Is(err, admission.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
		if d := admit(t, l, one("fresh", "fp", dim)); !d.Allowed {
			t.Fatal("the conflict must not have spent the second slot")
		}
	})

	t.Run("a refused attempt leaves no trace in the other dimensions", func(t *testing.T) {
		l, env := newLimiter(t)
		a := admission.Dimension{Key: env.key("shared"), Limit: 1, Window: 10 * time.Second}
		b := admission.Dimension{Key: env.key("own"), Limit: 1, Window: 10 * time.Second}
		admit(t, l, one("x1", "fp", a))
		d := admit(t, l, one("x2", "fp", b, a))
		if d.Allowed || d.Dimension != 1 {
			t.Fatalf("want a refusal by dimension 1, got %+v", d)
		}
		if d := admit(t, l, one("x3", "fp", b)); !d.Allowed {
			t.Fatal("dimension b was charged by a refused attempt")
		}
	})

	t.Run("the refusal names the dimension that frees last", func(t *testing.T) {
		l, env := newLimiter(t)
		short := admission.Dimension{Key: env.key("short"), Limit: 1, Window: Window}
		long := admission.Dimension{Key: env.key("long"), Limit: 1, Window: 20 * time.Second}
		admit(t, l, one("s", "fp", short))
		admit(t, l, one("l", "fp", long))
		d := admit(t, l, one("both", "fp", short, long))
		if d.Allowed || d.Dimension != 1 || d.RetryAfter < 10*time.Second {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("an admission record ends with the longest window", func(t *testing.T) {
		l, env := newLimiter(t)
		dim := admission.Dimension{Key: env.key("record"), Limit: 1, Window: Window}
		admit(t, l, one("again", "fp", dim))
		env.Advance(Window + Window/2)
		if d := admit(t, l, one("again", "fp", dim)); !d.Allowed || d.Replay {
			t.Fatalf("after the window the same ID is a new attempt: %+v", d)
		}
	})
}

// Slots runs the suite for admission.Slots.
func Slots(t *testing.T, newSlots func(t *testing.T) (admission.Slots, Env)) {
	t.Run("the last slot goes to exactly max of many concurrent holders", func(t *testing.T) {
		s, env := newSlots(t)
		var granted atomic.Int64
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Go(func() {
				g, err := s.Acquire(ctx(t), admission.SlotRequest{Holder: "h" + string(rune('A'+i)), TTL: 10 * time.Second, Limits: []admission.SlotLimit{{Key: env.key("sse:last"), Max: 3}}})
				if err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				if g.Granted {
					granted.Add(1)
				}
			})
		}
		wg.Wait()
		if granted.Load() != 3 {
			t.Fatalf("granted %d, want exactly 3", granted.Load())
		}
	})

	t.Run("a holder is counted once and release is idempotent", func(t *testing.T) {
		s, env := newSlots(t)
		key := env.key("sse:once")
		req := func(h string) admission.SlotRequest {
			return admission.SlotRequest{Holder: h, TTL: 10 * time.Second, Limits: []admission.SlotLimit{{Key: key, Max: 1}}}
		}
		for range 2 {
			if g, err := s.Acquire(ctx(t), req("a")); err != nil || !g.Granted {
				t.Fatalf("a: %+v %v", g, err)
			}
		}
		if g := slotAcquire(t, s, req("b")); g.Granted {
			t.Fatal("b took a slot that a holds")
		}
		for range 2 {
			if err := s.Release(ctx(t), "a", key); err != nil {
				t.Fatal(err)
			}
		}
		if g := slotAcquire(t, s, req("b")); !g.Granted {
			t.Fatal("the slot was not freed")
		}
	})

	t.Run("all keys or none", func(t *testing.T) {
		s, env := newSlots(t)
		full, free := env.key("sse:full"), env.key("sse:free")
		slotAcquire(t, s, admission.SlotRequest{Holder: "x", TTL: 10 * time.Second, Limits: []admission.SlotLimit{{Key: full, Max: 1}}})
		g, err := s.Acquire(ctx(t), admission.SlotRequest{Holder: "y", TTL: 10 * time.Second, Limits: []admission.SlotLimit{{Key: free, Max: 1}, {Key: full, Max: 1}}})
		if err != nil || g.Granted || g.Denied != 1 {
			t.Fatalf("%+v %v", g, err)
		}
		if g := slotAcquire(t, s, admission.SlotRequest{Holder: "z", TTL: 10 * time.Second, Limits: []admission.SlotLimit{{Key: free, Max: 1}}}); !g.Granted {
			t.Fatal("a refused acquire occupied the free key")
		}
	})

	t.Run("a lost lease fails the renewal and a stale holder frees nothing", func(t *testing.T) {
		s, env := newSlots(t)
		key := env.key("sse:stale")
		take := func(h string) admission.SlotGrant {
			g, err := s.Acquire(ctx(t), admission.SlotRequest{Holder: h, TTL: Window, Limits: []admission.SlotLimit{{Key: key, Max: 1}}})
			if err != nil {
				t.Fatal(err)
			}
			return g
		}
		if !take("old").Granted {
			t.Fatal("old")
		}
		if ok, err := s.Renew(ctx(t), "old", Window, key); err != nil || !ok {
			t.Fatalf("renew while held: %v %v", ok, err)
		}
		env.Advance(2 * Window)
		if ok, err := s.Renew(ctx(t), "old", Window, key); err != nil || ok {
			t.Fatal("an expired lease was renewed")
		}
		if !take("new").Granted {
			t.Fatal("the expired holder still occupies the slot")
		}
		if err := s.Release(ctx(t), "old", key); err != nil {
			t.Fatal(err)
		}
		if take("third").Granted {
			t.Fatal("the stale holder released the slot of its successor")
		}
	})
}

// Leader runs the suite for admission.Leader.
func Leader(t *testing.T, newLeader func(t *testing.T) (admission.Leader, Env)) {
	t.Run("one holder at a time, fence grows with each takeover", func(t *testing.T) {
		l, env := newLeader(t)
		name := env.key("lease")
		a, err := l.Acquire(ctx(t), name, "a", Window)
		if err != nil || !a.Acquired || a.Fence < 1 {
			t.Fatalf("a: %+v %v", a, err)
		}
		if b := leaderAcquire(t, l, name, "b", Window); b.Acquired {
			t.Fatal("two holders")
		}
		if again := leaderAcquire(t, l, name, "a", Window); !again.Acquired || again.Fence != a.Fence {
			t.Fatalf("the holder keeps its fence: %+v", again)
		}
		env.Advance(2 * Window)
		b, err := l.Acquire(ctx(t), name, "b", Window)
		if err != nil || !b.Acquired || b.Fence <= a.Fence {
			t.Fatalf("takeover: %+v %v", b, err)
		}
	})

	t.Run("renewal and release belong to the holder", func(t *testing.T) {
		l, env := newLeader(t)
		name := env.key("owned")
		leaderAcquire(t, l, name, "a", 10*time.Second)
		if ok, err := l.Renew(ctx(t), name, "b", 10*time.Second); err != nil || ok {
			t.Fatal("a stranger renewed")
		}
		if ok, err := l.Renew(ctx(t), name, "a", 10*time.Second); err != nil || !ok {
			t.Fatalf("holder renewal: %v %v", ok, err)
		}
		if err := l.Release(ctx(t), name, "b"); err != nil {
			t.Fatal(err)
		}
		if b := leaderAcquire(t, l, name, "b", 10*time.Second); b.Acquired {
			t.Fatal("a stranger released the lease")
		}
		if err := l.Release(ctx(t), name, "a"); err != nil {
			t.Fatal(err)
		}
		first := leaderAcquire(t, l, name, "b", 10*time.Second)
		if !first.Acquired || first.Fence < 2 {
			t.Fatalf("after release: %+v", first)
		}
	})

	t.Run("an expired lease cannot be renewed", func(t *testing.T) {
		l, env := newLeader(t)
		name := env.key("expired")
		leaderAcquire(t, l, name, "a", Window)
		env.Advance(2 * Window)
		if ok, err := l.Renew(ctx(t), name, "a", Window); err != nil || ok {
			t.Fatal("renewed after expiry")
		}
	})
}
