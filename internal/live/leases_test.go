package live

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type leasePolicy struct{}

func (leasePolicy) StreamLimits(context.Context, string, string) ([]SlotLimit, error) {
	return []SlotLimit{{Key: "sse:s:session", Max: 8}, {Key: "sse:o:org", Max: 200}, {Key: "sse:cell", Max: 2000}}, nil
}

type leaseSlots struct {
	mu       sync.Mutex
	acquires int
	renews   int
	releases int
	grant    SlotGrant
	err      error
	renew    bool
}

func (s *leaseSlots) Acquire(_ context.Context, req SlotRequest) (SlotGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acquires++
	if req.TTL != 30*time.Second || len(req.Limits) != 3 || req.Holder == "" {
		return SlotGrant{}, errors.New("invalid lease request")
	}
	if s.err != nil {
		return SlotGrant{}, s.err
	}
	return s.grant, nil
}
func (s *leaseSlots) Renew(context.Context, string, time.Duration, ...string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renews++
	return s.renew, s.err
}
func (s *leaseSlots) Release(context.Context, string, ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases++
	return s.err
}

func (s *leaseSlots) counts() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acquires, s.renews, s.releases
}

func TestScopedSSEAcquiresSharedLeaseAfterAccessCheck(t *testing.T) {
	f := g4LiveLimits(t, 8, 20, 200)
	f.handler.opts.Clock = SystemClock{}
	slots := &leaseSlots{grant: SlotGrant{Granted: true}, renew: true}
	f.handler.opts.Admission = leasePolicy{}
	f.handler.opts.Slots = slots
	f.handler.opts.LeaseTTL = 30 * time.Second
	f.handler.opts.LeaseRenewInterval = 5 * time.Millisecond
	f.handler.opts.NewLeaseID = func() string { return "test-holder" }
	r := w1Open(t, f, g4Tenant, "actor")
	if r.status != 200 {
		t.Fatalf("stream status %d", r.status)
	}
	deadline := time.Now().Add(time.Second)
	_, renews, _ := slots.counts()
	for renews == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		_, renews, _ = slots.counts()
	}
	acquires, renews, _ := slots.counts()
	if acquires != 1 || renews == 0 {
		t.Fatalf("lease was not acquired and renewed: acquire=%d renew=%d", acquires, renews)
	}
	if err := r.body.Close(); err != nil {
		t.Fatal(err)
	}
	w1WaitFree(t, f)
	_, _, releases := slots.counts()
	if releases != 1 {
		t.Fatalf("lease release count %d", releases)
	}
}

func TestScopedSSERefusesUnavailableOrFullSharedLease(t *testing.T) {
	for name, slots := range map[string]*leaseSlots{
		"unavailable": {err: errors.New("offline")},
		"full":        {grant: SlotGrant{Denied: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			f := g4LiveLimits(t, 8, 20, 200)
			f.handler.opts.Clock = SystemClock{}
			f.handler.opts.Admission = leasePolicy{}
			f.handler.opts.Slots = slots
			f.handler.opts.LeaseTTL = 30 * time.Second
			f.handler.opts.LeaseRenewInterval = 5 * time.Millisecond
			f.handler.opts.NewLeaseID = func() string { return "test-holder" }
			r := w1Open(t, f, g4Tenant, "actor")
			want := 503
			if name == "full" {
				want = 429
			}
			acquires, _, _ := slots.counts()
			if r.status != want || acquires != 1 {
				t.Fatalf("lease refusal: status=%d acquire=%d body=%v", r.status, acquires, r.body)
			}
			w1WaitFree(t, f)
		})
	}
}

func TestScopedSSEClosesWhenSharedLeaseRenewalIsLost(t *testing.T) {
	f := g4LiveLimits(t, 8, 20, 200)
	f.handler.opts.Clock = SystemClock{}
	slots := &leaseSlots{grant: SlotGrant{Granted: true}, renew: false}
	f.handler.opts.Admission = leasePolicy{}
	f.handler.opts.Slots = slots
	f.handler.opts.LeaseTTL = 30 * time.Second
	f.handler.opts.LeaseRenewInterval = 5 * time.Millisecond
	f.handler.opts.NewLeaseID = func() string { return "test-holder" }
	if r := w1Open(t, f, g4Tenant, "actor"); r.status != 200 {
		t.Fatalf("stream status %d", r.status)
	}
	w1WaitFree(t, f)
	_, renews, releases := slots.counts()
	if renews == 0 || releases != 1 {
		t.Fatalf("lost lease was not stopped and released: renews=%d releases=%d", renews, releases)
	}
}
