package expiration

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestG5UnknownRecoveryWithoutNewTransitions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		known   bool
		version string
	}{
		{name: "prior_known_version", known: true, version: "2"},
		{name: "first_observation_unknown", version: "2"},
		{name: "unchanged_version", known: true, version: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := schedulerFixture()
			r := newSchedulerTest(t, p)
			if tc.known {
				r.tick(context.Background())
			}
			p.dueErr = errors.New("reply lost before expiry committed")
			r.tick(context.Background())
			p.result = DueResult{Epoch: warehouseEpoch, Version: tc.version}
			r.tick(context.Background())
			if !slices.Equal(p.changes, []string{tenantA}) {
				t.Fatalf("repeated unknown polls must invalidate only once: %v", p.changes)
			}
			p.dueErr = nil
			r.tick(context.Background())
			if !slices.Equal(p.changes, []string{tenantA, tenantA}) {
				t.Fatalf("recovery without new transitions must invalidate again: %v", p.changes)
			}
			r.tick(context.Background())
			if len(p.changes) != 2 {
				t.Fatalf("known unchanged poll invalidated again: %v", p.changes)
			}
		})
	}
}

type recoveryChanges struct {
	*schedulerPeer
	fail   bool
	topics [][]string
}

func (c *recoveryChanges) Append(restaurantID string, topics []string) error {
	if c.fail {
		return errors.New("journal unavailable")
	}
	c.topics = append(c.topics, slices.Clone(topics))
	return c.schedulerPeer.Append(restaurantID, topics)
}

func TestG5UnknownRecoveryRetriesFailedInvalidation(t *testing.T) {
	p := schedulerFixture()
	c := &recoveryChanges{schedulerPeer: p}
	r := newSchedulerTest(t, p)
	r.opts.Changes = c
	r.tick(context.Background())
	p.dueErr = errors.New("reply lost")
	r.tick(context.Background())
	p.dueErr = nil
	p.result = DueResult{Epoch: warehouseEpoch, Version: "2"}
	c.fail = true
	r.tick(context.Background())
	if !slices.Equal(p.changes, []string{tenantA}) {
		t.Fatalf("failed append published an invalidation: %v", p.changes)
	}
	c.fail = false
	r.tick(context.Background())
	if !slices.Equal(p.changes, []string{tenantA, tenantA}) {
		t.Fatalf("failed recovery append advanced the watermark: %v", p.changes)
	}
	for _, topics := range c.topics {
		if !slices.Equal(topics, []string{"stock", "menu", "analytics"}) {
			t.Fatalf("recovery omitted affected views: %v", topics)
		}
	}
	r.tick(context.Background())
	if len(p.changes) != 2 {
		t.Fatalf("successful recovery failed to save the watermark: %v", p.changes)
	}
}
