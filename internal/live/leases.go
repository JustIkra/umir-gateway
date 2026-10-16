package live

import (
	"context"
	"time"

	"github.com/JustIkra/umir-gateway/internal/admission"
)

type streamLease struct {
	holder string
	keys   []string
	ttl    time.Duration
}

func (h *Handler) acquireLease(ctx context.Context, session, org string) (streamLease, admission.SlotGrant, error) {
	limits, err := h.opts.Admission.StreamLimits(ctx, session, org)
	if err != nil {
		return streamLease{}, admission.SlotGrant{}, err
	}
	holder := h.opts.NewLeaseID()
	if holder == "" {
		return streamLease{}, admission.SlotGrant{}, admission.ErrUnavailable
	}
	request := admission.SlotRequest{Holder: holder, TTL: h.opts.LeaseTTL, Limits: limits}
	grant, err := h.opts.Slots.Acquire(ctx, request)
	if err != nil {
		return streamLease{}, admission.SlotGrant{}, err
	}
	lease := streamLease{holder: holder, ttl: h.opts.LeaseTTL}
	for _, limit := range limits {
		lease.keys = append(lease.keys, limit.Key)
	}
	return lease, grant, nil
}

func (h *Handler) renewLease(ctx context.Context, cancel context.CancelFunc, lease streamLease, done chan<- struct{}) {
	defer close(done)
	for {
		timer := h.opts.Clock.NewTimer(h.opts.LeaseRenewInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
		ok, err := h.opts.Slots.Renew(ctx, lease.holder, lease.ttl, lease.keys...)
		if err != nil || !ok {
			h.opts.Logger.Print("scoped SSE lease renewal failed")
			cancel()
			return
		}
	}
}

func (h *Handler) releaseLease(lease streamLease) {
	ctx, cancel := context.WithTimeout(context.Background(), h.opts.LeaseRenewInterval)
	defer cancel()
	if err := h.opts.Slots.Release(ctx, lease.holder, lease.keys...); err != nil {
		h.opts.Logger.Print("scoped SSE lease release failed")
	}
}
