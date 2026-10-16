package live

import (
	"context"
	"time"
)

type SlotLimit struct {
	Key string
	Max int64
}

type SlotRequest struct {
	Holder string
	TTL    time.Duration
	Limits []SlotLimit
}

type SlotGrant struct {
	Granted bool
	Denied  int
}

type LeasePolicy interface {
	StreamLimits(context.Context, string, string) ([]SlotLimit, error)
}

type Slots interface {
	Acquire(context.Context, SlotRequest) (SlotGrant, error)
	Renew(context.Context, string, time.Duration, ...string) (bool, error)
	Release(context.Context, string, ...string) error
}
