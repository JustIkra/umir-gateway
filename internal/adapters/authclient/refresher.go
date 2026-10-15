package authclient

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/JustIkra/umir-gateway/internal/expiration"
)

// RefresherOptions configures a RegistryRefresher.
type RefresherOptions struct {
	Client    *Client
	Interval  time.Duration
	NewTicker func(time.Duration) (<-chan time.Time, func())
	Logger    *log.Logger
}

// RegistryRefresher reads the Auth registry on its own schedule so that runtime readiness and the
// expiration scheduler depend on the last successful snapshot and never on each other's pace.
type RegistryRefresher struct {
	client    *Client
	interval  time.Duration
	newTicker func(time.Duration) (<-chan time.Time, func())
	logger    *log.Logger
}

func NewRegistryRefresher(opts RefresherOptions) (*RegistryRefresher, error) {
	if opts.Client == nil || opts.Interval <= 0 || opts.NewTicker == nil || opts.Logger == nil {
		return nil, errors.New("authclient: refresher client, positive interval, ticker and logger required")
	}
	return &RegistryRefresher{client: opts.Client, interval: opts.Interval, newTicker: opts.NewTicker, logger: opts.Logger}, nil
}

// Run reads the registry at start and then at every interval until ctx ends; a read in flight is
// cancelled with ctx and Run returns only after it. A failed read keeps the previous snapshot: the
// snapshot expires by age. The log carries the change of state, never a value.
func (r *RegistryRefresher) Run(ctx context.Context) {
	ticks, stop := r.newTicker(r.interval)
	defer stop()
	healthy := true
	refresh := func() {
		if ctx.Err() != nil {
			return
		}
		_, err := r.client.Registry(ctx)
		switch {
		case ctx.Err() != nil:
		case err != nil && healthy:
			healthy = false
			r.logger.Printf("registry refresh unavailable")
		case err == nil && !healthy:
			healthy = true
			r.logger.Printf("registry refresh recovered")
		}
	}
	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			refresh()
		}
	}
}

// Registry serves the scheduler the refresher's snapshot instead of a read of its own.
func (r *RegistryRefresher) Registry(context.Context) (expiration.Registry, error) {
	snapshot, ok := r.client.RegistrySnapshot()
	if !ok {
		return expiration.Registry{}, errors.New("registry snapshot unavailable")
	}
	return snapshot, nil
}
