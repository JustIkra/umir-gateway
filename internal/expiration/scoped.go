package expiration

import (
	"context"
	"errors"
	"log"
	"time"
)

type ServiceRequest struct {
	RestaurantID string `json:"restaurantID"`
	Operation    string `json:"operation"`
	Epoch        string `json:"epoch"`
}
type Credential struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type Restaurant struct {
	RestaurantID     string `json:"restaurantID"`
	OrgID            string `json:"orgID"`
	Lifecycle        string `json:"lifecycle"`
	LifecycleVersion string `json:"lifecycleVersion"`
}
type Readiness struct {
	RestaurantID     string `json:"restaurantID"`
	Service          string `json:"service"`
	Epoch            string `json:"epoch"`
	State            string `json:"state"`
	LifecycleVersion string `json:"lifecycleVersion"`
}
type RegistryEntry struct {
	Settings struct {
		TimeZone string `json:"timeZone"`
		Version  string `json:"settingsVersion"`
	} `json:"settings"`
	Restaurant Restaurant  `json:"restaurant"`
	Services   []Readiness `json:"services"`
}
type Tombstone struct {
	RestaurantID     string `json:"restaurantID"`
	OrgID            string `json:"orgID"`
	LifecycleVersion string `json:"lifecycleVersion"`
}
type Registry struct {
	Complete   bool            `json:"complete"`
	Entries    []RegistryEntry `json:"entries"`
	Tombstones []Tombstone     `json:"tombstones"`
}
type RuntimeStatus struct {
	Service string `json:"service"`
	Epoch   string `json:"epoch"`
	Ready   bool   `json:"ready"`
}
type DueRequest struct{ RestaurantID, OrgID, Epoch, Token, RunID string }
type DueFailure struct {
	Status  int
	Outcome string
	Cause   error
}

func (e *DueFailure) Error() string { return "scheduler dispatch failed: " + e.Outcome }
func (e *DueFailure) Unwrap() error { return e.Cause }

type DueResult struct {
	Epoch, Version string
	Invalidation   bool
	FinalWriteoffs int
}
type SchedulerAuth interface {
	Registry(context.Context) (Registry, error)
	ServiceToken(context.Context, ServiceRequest) (Credential, error)
}
type SchedulerWarehouse interface {
	Status(context.Context) (RuntimeStatus, error)
	Due(context.Context, DueRequest) (DueResult, error)
}
type ScopedChanges interface {
	Append(string, []string) error
	ObserveRuntime(string, string, string) error
	CloseScope(string) error
}
type ScopedOptions struct {
	GatewayEpoch       string
	Auth               SchedulerAuth
	Warehouse          SchedulerWarehouse
	Changes            ScopedChanges
	Interval, Timeout  time.Duration
	Now                func() time.Time
	NewRunID           func() (string, error)
	NewTicker          func(time.Duration) (<-chan time.Time, func())
	IterationCompleted chan<- uint64
	Logger             *log.Logger
}
type schedulerState struct {
	epoch, version string
	unknown        bool
}
type ScopedRunner struct {
	opts         ScopedOptions
	states       map[string]schedulerState
	closedScopes map[string]bool
}

func NewScoped(opts ScopedOptions) (*ScopedRunner, error) {
	if opts.Auth == nil || opts.Warehouse == nil || opts.Changes == nil || opts.Interval <= 0 || opts.Timeout <= 0 || opts.Now == nil || opts.NewRunID == nil || opts.NewTicker == nil || opts.Logger == nil {
		return nil, errors.New("scoped scheduler dependencies and bounds required")
	}
	opts.Timeout = min(opts.Timeout, 5*time.Second)
	return &ScopedRunner{opts: opts, states: map[string]schedulerState{}, closedScopes: map[string]bool{}}, nil
}
func (r *ScopedRunner) Run(ctx context.Context) {
	ticks, stop := r.opts.NewTicker(r.opts.Interval)
	defer stop()
	if ctx.Err() != nil {
		return
	}
	var sequence uint64
	iteration := func() {
		sequence++
		defer r.observeIteration(sequence)
		r.tick(ctx)
	}
	iteration()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			iteration()
		}
	}
}
func (r *ScopedRunner) observeIteration(sequence uint64) {
	// A closed advisory port is a dropped observation; scheduler panics remain outside this helper.
	defer func() {
		if recover() != nil {
			return
		}
	}()
	select {
	case r.opts.IterationCompleted <- sequence:
	default:
	}
}
func (r *ScopedRunner) tick(parent context.Context) {
	if parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, r.opts.Timeout)
	registry, err := r.opts.Auth.Registry(ctx)
	cancel()
	if err != nil || !registry.Complete {
		r.opts.Logger.Printf("scheduler registry unavailable")
		return
	}
	if err := registry.Validate(); err != nil {
		r.opts.Logger.Printf("scheduler registry inconsistent")
		return
	}
	for _, t := range registry.Tombstones {
		r.closeScope(t.RestaurantID)
	}
	for _, e := range registry.Entries {
		if e.Restaurant.Lifecycle == "deleting" || e.Restaurant.Lifecycle == "deleted" {
			r.closeScope(e.Restaurant.RestaurantID)
		}
	}
	ctx, cancel = context.WithTimeout(parent, r.opts.Timeout)
	status, err := r.opts.Warehouse.Status(ctx)
	cancel()
	if err != nil || status.Service != "warehouse" || !status.Ready || status.Epoch == "" {
		r.opts.Logger.Printf("scheduler Warehouse unavailable")
		return
	}
	for _, e := range registry.Entries {
		if parent.Err() != nil {
			return
		}
		if !schedulerReady(e, status.Epoch, r.opts.GatewayEpoch) {
			continue
		}
		r.due(parent, e.Restaurant, status.Epoch)
	}
}
func schedulerReady(e RegistryEntry, epoch, gatewayEpoch string) bool {
	if e.Restaurant.Lifecycle != "ready" {
		return false
	}
	found := false
	seen := map[string]bool{}
	for _, s := range e.Services {
		if seen[s.Service] || s.RestaurantID != e.Restaurant.RestaurantID || s.LifecycleVersion != e.Restaurant.LifecycleVersion {
			return false
		}
		seen[s.Service] = true
		if s.State != "ready" {
			return false
		}
		if s.Service == "gateway" && gatewayEpoch != "" && s.Epoch != gatewayEpoch {
			return false
		}
		if s.Service == "warehouse" {
			if s.State != "ready" || s.Epoch != epoch {
				return false
			}
			found = true
		}
	}
	return found && (gatewayEpoch == "" || (seen["gateway"] && seen["serving"]))
}
func (r *ScopedRunner) closeScope(id string) {
	if r.closedScopes[id] {
		return
	}
	if err := r.opts.Changes.CloseScope(id); err != nil {
		r.opts.Logger.Printf("scheduler scope close unavailable")
		return
	}
	delete(r.states, id)
	r.closedScopes[id] = true
}
func (r *ScopedRunner) due(parent context.Context, restaurant Restaurant, epoch string) {
	ctx, cancel := context.WithTimeout(parent, r.opts.Timeout)
	defer cancel()
	credential, err := r.opts.Auth.ServiceToken(ctx, ServiceRequest{RestaurantID: restaurant.RestaurantID, Operation: "expiry.due", Epoch: epoch})
	if err != nil || credential.Token == "" || !r.opts.Now().Before(credential.ExpiresAt) {
		r.opts.Logger.Printf("scheduler credential unavailable")
		return
	}
	runID, err := r.opts.NewRunID()
	if err != nil || runID == "" {
		r.opts.Logger.Printf("scheduler run identity unavailable")
		return
	}
	if err := r.opts.Changes.ObserveRuntime(restaurant.RestaurantID, "warehouse", epoch); err != nil {
		r.opts.Logger.Printf("scheduler journal unavailable")
		return
	}
	state := r.states[restaurant.RestaurantID]
	if state.epoch != epoch {
		state = schedulerState{epoch: epoch}
	}
	result, err := r.opts.Warehouse.Due(ctx, DueRequest{RestaurantID: restaurant.RestaurantID, OrgID: restaurant.OrgID, Epoch: epoch, Token: credential.Token, RunID: runID})
	if err != nil || result.Epoch != epoch || !validVersion(result.Version) || result.FinalWriteoffs != 0 {
		var failure *DueFailure
		if errors.As(err, &failure) && failure.Outcome == "not_committed" {
			r.opts.Logger.Printf("scheduler dispatch rejected")
			return
		}
		if !state.unknown {
			if err := r.opts.Changes.Append(restaurant.RestaurantID, []string{"stock", "menu", "analytics"}); err == nil {
				state.unknown = true
			} else {
				r.opts.Logger.Printf("scheduler invalidation unavailable")
			}
		}
		r.states[restaurant.RestaurantID] = state
		r.opts.Logger.Printf("scheduler due result unavailable")
		return
	}
	if result.Invalidation || state.unknown || (state.version != "" && state.version != result.Version) {
		if err := r.opts.Changes.Append(restaurant.RestaurantID, []string{"stock", "menu", "analytics"}); err != nil {
			r.opts.Logger.Printf("scheduler invalidation unavailable")
			return
		}
	}
	r.states[restaurant.RestaurantID] = schedulerState{epoch: epoch, version: result.Version}
}

func (r Registry) Validate() error {
	if !r.Complete || len(r.Entries) > 10000 || len(r.Tombstones) > 10000 {
		return errors.New("incomplete registry")
	}
	entries := map[string]Restaurant{}
	for _, e := range r.Entries {
		id := e.Restaurant.RestaurantID
		if id == "" || entries[id].RestaurantID != "" {
			return errors.New("duplicate registry entry")
		}
		entries[id] = e.Restaurant
		peers := map[string]bool{}
		for _, s := range e.Services {
			if peers[s.Service] || s.RestaurantID != id || s.LifecycleVersion != e.Restaurant.LifecycleVersion {
				return errors.New("inconsistent peer association")
			}
			peers[s.Service] = true
		}
	}
	deleted := map[string]bool{}
	for _, t := range r.Tombstones {
		if t.RestaurantID == "" || deleted[t.RestaurantID] {
			return errors.New("duplicate tombstone")
		}
		deleted[t.RestaurantID] = true
		if e, ok := entries[t.RestaurantID]; ok && (e.Lifecycle != "deleting" && e.Lifecycle != "deleted" || e.OrgID != t.OrgID || e.LifecycleVersion != t.LifecycleVersion) {
			return errors.New("inconsistent tombstone")
		}
	}
	return nil
}
