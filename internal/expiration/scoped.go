package expiration

import (
	"context"
	"errors"
	"log"
	"sync"
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
	healthMu     sync.Mutex
	health       SchedulerHealth
	loggedState  string
}

// SchedulerHealth summarizes the iterations of the scheduler: when the last one started, when one last
// succeeded, how long the last finished one took and how many failed in a row. An iteration succeeds
// when it obtained a usable registry and a ready Warehouse and reached every restaurant; a single
// restaurant's failed dispatch does not fail it.
type SchedulerHealth struct {
	LastStart, LastSuccess time.Time
	LastDuration           time.Duration
	ConsecutiveFailures    int
}

// Scheduler states reported through readiness.
const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateDown     = "down"
)

// Lag thresholds in scheduler intervals since the last successful iteration, and the number of
// failed iterations in a row with no success at all that mean the scheduler is down.
const (
	degradedLagIntervals = 3
	downLagIntervals     = 10
	downStartupFailures  = 3
)

// State classifies the scheduler at now for an iteration pace of interval.
func (h SchedulerHealth) State(now time.Time, interval time.Duration) string {
	if h.LastSuccess.IsZero() {
		if h.ConsecutiveFailures >= downStartupFailures {
			return StateDown
		}
		return StateDegraded
	}
	lag := max(now.Sub(h.LastSuccess), 0)
	switch {
	case lag > downLagIntervals*interval:
		return StateDown
	case lag > degradedLagIntervals*interval || h.ConsecutiveFailures > 0:
		return StateDegraded
	}
	return StateOK
}

// Health returns the current iteration summary.
func (r *ScopedRunner) Health() SchedulerHealth {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	return r.health
}

// Interval is the pace the scheduler is configured to run at.
func (r *ScopedRunner) Interval() time.Duration { return r.opts.Interval }

func (r *ScopedRunner) runIteration(ctx context.Context) {
	start := r.opts.Now()
	r.healthMu.Lock()
	r.health.LastStart = start
	r.healthMu.Unlock()
	succeeded := r.tick(ctx)
	if ctx.Err() != nil {
		// An iteration cut short by shutdown says nothing about the scheduler.
		return
	}
	end := r.opts.Now()
	r.healthMu.Lock()
	r.health.LastDuration = end.Sub(start)
	if succeeded {
		r.health.LastSuccess, r.health.ConsecutiveFailures = end, 0
	} else {
		r.health.ConsecutiveFailures++
	}
	health := r.health
	r.healthMu.Unlock()
	r.logStateChange(health, end)
}

// logStateChange writes one line when the scheduler state differs from the last one logged. Only the
// iteration goroutine calls it. The line carries times, a duration and a count, never a value.
func (r *ScopedRunner) logStateChange(h SchedulerHealth, now time.Time) {
	state := h.State(now, r.opts.Interval)
	if state == r.loggedState {
		return
	}
	r.loggedState = state
	r.opts.Logger.Printf("event=scheduler_state state=%s last_start=%s last_success=%s last_duration=%s consecutive_failures=%d", state, formatInstant(h.LastStart), formatInstant(h.LastSuccess), h.LastDuration, h.ConsecutiveFailures)
}

func formatInstant(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
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
		r.runIteration(ctx)
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
func (r *ScopedRunner) tick(parent context.Context) bool {
	if parent.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(parent, r.opts.Timeout)
	registry, err := r.opts.Auth.Registry(ctx)
	cancel()
	if err != nil || !registry.Complete {
		r.opts.Logger.Printf("scheduler registry unavailable")
		return false
	}
	if err := registry.Validate(); err != nil {
		r.opts.Logger.Printf("scheduler registry inconsistent")
		return false
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
		return false
	}
	for _, e := range registry.Entries {
		if parent.Err() != nil {
			return false
		}
		if !schedulerReady(e, status.Epoch, r.opts.GatewayEpoch) {
			continue
		}
		r.due(parent, e.Restaurant, status.Epoch)
	}
	return true
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
