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
	// Concurrency bounds the restaurants dispatched at once; zero means DefaultConcurrency.
	Concurrency int
	// IterationBudget bounds the time an iteration spends starting dispatches; zero means DefaultIterationBudget.
	IterationBudget time.Duration
}
type schedulerState struct {
	epoch, version string
	unknown        bool
}

// Defaults of the dispatch pool when ScopedOptions leaves its bounds zero.
const (
	DefaultConcurrency     = 8
	DefaultIterationBudget = 10 * time.Second
)

type ScopedRunner struct {
	opts ScopedOptions
	// stateMu guards states and closedScopes: dispatches of one iteration run in parallel.
	stateMu      sync.Mutex
	states       map[string]schedulerState
	closedScopes map[string]bool
	healthMu     sync.Mutex
	health       SchedulerHealth
	loggedState  string
	// resumeAt is the restaurant the next iteration starts with after a budget-cut iteration. Only the
	// iteration goroutine reads and writes it.
	resumeAt string
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

// Concurrency is how many restaurants the scheduler dispatches at once at most.
func (r *ScopedRunner) Concurrency() int { return r.opts.Concurrency }

// IterationBudget is how long an iteration keeps starting dispatches.
func (r *ScopedRunner) IterationBudget() time.Duration { return r.opts.IterationBudget }

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
	if opts.Concurrency < 0 || opts.IterationBudget < 0 {
		return nil, errors.New("scoped scheduler concurrency and iteration budget must not be negative")
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.IterationBudget == 0 {
		opts.IterationBudget = DefaultIterationBudget
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
	var ready []Restaurant
	for _, e := range registry.Entries {
		if schedulerReady(e, status.Epoch, r.opts.GatewayEpoch) {
			ready = append(ready, e.Restaurant)
		}
	}
	return r.dispatchAll(parent, ready, status.Epoch)
}

// dispatchAll runs due for every ready restaurant through a pool of at most Concurrency workers and
// returns after all of them finished. It stops starting new dispatches once IterationBudget of the
// injected clock has passed, and the next iteration then resumes with the first restaurant left
// undone, so a long list never starves its tail. It reports whether every restaurant was reached.
func (r *ScopedRunner) dispatchAll(ctx context.Context, ready []Restaurant, epoch string) bool {
	n := len(ready)
	if n == 0 {
		r.resumeAt = ""
		return true
	}
	first := 0
	for i, restaurant := range ready {
		if restaurant.RestaurantID == r.resumeAt {
			first = i
			break
		}
	}
	begun := r.opts.Now()
	slots := make(chan struct{}, r.opts.Concurrency)
	var workers sync.WaitGroup
	reached := 0
	cut := false
dispatching:
	for ; reached < n; reached++ {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break dispatching
		}
		// The first restaurant always starts, so every iteration makes progress.
		if ctx.Err() != nil || reached > 0 && r.opts.Now().Sub(begun) >= r.opts.IterationBudget {
			<-slots
			cut = ctx.Err() == nil
			break
		}
		restaurant := ready[(first+reached)%n]
		workers.Go(func() {
			defer func() { <-slots }()
			r.due(ctx, restaurant, epoch)
		})
	}
	workers.Wait()
	if reached == n {
		r.resumeAt = ""
		return ctx.Err() == nil
	}
	if cut {
		r.resumeAt = ready[(first+reached)%n].RestaurantID
		r.opts.Logger.Printf("scheduler iteration budget exhausted reached=%d total=%d", reached, n)
	}
	return false
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
	r.stateMu.Lock()
	closed := r.closedScopes[id]
	r.stateMu.Unlock()
	if closed {
		return
	}
	if err := r.opts.Changes.CloseScope(id); err != nil {
		r.opts.Logger.Printf("scheduler scope close unavailable")
		return
	}
	r.stateMu.Lock()
	delete(r.states, id)
	r.closedScopes[id] = true
	r.stateMu.Unlock()
}

// loadState returns what is known of a restaurant's last result for epoch.
func (r *ScopedRunner) loadState(id, epoch string) schedulerState {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	state := r.states[id]
	if state.epoch != epoch {
		return schedulerState{epoch: epoch}
	}
	return state
}

func (r *ScopedRunner) storeState(id string, state schedulerState) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	r.states[id] = state
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
	state := r.loadState(restaurant.RestaurantID, epoch)
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
		r.storeState(restaurant.RestaurantID, state)
		r.opts.Logger.Printf("scheduler due result unavailable")
		return
	}
	if result.Invalidation || state.unknown || (state.version != "" && state.version != result.Version) {
		if err := r.opts.Changes.Append(restaurant.RestaurantID, []string{"stock", "menu", "analytics"}); err != nil {
			r.opts.Logger.Printf("scheduler invalidation unavailable")
			return
		}
	}
	r.storeState(restaurant.RestaurantID, schedulerState{epoch: epoch, version: result.Version})
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
