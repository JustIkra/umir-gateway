package journal

import (
	"errors"
	"slices"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	TopicsAll    = "all"
	TopicsEvent  = "event"
	eventIDLimit = 4096
)

type Change struct {
	Sequence int64
	Topics   []string
}

type Snapshot struct {
	Epoch      string
	Changes    []Change
	Last       int64
	Refresh    bool
	Closed     bool
	Generation uint64
}

type scopeJournal struct {
	// ring is allocated by the first Append and released when the scope is reset.
	ring           []Change
	last           int64
	generation     uint64
	subscribers    map[chan struct{}]struct{}
	orgID          string
	authGeneration string
	lastActivity   time.Time
	owners         map[string]ownerState
}

type CursorPosition struct {
	Tenant     string    `json:"t"`
	Actor      string    `json:"a"`
	Epoch      string    `json:"e"`
	Sequence   int64     `json:"s"`
	Generation uint64    `json:"g"`
	Expires    time.Time `json:"x"`
}

type CursorCodec interface {
	Encode(CursorPosition) (string, error)
	Decode(string) (CursorPosition, error)
}

type Event struct {
	EventID           string    `json:"eventID"`
	Owner             string    `json:"owner"`
	SchemaVersion     int       `json:"schemaVersion"`
	OrgID             string    `json:"orgID"`
	RestaurantID      string    `json:"restaurantID,omitempty"`
	AggregateID       string    `json:"aggregateID"`
	AggregateRevision int64     `json:"aggregateRevision"`
	Generation        string    `json:"generation"`
	OccurredAt        time.Time `json:"occurredAt"`
	CorrelationID     string    `json:"correlationID,omitempty"`
	CausationID       string    `json:"causationID,omitempty"`
	Topics            []string  `json:"topics,omitempty"`
	Type              string    `json:"-"`
}

type ScopedOptions struct {
	Epoch           string
	Capacity        int
	MaxScopes       int
	MaxClosedScopes int
	MaxCursors      int
	RingIdle        time.Duration
	TopicsMode      string
	Now             func() time.Time
	NewCursor       func() string
	Codec           CursorCodec
}

type ownerState struct {
	generation  string
	revision    int64
	hasRevision bool
}

type Scoped struct {
	mu                              sync.Mutex
	epoch                           string
	capacity, maxScopes, maxCursors int
	maxClosedScopes                 int
	ringIdle                        time.Duration
	topicsMode                      string
	now                             func() time.Time
	newCursor                       func() string
	scopes                          map[string]*scopeJournal
	// closed holds closed scopes outside the live slots, with the generation they closed under.
	closed map[string]uint64
	// generations is the process-wide counter every scope generation comes from, so a recreated ring
	// never repeats a generation a cursor may still carry.
	generations  uint64
	codec        CursorCodec
	cursors      map[string]CursorPosition
	cursorOrder  []string
	seenEventIDs map[string]map[string]struct{}
	eventIDOrder map[string][]string
}

var ErrCursor = errors.New("journal: cursor is not issued for this scope and actor")
var ErrCapacity = errors.New("journal: scoped journal capacity exhausted")
var ErrOrganizationMismatch = errors.New("journal: organization does not match scope")
var ErrEvent = errors.New("journal: invalid owner event")

func NewScoped(epoch string, capacity, maxScopes, maxCursors int, now func() time.Time, newCursor func() string, codec CursorCodec) (*Scoped, error) {
	return NewScopedWithOptions(ScopedOptions{Epoch: epoch, Capacity: capacity, MaxScopes: maxScopes, MaxClosedScopes: maxScopes, MaxCursors: maxCursors, RingIdle: 10 * time.Minute, TopicsMode: TopicsAll, Now: now, NewCursor: newCursor, Codec: codec})
}

func NewScopedWithOptions(opts ScopedOptions) (*Scoped, error) {
	if opts.Epoch == "" || opts.Capacity <= 0 || opts.MaxScopes <= 0 || opts.MaxClosedScopes <= 0 || opts.RingIdle <= 0 || opts.Now == nil || (opts.TopicsMode != TopicsAll && opts.TopicsMode != TopicsEvent) {
		return nil, errors.New("journal: scoped dependencies and bounds are required")
	}
	if opts.Codec == nil && (opts.MaxCursors <= 0 || opts.NewCursor == nil) {
		return nil, errors.New("journal: unencrypted cursor test source and bounds are required")
	}
	return &Scoped{
		epoch: opts.Epoch, capacity: opts.Capacity, maxScopes: opts.MaxScopes, maxClosedScopes: opts.MaxClosedScopes,
		maxCursors: opts.MaxCursors, ringIdle: opts.RingIdle, topicsMode: opts.TopicsMode, now: opts.Now,
		newCursor: opts.NewCursor, scopes: map[string]*scopeJournal{}, closed: map[string]uint64{}, codec: opts.Codec,
		cursors: map[string]CursorPosition{}, seenEventIDs: map[string]map[string]struct{}{}, eventIDOrder: map[string][]string{},
	}, nil
}

// get returns the live journal of a scope, creating it without a ring. A closed scope has none.
func (s *Scoped) get(tenant string) (*scopeJournal, error) {
	s.evictIdle(s.now())
	j := s.scopes[tenant]
	if j == nil {
		if len(s.scopes) >= s.maxScopes {
			if !s.evictOldestIdle() {
				return nil, ErrCapacity
			}
		}
		j = &scopeJournal{generation: s.nextGeneration(), lastActivity: s.now(), owners: map[string]ownerState{}}
		s.scopes[tenant] = j
	}
	j.lastActivity = s.now()
	return j, nil
}

func (s *Scoped) evictIdle(now time.Time) {
	for tenant, j := range s.scopes {
		if len(j.subscribers) == 0 && !now.Before(j.lastActivity.Add(s.ringIdle)) {
			delete(s.scopes, tenant)
		}
	}
}

func (s *Scoped) evictOldestIdle() bool {
	var oldest string
	var at time.Time
	var generation uint64
	for tenant, j := range s.scopes {
		if len(j.subscribers) != 0 {
			continue
		}
		if oldest == "" || j.lastActivity.Before(at) || (j.lastActivity.Equal(at) && j.generation < generation) {
			oldest, at, generation = tenant, j.lastActivity, j.generation
		}
	}
	if oldest == "" {
		return false
	}
	delete(s.scopes, oldest)
	return true
}

func validEvent(event Event) bool {
	if !validOpaqueID(event.EventID) || event.Owner == "" || event.Type == "" || event.SchemaVersion != 1 || !validOpaqueID(event.OrgID) || !validOpaqueID(event.AggregateID) || event.AggregateRevision < 1 || !validUUID(event.Generation) || event.OccurredAt.IsZero() {
		return false
	}
	if (event.CorrelationID != "" && !validTraceID(event.CorrelationID)) || (event.CausationID != "" && !validTraceID(event.CausationID)) {
		return false
	}
	switch event.Owner {
	case "warehouse":
		return validOpaqueID(event.RestaurantID) && event.AggregateID == event.RestaurantID && slices.Contains(warehouseEventTypes, event.Type) && validTopics(event.Topics)
	case "auth":
		return len(event.Topics) == 0 && slices.Contains(authEventTypes, event.Type) && (event.RestaurantID == "" || validOpaqueID(event.RestaurantID))
	default:
		return false
	}
}

func validOpaqueID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validTraceID(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return value != ""
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		switch {
		case value[i] >= '0' && value[i] <= '9':
		case value[i] >= 'a' && value[i] <= 'f':
		case value[i] >= 'A' && value[i] <= 'F':
		default:
			return false
		}
	}
	return true
}

var warehouseEventTypes = []string{
	"warehouse.ProductRegistered", "warehouse.DishDefined", "warehouse.DeliveryReceived", "warehouse.OrderPlaced",
	"warehouse.BatchExpiryPending", "warehouse.BatchWriteoffConfirmed", "warehouse.BatchExpired",
}

var authEventTypes = []string{
	"auth.restaurant.deleting", "auth.restaurant.deleted", "auth.organization.deleting", "auth.organization.deleted",
	"auth.organization.settings_changed", "auth.membership.revoked", "auth.assignment.revoked",
}

func (s *Scoped) rememberEvent(owner, eventID string) {
	if s.seenEventIDs[owner] == nil {
		s.seenEventIDs[owner] = map[string]struct{}{}
	}
	seen := s.seenEventIDs[owner]
	seen[eventID] = struct{}{}
	order := append(s.eventIDOrder[owner], eventID)
	if len(order) > eventIDLimit {
		delete(seen, order[0])
		order = order[1:]
	}
	s.eventIDOrder[owner] = order
}

func (s *Scoped) Apply(event Event) error {
	if !validEvent(event) {
		return ErrEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictIdle(s.now())
	if _, exists := s.seenEventIDs[event.Owner][event.EventID]; exists {
		return nil
	}
	var err error
	if event.Owner == "auth" {
		err = s.applyAuthEvent(event)
	} else {
		err = s.applyWarehouseEvent(event)
	}
	if err != nil {
		return err
	}
	s.rememberEvent(event.Owner, event.EventID)
	return nil
}

func (s *Scoped) applyWarehouseEvent(event Event) error {
	j := s.scopes[event.RestaurantID]
	if j == nil || j.orgID == "" || j.orgID != event.OrgID {
		return nil
	}
	ownerKey := event.Owner + "\x00" + event.AggregateID
	state := j.owners[ownerKey]
	switch {
	case state.generation != "" && state.generation != event.Generation:
		s.resetRing(j)
		state = ownerState{generation: event.Generation, revision: event.AggregateRevision, hasRevision: true}
		j.owners[ownerKey] = state
		return nil
	case state.generation == "" || !state.hasRevision:
		state.generation = event.Generation
		state.revision = event.AggregateRevision - 1
	case event.AggregateRevision <= state.revision:
		return nil
	case event.AggregateRevision > state.revision+1:
		s.resetRing(j)
		state.revision = event.AggregateRevision
		state.hasRevision = true
		j.owners[ownerKey] = state
		return nil
	}
	topics := event.Topics
	if s.topicsMode == TopicsAll {
		topics = allTopics
	}
	s.append(j, topics)
	state.revision = event.AggregateRevision
	state.hasRevision = true
	j.owners[ownerKey] = state
	return nil
}

func (s *Scoped) applyAuthEvent(event Event) error {
	var tenants []string
	if event.RestaurantID != "" {
		if j := s.scopes[event.RestaurantID]; j != nil && j.orgID == event.OrgID {
			tenants = append(tenants, event.RestaurantID)
		}
	} else {
		for tenant, j := range s.scopes {
			if j.orgID == event.OrgID {
				tenants = append(tenants, tenant)
			}
		}
	}
	accepted := make([]string, 0, len(tenants))
	for _, tenant := range tenants {
		j := s.scopes[tenant]
		key := authRevisionKey(event)
		state, tracked := j.owners[key]
		if j.authGeneration == event.Generation && key != "" && tracked && event.AggregateRevision <= state.revision {
			continue
		}
		accepted = append(accepted, tenant)
	}
	switch event.Type {
	case "auth.restaurant.deleting", "auth.restaurant.deleted":
		if event.RestaurantID == "" {
			return ErrEvent
		}
		if s.scopes[event.RestaurantID] != nil && len(accepted) == 0 {
			return nil
		}
		if _, closed := s.closed[event.RestaurantID]; !closed && len(s.closed) >= s.maxClosedScopes {
			return ErrCapacity
		}
		if s.scopes[event.RestaurantID] != nil {
			s.acceptAuthEvent(event.RestaurantID, event)
		}
		return s.closeScopeLockedCapacity(event.RestaurantID)
	case "auth.organization.deleting", "auth.organization.deleted":
		if len(tenants) > 0 && len(accepted) == 0 {
			return nil
		}
		if len(s.closed)+len(accepted) > s.maxClosedScopes {
			return ErrCapacity
		}
		for _, tenant := range accepted {
			s.acceptAuthEvent(tenant, event)
		}
		return s.closeTenantsLocked(accepted)
	case "auth.organization.settings_changed", "auth.membership.revoked", "auth.assignment.revoked":
		for _, tenant := range accepted {
			s.acceptAuthEvent(tenant, event)
			signalScope(s.scopes[tenant])
		}
	}
	return nil
}

func (s *Scoped) acceptAuthEvent(tenant string, event Event) {
	j := s.scopes[tenant]
	if j == nil {
		return
	}
	if j.authGeneration != "" && j.authGeneration != event.Generation {
		s.resetRing(j)
	}
	j.authGeneration = event.Generation
	if key := authRevisionKey(event); key != "" {
		j.owners[key] = ownerState{generation: event.Generation, revision: event.AggregateRevision, hasRevision: true}
	}
	j.lastActivity = s.now()
}

func authRevisionKey(event Event) string {
	if event.Owner == "auth" && (event.Type == "auth.restaurant.deleting" || event.Type == "auth.restaurant.deleted") {
		return "auth.restaurant"
	}
	return ""
}

var allTopics = []string{"catalog", "stock", "menu", "orders", "analytics"}

func (s *Scoped) nextGeneration() uint64 {
	s.generations++
	return s.generations
}

func (s *Scoped) isClosed(tenant string) bool {
	_, closed := s.closed[tenant]
	return closed
}

func (s *Scoped) Watch(tenant string) (<-chan struct{}, func(), error) {
	return s.WatchScope(tenant, "")
}

func (s *Scoped) WatchScope(tenant, orgID string) (<-chan struct{}, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed(tenant) {
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		return ch, func() {}, nil
	}
	j, err := s.get(tenant)
	if err != nil {
		return nil, nil, err
	}
	if orgID != "" {
		if j.orgID != "" && j.orgID != orgID {
			return nil, nil, ErrOrganizationMismatch
		}
		j.orgID = orgID
	}
	ch := make(chan struct{}, 1)
	if j.subscribers == nil {
		j.subscribers = map[chan struct{}]struct{}{}
	}
	j.subscribers[ch] = struct{}{}
	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(j.subscribers, ch)
		if len(j.subscribers) == 0 {
			j.subscribers = nil
			j.lastActivity = s.now()
		}
	}, nil
}

func signalScope(j *scopeJournal) {
	for ch := range j.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *Scoped) Append(tenant string, topics []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed(tenant) {
		return errors.New("journal: scope is closed")
	}
	j, err := s.get(tenant)
	if err != nil {
		return err
	}
	if len(topics) == 0 || len(topics) > 5 {
		return errors.New("journal: invalid change topics")
	}
	if !validTopics(topics) {
		return errors.New("journal: invalid change topics")
	}
	s.append(j, topics)
	return nil
}

func validTopics(topics []string) bool {
	if len(topics) == 0 || len(topics) > 5 {
		return false
	}
	seen := map[string]bool{}
	for _, topic := range topics {
		if seen[topic] || !slices.Contains([]string{"catalog", "stock", "menu", "orders", "analytics"}, topic) {
			return false
		}
		seen[topic] = true
	}
	return true
}

func (s *Scoped) append(j *scopeJournal, topics []string) {
	if j.ring == nil {
		j.ring = make([]Change, s.capacity)
	}
	j.last++
	j.ring[(j.last-1)%int64(len(j.ring))] = Change{Sequence: j.last, Topics: slices.Clone(topics)}
	j.lastActivity = s.now()
	signalScope(j)
}

func (s *Scoped) CloseScope(tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeScopeLockedCapacity(tenant)
}

func (s *Scoped) closeScopeLockedCapacity(tenant string) error {
	if s.isClosed(tenant) {
		return nil
	}
	if len(s.closed) >= s.maxClosedScopes {
		return ErrCapacity
	}
	s.closeScopeLocked(tenant)
	return nil
}

func (s *Scoped) closeScopeLocked(tenant string) {
	generation := s.nextGeneration()
	if j := s.scopes[tenant]; j != nil {
		delete(s.scopes, tenant)
		signalScope(j)
	}
	s.closed[tenant] = generation
}

func (s *Scoped) CloseOrganization(orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeOrganizationLocked(orgID)
}

func (s *Scoped) closeOrganizationLocked(orgID string) error {
	var tenants []string
	for tenant, j := range s.scopes {
		if j.orgID == orgID {
			tenants = append(tenants, tenant)
		}
	}
	return s.closeTenantsLocked(tenants)
}

func (s *Scoped) closeTenantsLocked(tenants []string) error {
	if len(s.closed)+len(tenants) > s.maxClosedScopes {
		return ErrCapacity
	}
	for _, tenant := range tenants {
		s.closeScopeLocked(tenant)
	}
	return nil
}

func (s *Scoped) WakeScope(tenant string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j := s.scopes[tenant]; j != nil {
		j.lastActivity = s.now()
		signalScope(j)
	}
}

func (s *Scoped) WakeOrganization(orgID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.scopes {
		if j.orgID == orgID {
			j.lastActivity = s.now()
			signalScope(j)
		}
	}
}

func (s *Scoped) Reset(tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed(tenant) {
		return errors.New("journal: scope is closed")
	}
	j, err := s.get(tenant)
	if err != nil {
		return err
	}
	s.resetRing(j)
	return nil
}

func (s *Scoped) resetRing(j *scopeJournal) {
	j.generation = s.nextGeneration()
	j.last = 0
	j.ring = nil
	j.lastActivity = s.now()
	signalScope(j)
}

func (s *Scoped) ResetAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.scopes {
		s.resetRing(j)
		j.owners = map[string]ownerState{}
	}
	return nil
}

func (s *Scoped) Read(tenant, actor, handle string, after int64, generation uint64) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation, closed := s.closed[tenant]; closed {
		return Snapshot{Epoch: s.epoch, Closed: true, Generation: generation}, nil
	}
	j, err := s.get(tenant)
	if err != nil {
		return Snapshot{}, err
	}
	result := Snapshot{Epoch: s.epoch, Last: j.last, Generation: j.generation}
	if handle != "" {
		var c CursorPosition
		var ok bool
		if s.codec == nil {
			c, ok = s.cursors[handle]
		} else {
			var err error
			c, err = s.codec.Decode(handle)
			ok = err == nil
		}
		if !ok || c.Tenant != tenant || c.Actor != actor {
			return Snapshot{}, ErrCursor
		}
		after, generation = c.Sequence, c.Generation
		if c.Epoch != s.epoch || !s.now().Before(c.Expires) {
			result.Refresh = true
			return result, nil
		}
	}
	if generation == 0 || generation != j.generation || after < j.last-int64(len(j.ring)) || after > j.last {
		result.Refresh = true
		return result, nil
	}
	for n := after + 1; n <= j.last; n++ {
		c := j.ring[(n-1)%int64(len(j.ring))]
		c.Topics = slices.Clone(c.Topics)
		result.Changes = append(result.Changes, c)
	}
	return result, nil
}

func (s *Scoped) Cursor(tenant, actor string, sequence int64, generation uint64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed(tenant) {
		return "", ErrCursor
	}
	j, err := s.get(tenant)
	if err != nil {
		return "", err
	}
	if generation != j.generation || sequence < 1 || sequence > j.last {
		return "", ErrCursor
	}
	position := CursorPosition{Tenant: tenant, Actor: actor, Epoch: s.epoch, Sequence: sequence, Generation: generation, Expires: s.now().Add(5 * time.Minute)}
	handle := ""
	if s.codec != nil {
		handle, err = s.codec.Encode(position)
		if err != nil {
			return "", err
		}
	} else {
		handle = s.newCursor()
	}
	if handle == "" || len(handle) > 1024 {
		return "", errors.New("journal: invalid cursor source")
	}
	if s.codec == nil {
		if _, exists := s.cursors[handle]; exists {
			return "", errors.New("journal: duplicate cursor source")
		}
		if len(s.cursors) >= s.maxCursors {
			oldest := s.cursorOrder[0]
			delete(s.cursors, oldest)
			s.cursorOrder = s.cursorOrder[1:]
		}
		s.cursors[handle] = position
		s.cursorOrder = append(s.cursorOrder, handle)
	}
	j.lastActivity = s.now()
	return handle, nil
}

func (s *Scoped) ObserveRuntime(tenant, service, epoch string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if service != "warehouse" && service != "serving" {
		return errors.New("journal: invalid runtime service")
	}
	if s.isClosed(tenant) {
		return errors.New("journal: scope is closed")
	}
	j := s.scopes[tenant]
	if j == nil {
		return nil
	}
	ownerKey := service + "\x00" + tenant
	state := j.owners[ownerKey]
	previous := state.generation
	if previous != "" && previous != epoch {
		s.resetRing(j)
		state = ownerState{}
	}
	state.generation = epoch
	j.owners[ownerKey] = state
	j.lastActivity = s.now()
	return nil
}
