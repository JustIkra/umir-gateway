package journal

import (
	"errors"
	"slices"
	"sync"
	"time"
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
	ring                         []Change
	last                         int64
	generation                   uint64
	subscribers                  map[chan struct{}]struct{}
	warehouseEpoch, servingEpoch string
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

type Scoped struct {
	mu                              sync.Mutex
	epoch                           string
	capacity, maxScopes, maxCursors int
	now                             func() time.Time
	newCursor                       func() string
	scopes                          map[string]*scopeJournal
	// closed holds closed scopes outside the live slots, with the generation they closed under.
	closed map[string]uint64
	// generations is the process-wide counter every scope generation comes from, so a recreated ring
	// never repeats a generation a cursor may still carry.
	generations uint64
	codec       CursorCodec
	cursors     map[string]CursorPosition
	cursorOrder []string
}

var ErrCursor = errors.New("journal: cursor is not issued for this scope and actor")
var ErrCapacity = errors.New("journal: scoped journal capacity exhausted")

func NewScoped(epoch string, capacity, maxScopes, maxCursors int, now func() time.Time, newCursor func() string, codec CursorCodec) (*Scoped, error) {
	if epoch == "" || capacity <= 0 || maxScopes <= 0 || maxCursors <= 0 || now == nil || newCursor == nil {
		return nil, errors.New("journal: scoped dependencies and bounds are required")
	}
	return &Scoped{epoch: epoch, capacity: capacity, maxScopes: maxScopes, maxCursors: maxCursors, now: now, newCursor: newCursor, scopes: map[string]*scopeJournal{}, closed: map[string]uint64{}, codec: codec, cursors: map[string]CursorPosition{}}, nil
}

// get returns the live journal of a scope, creating it without a ring. A closed scope has none.
func (s *Scoped) get(tenant string) (*scopeJournal, error) {
	j := s.scopes[tenant]
	if j == nil {
		if len(s.scopes) >= s.maxScopes {
			return nil, ErrCapacity
		}
		j = &scopeJournal{generation: s.nextGeneration()}
		s.scopes[tenant] = j
	}
	return j, nil
}

func (s *Scoped) nextGeneration() uint64 {
	s.generations++
	return s.generations
}

func (s *Scoped) isClosed(tenant string) bool {
	_, closed := s.closed[tenant]
	return closed
}

func (s *Scoped) Watch(tenant string) (<-chan struct{}, func(), error) {
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
	seen := map[string]bool{}
	for _, topic := range topics {
		if seen[topic] || !slices.Contains([]string{"catalog", "stock", "menu", "orders", "analytics"}, topic) {
			return errors.New("journal: invalid change topic")
		}
		seen[topic] = true
	}
	if j.ring == nil {
		j.ring = make([]Change, s.capacity)
	}
	j.last++
	j.ring[(j.last-1)%int64(len(j.ring))] = Change{Sequence: j.last, Topics: slices.Clone(topics)}
	signalScope(j)
	return nil
}

func (s *Scoped) CloseScope(tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed(tenant) {
		return nil
	}
	if len(s.closed) >= s.maxScopes {
		return ErrCapacity
	}
	generation := s.nextGeneration()
	if j := s.scopes[tenant]; j != nil {
		delete(s.scopes, tenant)
		signalScope(j)
	}
	s.closed[tenant] = generation
	return nil
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
	signalScope(j)
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
		c, ok := s.cursors[handle]
		if !ok && s.codec != nil {
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
	j, err := s.get(tenant)
	if err != nil {
		return err
	}
	epochOf := &j.warehouseEpoch
	if service == "serving" {
		epochOf = &j.servingEpoch
	}
	if previous := *epochOf; previous != "" && previous != epoch {
		s.resetRing(j)
	}
	*epochOf = epoch
	return nil
}
