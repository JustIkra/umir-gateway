// Package journal keeps the gateway's in-memory record of state-changing exchanges. It sees only
// methods, paths and HTTP statuses, never bodies, so it makes no business decisions.
package journal

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

// Source names what produced an entry.
type Source string

const (
	SourceRequest    Source = "request"
	SourceExpiration Source = "expiration"
	// SourceExternal marks a change the gateway noticed without a request through it.
	SourceExternal Source = "external"
)

// Outcome is what the gateway knows about an exchange from its status alone.
type Outcome string

const (
	OutcomeSuccess  Outcome = "success"
	OutcomePending  Outcome = "pending"
	OutcomeRejected Outcome = "rejected"
	OutcomeUnknown  Outcome = "unknown"
)

// OutcomeOf maps an HTTP status to its outcome. Status 0 is a transport error; any status outside
// 2xx and 4xx may have changed state, so it is unknown.
func OutcomeOf(status int) Outcome {
	switch {
	case status == http.StatusAccepted:
		return OutcomePending
	case status >= http.StatusOK && status < http.StatusMultipleChoices:
		return OutcomeSuccess
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		return OutcomeRejected
	}
	return OutcomeUnknown
}

// Entry is one finished exchange. It never holds bodies, session IDs, addresses or headers.
type Entry struct {
	Seq    int64
	At     time.Time
	Source Source
	// Method and Path, without the query, are empty for expiration and external entries.
	Method string
	Path   string
	// Status is 0 when no response arrived.
	Status  int
	Outcome Outcome
	// Count is the number of batches an expiration run wrote off.
	Count int
}

// Journal is a ring buffer of the latest entries of one gateway process. Seq starts at 1 in every
// epoch and grows by one without gaps.
type Journal struct {
	epoch string
	now   func() time.Time

	mu   sync.Mutex
	ring []Entry
	last int64
	// lastRequest is the seq of the newest request entry, 0 before the first.
	lastRequest int64
	subscribers map[chan struct{}]struct{}
}

// New starts an empty journal of capacity entries in a new epoch named by newID.
func New(capacity int, newID func() string, now func() time.Time) (*Journal, error) {
	if capacity <= 0 || newID == nil || now == nil {
		return nil, errors.New("journal: positive capacity, ID source and clock are required")
	}
	epoch := newID()
	if epoch == "" || len(epoch) > 64 || !utf8.ValidString(epoch) {
		return nil, errors.New("journal: epoch must be 1 to 64 bytes of UTF-8")
	}
	return &Journal{epoch: epoch, now: now, ring: make([]Entry, capacity), subscribers: map[chan struct{}]struct{}{}}, nil
}

// Append numbers and stamps e, keeps it in place of the oldest entry when the buffer is full and
// wakes subscribers unless the owner rejected the exchange. It never blocks on a subscriber.
func (j *Journal) Append(e Entry) int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.last++
	e.Seq, e.At = j.last, j.now()
	j.ring[(e.Seq-1)%int64(len(j.ring))] = e
	if e.Source == SourceRequest {
		j.lastRequest = e.Seq
	}
	if e.Outcome != OutcomeRejected {
		for ch := range j.subscribers {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	return e.Seq
}

// Last returns the epoch and the seq of the newest entry, 0 while the journal is empty.
func (j *Journal) Last() (epoch string, seq int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.epoch, j.last
}

// LastRequest returns the seq of the newest request entry, 0 before the first. The expiration
// scheduler compares it between runs to tell a change it did not see pass through the gateway.
func (j *Journal) LastRequest() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.lastRequest
}

// Subscribe returns a channel that holds one signal after any number of entries that may have
// changed state. The subscription ends with ctx; the channel is never closed.
func (j *Journal) Subscribe(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{}, 1)
	j.mu.Lock()
	j.subscribers[ch] = struct{}{}
	j.mu.Unlock()
	context.AfterFunc(ctx, func() {
		j.mu.Lock()
		defer j.mu.Unlock()
		delete(j.subscribers, ch)
	})
	return ch
}

// Entries returns the kept entries with a seq above after, oldest first.
func (j *Journal) Entries(after int64) []Entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	first := max(after+1, j.last-int64(len(j.ring))+1, 1)
	entries := make([]Entry, 0, max(j.last-first+1, 0))
	for seq := first; seq <= j.last; seq++ {
		entries = append(entries, j.ring[(seq-1)%int64(len(j.ring))])
	}
	return entries
}
