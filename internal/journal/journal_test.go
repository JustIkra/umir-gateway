package journal

import (
	"context"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var moscow = time.FixedZone("MSK", 3*60*60)

// newTestJournal starts a journal of capacity entries in epoch "epoch-1" at a fixed Moscow time.
func newTestJournal(t *testing.T, capacity int) *Journal {
	t.Helper()
	at := time.Date(2026, 10, 12, 14, 0, 0, 0, moscow)
	j, err := New(capacity, func() string { return "epoch-1" }, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func request(status int) Entry {
	return Entry{Source: SourceRequest, Method: http.MethodPost, Path: "/api/warehouse/receipts", Status: status, Outcome: OutcomeOf(status)}
}

func TestNewRejectsUnusableSettings(t *testing.T) {
	now := func() time.Time { return time.Time{} }
	for name, epoch := range map[string]string{"empty": "", "too long": strings.Repeat("e", 65), "invalid UTF-8": "\xff"} {
		if _, err := New(1, func() string { return epoch }, now); err == nil {
			t.Errorf("%s epoch accepted", name)
		}
	}
	if _, err := New(0, func() string { return "e" }, now); err == nil {
		t.Error("zero capacity accepted")
	}
	if _, err := New(1, func() string { return strings.Repeat("e", 64) }, now); err != nil {
		t.Errorf("64-byte epoch: %v", err)
	}
}

func TestClassifyFollowsTheStatusTable(t *testing.T) {
	for status, want := range map[int]Outcome{
		0: OutcomeUnknown, 200: OutcomeSuccess, 201: OutcomeSuccess, 202: OutcomePending, 204: OutcomeSuccess, 302: OutcomeUnknown,
		400: OutcomeRejected, 401: OutcomeRejected, 409: OutcomeRejected, 422: OutcomeRejected, 499: OutcomeRejected,
		500: OutcomeUnknown, 502: OutcomeUnknown, 503: OutcomeUnknown, 504: OutcomeUnknown,
	} {
		if got := OutcomeOf(status); got != want {
			t.Errorf("OutcomeOf(%d) = %s, want %s", status, got, want)
		}
	}
}

func TestSeqIsGaplessAndLastStartsAtZero(t *testing.T) {
	j := newTestJournal(t, 10)
	if epoch, seq := j.Last(); epoch != "epoch-1" || seq != 0 {
		t.Fatalf("empty journal Last = %q, %d", epoch, seq)
	}
	for i, status := range []int{201, 409, 0, 202} {
		if seq := j.Append(request(status)); seq != int64(i+1) {
			t.Fatalf("Append #%d = %d", i+1, seq)
		}
	}
	if _, seq := j.Last(); seq != 4 {
		t.Fatalf("Last = %d", seq)
	}
	entries := j.Entries(0)
	if len(entries) != 4 {
		t.Fatalf("entries = %+v", entries)
	}
	for i, e := range entries {
		if e.Seq != int64(i+1) || !e.At.Equal(time.Date(2026, 10, 12, 14, 0, 0, 0, moscow)) {
			t.Errorf("entry %d = %+v", i, e)
		}
	}
	if got := j.Entries(2); len(got) != 2 || got[0].Seq != 3 || got[0].Outcome != OutcomeUnknown || got[1].Outcome != OutcomePending {
		t.Errorf("Entries(2) = %+v", got)
	}
}

func TestRingBufferKeepsTheNewestEntries(t *testing.T) {
	j := newTestJournal(t, 3)
	for range 5 {
		j.Append(request(http.StatusCreated))
	}
	var seqs []int64
	for _, e := range j.Entries(0) {
		seqs = append(seqs, e.Seq)
	}
	if !slices.Equal(seqs, []int64{3, 4, 5}) {
		t.Fatalf("kept %v", seqs)
	}
	if got := j.Entries(4); len(got) != 1 || got[0].Seq != 5 {
		t.Errorf("Entries(4) = %+v", got)
	}
	if got := j.Entries(5); len(got) != 0 {
		t.Errorf("Entries(5) = %+v", got)
	}
}

func TestRejectedEntriesDoNotWakeSubscribers(t *testing.T) {
	j := newTestJournal(t, 10)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	wake := j.Subscribe(ctx)
	j.Append(request(http.StatusConflict))
	select {
	case <-wake:
		t.Fatal("a rejected entry woke the subscriber")
	default:
	}
	for _, status := range []int{http.StatusOK, http.StatusAccepted, 0, http.StatusBadGateway} {
		j.Append(request(status))
		select {
		case <-wake:
		default:
			t.Fatalf("status %d did not wake the subscriber", status)
		}
	}
}

func TestBurstsCoalesceIntoOneSignal(t *testing.T) {
	j := newTestJournal(t, 10)
	wake := j.Subscribe(t.Context())
	for range 3 {
		j.Append(request(http.StatusCreated))
	}
	<-wake
	select {
	case <-wake:
		t.Fatal("three entries left more than one signal")
	default:
	}
}

func TestSubscriptionEndsWithItsContext(t *testing.T) {
	j := newTestJournal(t, 10)
	ctx, cancel := context.WithCancel(t.Context())
	j.Subscribe(ctx)
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		j.mu.Lock()
		left := len(j.subscribers)
		j.mu.Unlock()
		if left == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled subscriber was not removed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestEntriesHoldNoRequestData(t *testing.T) {
	var fields []string
	entry := reflect.TypeFor[Entry]()
	for i := range entry.NumField() {
		fields = append(fields, entry.Field(i).Name)
	}
	if want := []string{"Seq", "At", "Source", "Method", "Path", "Status", "Outcome", "Count"}; !slices.Equal(fields, want) {
		t.Fatalf("Entry fields = %v, want %v: bodies, session IDs, addresses and headers stay out", fields, want)
	}
}

func TestLastRequestFollowsOnlyRequestEntries(t *testing.T) {
	j := newTestJournal(t, 4)
	if got := j.LastRequest(); got != 0 {
		t.Fatalf("empty journal: %d", got)
	}
	j.Append(request(http.StatusOK))
	j.Append(Entry{Source: SourceExpiration, Outcome: OutcomeSuccess, Count: 1})
	j.Append(Entry{Source: SourceExternal, Outcome: OutcomeUnknown})
	if got := j.LastRequest(); got != 1 {
		t.Fatalf("after expiration and external entries: %d, want 1", got)
	}
	j.Append(request(http.StatusConflict))
	if got := j.LastRequest(); got != 4 {
		t.Fatalf("a rejected request is still a request: %d, want 4", got)
	}
}
