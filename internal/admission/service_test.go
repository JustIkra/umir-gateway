package admission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type recordingLimiter struct {
	requests []Request
	decision Decision
	err      error
}

func (l *recordingLimiter) Admit(_ context.Context, r Request) (Decision, error) {
	l.requests = append(l.requests, r)
	return l.decision, l.err
}

type fixedContinuity struct {
	state State
	err   error
}

func (c fixedContinuity) Check(context.Context) (State, error) { return c.state, c.err }

func testBudgets() map[string]Budget {
	return map[string]Budget{
		"csrf_client": {60, time.Minute, 20}, "csrf_global": {5000, 10 * time.Minute, 1500}, "login_client": {20, time.Minute, 5},
		"registration_client": {10, 10 * time.Minute, 2}, "registration_preauth": {3, 10 * time.Minute, 1}, "registration_global": {300, 10 * time.Minute, 60},
		"reset_client":    {10, 10 * time.Minute, 2},
		"feedback_client": {20, time.Hour, 4}, "feedback_preauth": {5, 10 * time.Minute, 1}, "feedback_global": {200, time.Hour, 40},
		"order_user": {60, time.Minute, 20}, "order_restaurant": {600, time.Minute, 200},
		"sse_session": {8, 0, 4}, "sse_org": {200, 0, 50}, "sse_cell": {2000, 0, 500},
	}
}

func newTestService(t *testing.T, l Limiter, c Continuity) *Service {
	t.Helper()
	n := 0
	s, err := New(Options{Limiter: l, Continuity: c, Budgets: testBudgets(), Key: []byte("0123456789abcdef0123456789abcdef"),
		NewID: func() string { n++; return "id-" + string(rune('a'+n)) }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestW2DimensionsHideSubjectsAndFollowTheRule(t *testing.T) {
	l := &recordingLimiter{decision: Decision{Allowed: true}}
	s := newTestService(t, l, fixedContinuity{})
	v, err := s.Admit(context.Background(), RuleRegistration, Subjects{Client: "203.0.113.7", Preauth: "pre-secret", Global: true}, Attempt{ID: "cmd-1", Fingerprint: "body-digest"})
	if err != nil || !v.Allowed {
		t.Fatalf("%+v %v", v, err)
	}
	r := l.requests[0]
	if r.Policy != "registration" || r.ID != "cmd-1" || len(r.Dimensions) != 3 {
		t.Fatalf("request: %+v", r)
	}
	for _, d := range r.Dimensions {
		if strings.Contains(d.Key, "203.0.113.7") || strings.Contains(d.Key, "pre-secret") {
			t.Fatalf("a raw subject reached the store key: %s", d.Key)
		}
	}
	if r.Dimensions[0].Limit != 10 || r.Dimensions[1].Limit != 3 || r.Dimensions[2].Limit != 300 || r.Dimensions[2].Window != 10*time.Minute {
		t.Fatalf("limits: %+v", r.Dimensions)
	}
	if _, err := s.Admit(context.Background(), RuleRegistration, Subjects{Client: "203.0.113.8", Preauth: "pre-secret", Global: true}, Attempt{ID: "cmd-1", Fingerprint: "body-digest"}); err != nil {
		t.Fatal(err)
	}
	if l.requests[1].Dimensions[0].Key == r.Dimensions[0].Key || l.requests[1].Dimensions[1].Key != r.Dimensions[1].Key {
		t.Fatal("subjects must map to stable, distinct keys")
	}
	if l.requests[1].Fingerprint != r.Fingerprint {
		t.Fatal("attempt fingerprint must remain stable when a retry's client dimension changes")
	}
}

func TestW2EmptySubjectsLeaveDimensionsOut(t *testing.T) {
	l := &recordingLimiter{decision: Decision{Allowed: true}}
	s := newTestService(t, l, fixedContinuity{})
	if v, err := s.Admit(context.Background(), RuleLogin, Subjects{}, Attempt{}); err != nil || !v.Allowed || len(l.requests) != 0 {
		t.Fatalf("without a client key login has no gateway budget: %+v %v %d", v, err, len(l.requests))
	}
	if _, err := s.Admit(context.Background(), RuleFeedback, Subjects{Preauth: "p", Global: true}, Attempt{ID: "x", Fingerprint: "y"}); err != nil {
		t.Fatal(err)
	}
	if got := len(l.requests[0].Dimensions); got != 2 {
		t.Fatalf("preauth and global only: %d", got)
	}
	if _, err := s.Admit(context.Background(), RuleCSRF, Subjects{Client: "c"}, Attempt{}); err != nil {
		t.Fatal(err)
	}
	if got := len(l.requests[1].Dimensions); got != 1 {
		t.Fatalf("global stays off unless asked: %d", got)
	}
}

func TestW2FeedbackAttemptFingerprintStillBindsDimensions(t *testing.T) {
	l := &recordingLimiter{decision: Decision{Allowed: true}}
	s := newTestService(t, l, fixedContinuity{})
	attempt := Attempt{ID: "feedback-attempt", Fingerprint: "body-digest"}
	for _, client := range []string{"203.0.113.10", "203.0.113.11"} {
		if _, err := s.Admit(context.Background(), RuleFeedback, Subjects{Client: client, Preauth: "preauth", Global: true}, attempt); err != nil {
			t.Fatal(err)
		}
	}
	if l.requests[0].Fingerprint == l.requests[1].Fingerprint {
		t.Fatal("feedback identity must continue to include its scoped dimensions")
	}
}

func TestW2AttemptsWithoutIDAreAlwaysNew(t *testing.T) {
	l := &recordingLimiter{decision: Decision{Allowed: true}}
	s := newTestService(t, l, fixedContinuity{})
	for range 2 {
		if _, err := s.Admit(context.Background(), RuleLogin, Subjects{Client: "c"}, Attempt{}); err != nil {
			t.Fatal(err)
		}
	}
	if l.requests[0].ID == l.requests[1].ID || l.requests[0].ID == "" {
		t.Fatalf("IDs: %q %q", l.requests[0].ID, l.requests[1].ID)
	}
}

func TestW2StrictModeUsesStrictLimits(t *testing.T) {
	l := &recordingLimiter{decision: Decision{Allowed: true}}
	s := newTestService(t, l, fixedContinuity{state: State{Mode: Strict, Reason: "marker_missing"}})
	if _, err := s.Admit(context.Background(), RuleFeedback, Subjects{Client: "c", Preauth: "p", Global: true}, Attempt{ID: "x", Fingerprint: "y"}); err != nil {
		t.Fatal(err)
	}
	got := []int{}
	for _, d := range l.requests[0].Dimensions {
		if d.Limit < 1 {
			t.Fatal("a strict limit is never zero")
		}
		got = append(got, d.Limit)
	}
	if got[0] != 4 || got[1] != 1 || got[2] != 40 {
		t.Fatalf("strict limits: %v", got)
	}
}

func TestW2UnavailableStoreIsNeverAllowed(t *testing.T) {
	boom := errors.New("boom")
	for name, s := range map[string]*Service{
		"limiter":    newTestService(t, &recordingLimiter{err: boom}, fixedContinuity{}),
		"continuity": newTestService(t, &recordingLimiter{decision: Decision{Allowed: true}}, fixedContinuity{err: boom}),
	} {
		v, err := s.Admit(context.Background(), RuleLogin, Subjects{Client: "c"}, Attempt{})
		if !errors.Is(err, ErrUnavailable) || v.Allowed {
			t.Errorf("%s: %+v %v", name, v, err)
		}
		if got := s.Snapshot()["login"]; got.Unavailable != 1 {
			t.Errorf("%s: counts %+v", name, got)
		}
	}
}

func TestW2RefusalCarriesRetryAfterAndConflictPasses(t *testing.T) {
	l := &recordingLimiter{decision: Decision{RetryAfter: 1500 * time.Millisecond}}
	s := newTestService(t, l, fixedContinuity{})
	v, err := s.Admit(context.Background(), RuleOrder, Subjects{User: "u", Restaurant: "r"}, Attempt{})
	if err != nil || v.Allowed || v.RetryAfter != 1500*time.Millisecond {
		t.Fatalf("%+v %v", v, err)
	}
	if RetryAfterSeconds(1500*time.Millisecond) != 2 || RetryAfterSeconds(time.Millisecond) != 1 || RetryAfterSeconds(2*time.Second) != 2 {
		t.Fatal("Retry-After rounds up to whole seconds, at least one")
	}
	if got := s.Snapshot()["order"]; got.Refused != 1 {
		t.Fatalf("counts %+v", got)
	}
	l.err = ErrConflict
	if _, err := s.Admit(context.Background(), RuleOrder, Subjects{User: "u"}, Attempt{ID: "a", Fingerprint: "b"}); !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("conflict: %v", err)
	}
}

func TestW2StreamLimits(t *testing.T) {
	s := newTestService(t, &recordingLimiter{}, fixedContinuity{})
	limits, err := s.StreamLimits(context.Background(), "session-token", "org-1")
	if err != nil || len(limits) != 3 {
		t.Fatalf("%+v %v", limits, err)
	}
	if strings.Contains(limits[0].Key, "session-token") || !strings.HasPrefix(limits[0].Key, "sse:s:") || limits[0].Max != 8 ||
		limits[1].Key != "sse:o:org-1" || limits[1].Max != 200 || limits[2].Key != "sse:cell" || limits[2].Max != 2000 {
		t.Fatalf("limits: %+v", limits)
	}
	strict := newTestService(t, &recordingLimiter{}, fixedContinuity{state: State{Mode: Strict}})
	limits, err = strict.StreamLimits(context.Background(), "s", "o")
	if err != nil {
		t.Fatal(err)
	}
	if limits[0].Max != 4 || limits[1].Max != 50 || limits[2].Max != 500 {
		t.Fatalf("strict: %+v", limits)
	}
	down := newTestService(t, &recordingLimiter{}, fixedContinuity{err: errors.New("x")})
	if _, err := down.StreamLimits(context.Background(), "s", "o"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("down: %v", err)
	}
}

func TestW2NewRefusesMissingBudgets(t *testing.T) {
	budgets := testBudgets()
	delete(budgets, "order_user")
	if _, err := New(Options{Limiter: &recordingLimiter{}, Continuity: fixedContinuity{}, Budgets: budgets, Key: []byte("0123456789abcdef")}); err == nil {
		t.Fatal("a rule without its budget must not start")
	}
	if _, err := New(Options{Limiter: &recordingLimiter{}, Continuity: fixedContinuity{}, Budgets: testBudgets(), Key: []byte("short")}); err == nil {
		t.Fatal("a short HMAC key must not start")
	}
}
