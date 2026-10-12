package operator

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPassword = "correct horse battery staple"

var moscow = time.FixedZone("MSK", 3*60*60)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) Advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

type tokens struct {
	mu     sync.Mutex
	n      int
	failOn map[int]bool
}

func (t *tokens) New() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n++
	if t.failOn[t.n] {
		return "", errors.New("entropy unavailable")
	}
	return fmt.Sprintf("token-%d", t.n), nil
}

// failCall makes the n-th token request, counted from the start of the test, fail.
func (t *tokens) failCall(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failOn == nil {
		t.failOn = map[int]bool{}
	}
	t.failOn[n] = true
}

// fakeHash encodes the exact password bytes as ASCII, as a real PHC string would be.
func fakeHash(password string) string { return "hash:" + hex.EncodeToString([]byte(password)) }

// fakeHasher stores fakeHash(password) and records verified hashes; onVerify can block a verification.
type fakeHasher struct {
	mu       sync.Mutex
	verified []string
	onVerify func()
	hashErr  error
}

func (h *fakeHasher) Hash(password string) (string, error) {
	if h.hashErr != nil {
		return "", h.hashErr
	}
	return fakeHash(password), nil
}

func (h *fakeHasher) Verify(password, encoded string) (bool, error) {
	h.mu.Lock()
	h.verified = append(h.verified, encoded)
	hook := h.onVerify
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	return encoded == fakeHash(password), nil
}

func (h *fakeHasher) Check(encoded string) error {
	if !strings.HasPrefix(encoded, "hash:") {
		return errors.New("unsupported hash")
	}
	return nil
}

func (h *fakeHasher) setOnVerify(hook func()) { h.mu.Lock(); defer h.mu.Unlock(); h.onVerify = hook }

func (h *fakeHasher) verifiedHashes() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.verified...)
}

type fakeStore struct {
	mu       sync.Mutex
	err      error
	replaced []State
}

func (s *fakeStore) Replace(next State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	next.Sessions = slices.Clone(next.Sessions)
	s.replaced = append(s.replaced, next)
	return nil
}

// states returns every committed state; last returns the newest one, or the initial empty state.
func (s *fakeStore) states() []State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.replaced)
}

func (s *fakeStore) last() State {
	if states := s.states(); len(states) > 0 {
		return states[len(states)-1]
	}
	return State{Account: testAccount()}
}

func testAccount() Account {
	return Account{ProfileID: "PROFILE1", Login: "operator", DisplayName: "Оператор", PasswordHash: fakeHash(testPassword), CredentialVersion: 1}
}

type fixture struct {
	svc    *Service
	clock  *clock
	hasher *fakeHasher
	store  *fakeStore
	tokens *tokens
	opts   Options
}

func newFixture(t *testing.T, change func(*Options)) fixture {
	t.Helper()
	f := fixture{clock: &clock{now: time.Date(2026, 10, 11, 12, 0, 0, 0, moscow)}, hasher: &fakeHasher{}, store: &fakeStore{}}
	ids := &tokens{}
	f.tokens = ids
	opts := Options{
		Store: f.store, Hasher: f.hasher, Now: f.clock.Now, NewToken: ids.New,
		IdleTimeout: DefaultIdleTimeout, AbsoluteTimeout: DefaultAbsoluteTimeout, MaxSessions: DefaultMaxSessions,
		MaxAnonymous: DefaultMaxAnonymous, AnonymousTTL: DefaultAnonymousTTL,
		MaxVerifications: DefaultMaxVerifications, MaxQueuedLogins: DefaultMaxQueuedLogins,
		FailureLimit: DefaultFailureLimit, FailureWindow: DefaultFailureWindow, Cooldown: DefaultCooldown,
		RememberTimeout: DefaultRememberTimeout, FeedbackContextLimit: DefaultFeedbackContextLimit,
		FeedbackProcessLimit: DefaultFeedbackProcessLimit, FeedbackWindow: DefaultFeedbackWindow,
	}
	if change != nil {
		change(&opts)
	}
	svc, err := NewService(State{Account: testAccount()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	f.svc, f.opts = svc, opts
	return f
}

// restart starts a new service from the last committed state, as a gateway restart would.
func (f fixture) restart(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(f.store.last(), f.opts)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (f fixture) login(t *testing.T) Session {
	t.Helper()
	_, session, err := f.svc.Login(t.Context(), "operator", testPassword, "", false)
	if err != nil {
		t.Fatal(err)
	}
	return session
}
func (s *fakeStore) setErr(err error) { s.mu.Lock(); defer s.mu.Unlock(); s.err = err }

func (s *fakeStore) calls() []Account {
	var accounts []Account
	for _, state := range s.states() {
		accounts = append(accounts, state.Account)
	}
	return accounts
}
