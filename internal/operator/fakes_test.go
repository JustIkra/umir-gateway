package operator

import (
	"errors"
	"fmt"
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
	mu sync.Mutex
	n  int
}

func (t *tokens) New() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.n++
	return fmt.Sprintf("token-%d", t.n), nil
}

// fakeHasher stores "hash:<password>" and records verified hashes; onVerify can block a verification.
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
	return "hash:" + password, nil
}

func (h *fakeHasher) Verify(password, encoded string) (bool, error) {
	h.mu.Lock()
	h.verified = append(h.verified, encoded)
	hook := h.onVerify
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	return encoded == "hash:"+password, nil
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
	replaced []Account
}

func (s *fakeStore) Replace(next Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.replaced = append(s.replaced, next)
	return nil
}

func testAccount() Account {
	return Account{ProfileID: "PROFILE1", Login: "operator", DisplayName: "Оператор", PasswordHash: "hash:" + testPassword, CredentialVersion: 1}
}

type fixture struct {
	svc    *Service
	clock  *clock
	hasher *fakeHasher
	store  *fakeStore
}

func newFixture(t *testing.T, change func(*Options)) fixture {
	t.Helper()
	f := fixture{clock: &clock{now: time.Date(2026, 10, 11, 12, 0, 0, 0, moscow)}, hasher: &fakeHasher{}, store: &fakeStore{}}
	ids := &tokens{}
	opts := Options{
		Store: f.store, Hasher: f.hasher, Now: f.clock.Now, NewToken: ids.New,
		IdleTimeout: DefaultIdleTimeout, AbsoluteTimeout: DefaultAbsoluteTimeout, MaxSessions: DefaultMaxSessions,
		MaxAnonymous: DefaultMaxAnonymous, AnonymousTTL: DefaultAnonymousTTL,
	}
	if change != nil {
		change(&opts)
	}
	svc, err := NewService(testAccount(), opts)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

func (f fixture) login(t *testing.T) Session {
	t.Helper()
	_, session, err := f.svc.Login(t.Context(), "operator", testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	return session
}
func (s *fakeStore) setErr(err error) { s.mu.Lock(); defer s.mu.Unlock(); s.err = err }

func (s *fakeStore) calls() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Account(nil), s.replaced...)
}
