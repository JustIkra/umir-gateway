package operator

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitUntil polls state guarded by the service mutex; it fails the test after five seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// receive fails the test instead of hanging when a login never finishes, for example on a leaked slot.
func receive(t *testing.T, results <-chan error) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("login did not finish within five seconds")
		return nil
	}
}

func (s *Service) waitingForTest() int {
	s.gate.mu.Lock()
	defer s.gate.mu.Unlock()
	return s.gate.waitingLogins
}

func (s *Service) waitingChangesForTest() int {
	s.gate.mu.Lock()
	defer s.gate.mu.Unlock()
	return s.gate.waitingChanges
}

func (s *Service) failuresForTest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.throttle.failures)
}

// blockVerifications holds every verification until release is closed and reports the peak concurrency.
type blockVerifications struct {
	mu      sync.Mutex
	active  int
	peak    int
	release chan struct{}
}

func (b *blockVerifications) hook() {
	b.mu.Lock()
	b.active++
	b.peak = max(b.peak, b.active)
	b.mu.Unlock()
	<-b.release
	b.mu.Lock()
	b.active--
	b.mu.Unlock()
}

func (b *blockVerifications) running() int { b.mu.Lock(); defer b.mu.Unlock(); return b.active }

func TestVerificationCapacity(t *testing.T) {
	f := newFixture(t, nil)
	block := &blockVerifications{release: make(chan struct{})}
	f.hasher.setOnVerify(block.hook)
	results := make(chan error, 10)
	for range 10 {
		go func() {
			_, _, err := f.svc.Login(context.Background(), "operator", testPassword, "")
			results <- err
		}()
	}
	waitUntil(t, "2 running and 8 queued logins", func() bool { return block.running() == 2 && f.svc.waitingForTest() == 8 })

	_, _, err := f.svc.Login(t.Context(), "operator", testPassword, "")
	var limited *RateLimitError
	if !errors.As(err, &limited) || !errors.Is(err, ErrLoginRateLimited) || limited.RetryAfter != time.Second {
		t.Fatalf("eleventh login = %v", err)
	}
	if f.svc.failuresForTest() != 0 {
		t.Error("full queue counted as a failed credential")
	}
	close(block.release)
	for range 10 {
		if err := receive(t, results); err != nil {
			t.Errorf("queued login: %v", err)
		}
	}
	if block.peak != 2 {
		t.Errorf("peak concurrent verifications = %d", block.peak)
	}
}

func TestCancelledQueuedLoginCreatesNoSession(t *testing.T) {
	f := newFixture(t, nil)
	block := &blockVerifications{release: make(chan struct{})}
	f.hasher.setOnVerify(block.hook)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, _, err := f.svc.Login(context.Background(), "operator", testPassword, "")
			results <- err
		}()
	}
	waitUntil(t, "2 running logins", func() bool { return block.running() == 2 })
	ctx, cancel := context.WithCancel(context.Background())
	queued := make(chan error, 1)
	go func() {
		_, _, err := f.svc.Login(ctx, "operator", testPassword, "")
		queued <- err
	}()
	waitUntil(t, "1 queued login", func() bool { return f.svc.waitingForTest() == 1 })
	cancel()
	if err := receive(t, queued); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled login = %v", err)
	}
	close(block.release)
	for range 2 {
		if err := receive(t, results); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.svc.sessions) != 2 || f.svc.waitingForTest() != 0 || f.svc.failuresForTest() != 0 {
		t.Errorf("sessions=%d waiting=%d failures=%d", len(f.svc.sessions), f.svc.waitingForTest(), f.svc.failuresForTest())
	}
}

func TestPasswordChangeWaitsForSlotWithoutQueueBound(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxQueuedLogins = 1 })
	session := f.login(t)
	block := &blockVerifications{release: make(chan struct{})}
	f.hasher.setOnVerify(block.hook)
	results := make(chan error, 3)
	for range 3 { // 2 running, 1 queued: the login queue is full
		go func() {
			_, _, err := f.svc.Login(context.Background(), "operator", testPassword, "")
			results <- err
		}()
	}
	waitUntil(t, "full login queue", func() bool { return block.running() == 2 && f.svc.waitingForTest() == 1 })
	changed := make(chan error, 1)
	go func() { changed <- f.svc.ChangePassword(context.Background(), session.ID, testPassword, newPassword) }()
	waitUntil(t, "password change waiting outside the login queue", func() bool {
		return f.svc.waitingForTest() == 1 && f.svc.waitingChangesForTest() == 1
	})
	close(block.release)
	if err := receive(t, changed); err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}
	for range 3 {
		// A login may lose the race with the password change; only its completion matters here.
		if err := receive(t, results); err != nil {
			t.Logf("login during password change: %v", err)
		}
	}
}

func TestFailedLoginThrottle(t *testing.T) {
	f := newFixture(t, nil)
	fail := func() error {
		_, _, err := f.svc.Login(t.Context(), "operator", "wrong password value", "")
		return err
	}
	for i := range 4 {
		if err := fail(); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d = %v", i+1, err)
		}
	}
	if _, _, err := f.svc.Login(t.Context(), "nobody", strings.Repeat("я", 33), ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("fifth failure = %v", err) // unknown login with an over-long password still counts
	}
	verifications := len(f.hasher.verifiedHashes())
	_, _, err := f.svc.Login(t.Context(), "operator", testPassword, "")
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.RetryAfter != 60*time.Second {
		t.Fatalf("login during cooldown = %v", err)
	}
	if len(f.hasher.verifiedHashes()) != verifications {
		t.Error("cooldown still verified the password")
	}
	f.clock.Advance(59*time.Second + 500*time.Millisecond)
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, ""); !errors.As(err, &limited) || limited.RetryAfter != time.Second {
		t.Fatalf("near the end of cooldown = %v", err)
	}
	f.clock.Advance(500 * time.Millisecond)
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, ""); err != nil {
		t.Fatalf("after cooldown = %v", err)
	}
}

func TestThrottleWindowRollsAndSuccessResets(t *testing.T) {
	f := newFixture(t, nil)
	fail := func() {
		t.Helper()
		if _, _, err := f.svc.Login(t.Context(), "operator", "wrong password value", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure = %v", err)
		}
	}
	for range 4 {
		fail()
	}
	f.clock.Advance(60 * time.Second) // the first four leave the rolling window
	fail()
	if f.svc.failuresForTest() != 1 {
		t.Fatalf("failures in window = %d", f.svc.failuresForTest())
	}
	for range 3 {
		fail()
	}
	f.login(t) // success clears the counter
	for range 4 {
		fail()
	}
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, ""); err != nil {
		t.Fatalf("four failures after a success must not throttle: %v", err)
	}
}

func TestCooldownStopsLoginsQueuedBeforeIt(t *testing.T) {
	f := newFixture(t, nil)
	for range DefaultFailureLimit - 1 {
		if _, _, err := f.svc.Login(t.Context(), "operator", "wrong password value", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("prior failure = %v", err)
		}
	}
	block := &blockVerifications{release: make(chan struct{})}
	f.hasher.setOnVerify(block.hook)
	before := len(f.hasher.verifiedHashes())
	login := func(password string, results chan<- error) {
		_, _, err := f.svc.Login(context.Background(), "operator", password, "")
		results <- err
	}
	results := make(chan error, 10)
	for range 2 {
		go login("wrong password value", results)
	}
	waitUntil(t, "2 running logins", func() bool { return block.running() == 2 })
	for range 7 {
		go login("wrong password value", results)
	}
	go login(testPassword, results) // queued before the cooldown, must not get a session during it
	waitUntil(t, "8 queued logins", func() bool { return f.svc.waitingForTest() == 8 })
	close(block.release)
	var invalid, limited int
	for range 10 {
		switch err := receive(t, results); {
		case errors.Is(err, ErrInvalidCredentials):
			invalid++
		case errors.Is(err, ErrLoginRateLimited):
			limited++
		default:
			t.Errorf("unexpected result: %v", err)
		}
	}
	if verified := len(f.hasher.verifiedHashes()) - before; verified != 2 || invalid != 2 || limited != 8 {
		t.Errorf("verified=%d invalid=%d limited=%d, want 2, 2, 8", verified, invalid, limited)
	}
	if len(f.svc.sessions) != 0 {
		t.Error("a login queued before the cooldown got a session during it")
	}
}

func TestWrongCurrentPasswordsRevokeTheSession(t *testing.T) {
	f := newFixture(t, nil)
	session, other := f.login(t), f.login(t)
	for i := range DefaultFailureLimit {
		if err := f.svc.ChangePassword(t.Context(), session.ID, "wrong current value", newPassword); !errors.Is(err, ErrCurrentPasswordIncorrect) {
			t.Fatalf("wrong current password %d = %v", i+1, err)
		}
	}
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, newPassword); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("change after %d wrong current passwords = %v", DefaultFailureLimit, err)
	}
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("guessing session still valid: %v", err)
	}
	if _, _, err := f.svc.Authenticate(other.ID); err != nil {
		t.Errorf("other session revoked: %v", err)
	}
	if len(f.store.calls()) != 0 {
		t.Error("store called for rejected changes")
	}
}

func TestPasswordChangesDoNotShrinkLoginQueue(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	block := &blockVerifications{release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(block.release) })
	t.Cleanup(release)
	f.hasher.setOnVerify(block.hook)
	logins := make(chan error, 10)
	login := func() {
		_, _, err := f.svc.Login(context.Background(), "operator", testPassword, "")
		logins <- err
	}
	for range 2 {
		go login()
	}
	waitUntil(t, "2 running logins", func() bool { return block.running() == 2 })
	changes := make(chan error, 12)
	for range 12 { // one session sends many parallel changes
		go func() { changes <- f.svc.ChangePassword(context.Background(), session.ID, testPassword, newPassword) }()
	}
	for range 8 {
		go login()
	}
	waitUntil(t, "8 queued logins beside pending password changes", func() bool { return f.svc.waitingForTest() == 8 })
	release()
	for range 10 {
		if err := receive(t, logins); err != nil {
			t.Logf("login during password change: %v", err)
		}
	}
	var changed, unauthenticated int
	for range 12 {
		switch err := receive(t, changes); {
		case err == nil:
			changed++
		case errors.Is(err, ErrUnauthenticated):
			unauthenticated++
		default:
			t.Errorf("unexpected change result: %v", err)
		}
	}
	if changed != 1 || unauthenticated != 11 {
		t.Errorf("changed=%d unauthenticated=%d, want 1 and 11", changed, unauthenticated)
	}
}
