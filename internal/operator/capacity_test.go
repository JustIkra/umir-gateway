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
	return s.gate.waiting
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
	waitUntil(t, "password change waiting", func() bool { return f.svc.waitingForTest() == 2 })
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
