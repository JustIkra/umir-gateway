package operator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
)

func TestLoginKeepsThePreviousSessionWhenTokensFail(t *testing.T) {
	for _, failing := range []int{1, 2} { // the new session ID, then its CSRF token
		t.Run(fmt.Sprintf("token %d", failing), func(t *testing.T) {
			f := newFixture(t, nil)
			previous := f.login(t) // takes token requests 1 and 2
			f.tokens.failCall(2 + failing)
			if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, previous.ID); err == nil {
				t.Fatal("login succeeded without its tokens")
			}
			if _, _, err := f.svc.Authenticate(previous.ID); err != nil {
				t.Errorf("a failed login ended the previous session: %v", err)
			}
			if n := len(f.svc.sessions); n != 1 {
				t.Errorf("sessions = %d, want only the previous one", n)
			}
		})
	}
}

// loginWaitsForLock reports whether a goroutine inside Login is blocked on a mutex.
func loginWaitsForLock() bool {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("sync.(*Mutex).")) && bytes.Contains(g, []byte("operator.(*Service).Login(")) {
			return true
		}
	}
	return false
}

func TestLoginCancelledWhileWaitingForTheStateLockCreatesNoSession(t *testing.T) {
	f := newFixture(t, nil)
	previous := f.login(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Verification ends with the state lock held by the test, so Login passes its cancellation check
	// outside the lock and then waits for the lock.
	locked := make(chan struct{})
	f.hasher.setOnVerify(func() { f.svc.mu.Lock(); close(locked) })
	done := make(chan error, 1)
	go func() {
		_, _, err := f.svc.Login(ctx, "operator", testPassword, previous.ID)
		done <- err
	}()
	<-locked
	waitUntil(t, "login waiting for the state lock", loginWaitsForLock)
	cancel()
	f.svc.mu.Unlock()
	if err := receive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("Login = %v, want context.Canceled", err)
	}
	f.hasher.setOnVerify(nil)
	if _, _, err := f.svc.Authenticate(previous.ID); err != nil {
		t.Errorf("a cancelled login ended the previous session: %v", err)
	}
	if n := len(f.svc.sessions); n != 1 {
		t.Errorf("sessions = %d, want only the previous one", n)
	}
}
