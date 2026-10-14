package operator

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// recordingObserver keeps every call as text; onCall, when set, runs inside the call.
type recordingObserver struct {
	mu     sync.Mutex
	calls  []string
	onCall func()
}

func (o *recordingObserver) SessionExtended(key string, _ uint64, idle, absolute time.Time) {
	o.add(fmt.Sprintf("extended %s idle %s absolute %s", key, idle.Format(time.TimeOnly), absolute.Format(time.TimeOnly)))
}

func (o *recordingObserver) SessionEnded(key string, _ uint64, reason EndReason) {
	o.add(fmt.Sprintf("ended %s %s", key, reason))
}

func (o *recordingObserver) add(call string) {
	o.mu.Lock()
	o.calls = append(o.calls, call)
	hook := o.onCall
	o.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// take returns the calls so far and forgets them.
func (o *recordingObserver) take() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	calls := o.calls
	o.calls = nil
	return calls
}

func observed(t *testing.T, change func(*Options)) (fixture, *recordingObserver) {
	t.Helper()
	observer := &recordingObserver{}
	f := newFixture(t, func(o *Options) {
		o.Observer = observer
		if change != nil {
			change(o)
		}
	})
	return f, observer
}

func TestPeekNeitherExtendsNorStores(t *testing.T) {
	f, observer := observed(t, nil)
	login := f.clock.Now()
	session := f.login(t)
	observer.take()
	stored := len(f.store.states())
	f.clock.Advance(10 * time.Minute)
	profile, peeked, err := f.svc.Peek(session.ID)
	if err != nil || profile.Login != "operator" || peeked.CSRFToken != session.CSRFToken {
		t.Fatalf("Peek = %+v, %+v, %v", profile, peeked, err)
	}
	wantDeadlines(t, peeked, login.Add(30*time.Minute), login.Add(8*time.Hour))
	if got := len(f.store.states()); got != stored {
		t.Errorf("Peek stored %d states", got-stored)
	}
	if calls := observer.take(); len(calls) != 0 {
		t.Errorf("Peek notified %v", calls)
	}
	// The idle deadline Peek left alone still ends the session.
	f.clock.Advance(20 * time.Minute)
	if _, _, err := f.svc.Peek(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Peek after 30 idle minutes = %v", err)
	}
}

func TestPeekRejectsLikeAuthenticate(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	for _, id := range []string{"", "token-999", session.CSRFToken} {
		if _, _, err := f.svc.Peek(id); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Peek(%q) = %v", id, err)
		}
	}
	f.store.setErr(errors.New("rename outcome unknown"))
	if _, err := f.svc.UpdateDisplayName(session.ID, "Смена"); !errors.Is(err, ErrUpdateOutcomeUnknown) {
		t.Fatalf("UpdateDisplayName = %v", err)
	}
	if _, _, err := f.svc.Peek(session.ID); !errors.Is(err, ErrAuthUnavailable) {
		t.Errorf("Peek during recovery = %v", err)
	}
}

func TestObserverHearsExtensionsByUserRequests(t *testing.T) {
	f, observer := observed(t, nil)
	login := f.clock.Now()
	session := f.login(t)
	key := SessionKey(session.ID)
	observer.take()
	steps := []struct {
		name string
		call func() error
	}{
		{"Authenticate", func() error { _, _, err := f.svc.Authenticate(session.ID); return err }},
		{"Authorize", func() error { _, _, err := f.svc.Authorize(session.ID, session.CSRFToken); return err }},
		{"Current", func() error { _, _, err := f.svc.Current(session.ID); return err }},
		{"UpdateDisplayName", func() error { _, err := f.svc.UpdateDisplayName(session.ID, "Смена"); return err }},
	}
	for _, step := range steps {
		f.clock.Advance(time.Minute)
		if err := step.call(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		want := fmt.Sprintf("extended %s idle %s absolute %s", key,
			f.clock.Now().Add(30*time.Minute).Format(time.TimeOnly), login.Add(8*time.Hour).Format(time.TimeOnly))
		if calls := observer.take(); !slices.Equal(calls, []string{want}) {
			t.Errorf("%s notified %v, want %q", step.name, calls, want)
		}
	}
	// A request at the instant already stored moves nothing and reports nothing.
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		t.Fatal(err)
	}
	if calls := observer.take(); len(calls) != 0 {
		t.Errorf("unchanged deadline notified %v", calls)
	}
}

func TestObserverIgnoresRememberedSessions(t *testing.T) {
	f, observer := observed(t, nil)
	_, session, err := f.svc.Login(t.Context(), "operator", testPassword, "", true)
	if err != nil {
		t.Fatal(err)
	}
	observer.take()
	f.clock.Advance(time.Minute)
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Current(session.ID); err != nil {
		t.Fatal(err)
	}
	if calls := observer.take(); len(calls) != 0 {
		t.Errorf("remembered session notified %v", calls)
	}
}

func TestObserverHearsEndedSessions(t *testing.T) {
	t.Run("sign-out", func(t *testing.T) {
		f, observer := observed(t, nil)
		session := f.login(t)
		observer.take()
		if err := f.svc.Logout(session.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.svc.Logout(session.ID); err != nil { // nothing left to end
			t.Fatal(err)
		}
		if calls := observer.take(); !slices.Equal(calls, []string{"ended " + SessionKey(session.ID) + " signed_out"}) {
			t.Errorf("calls = %v", calls)
		}
	})
	t.Run("sign-in that replaces the session", func(t *testing.T) {
		f, observer := observed(t, nil)
		first := f.login(t)
		observer.take()
		if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, first.ID, false); err != nil {
			t.Fatal(err)
		}
		if calls := observer.take(); !slices.Equal(calls, []string{"ended " + SessionKey(first.ID) + " signed_out"}) {
			t.Errorf("calls = %v", calls)
		}
	})
	t.Run("eviction at the bound", func(t *testing.T) {
		f, observer := observed(t, func(o *Options) { o.MaxSessions = 2 })
		oldest := f.login(t)
		f.clock.Advance(time.Second)
		f.login(t)
		observer.take()
		f.clock.Advance(time.Second)
		f.login(t)
		if calls := observer.take(); !slices.Equal(calls, []string{"ended " + SessionKey(oldest.ID) + " revoked"}) {
			t.Errorf("calls = %v", calls)
		}
	})
	t.Run("password change", func(t *testing.T) {
		f, observer := observed(t, nil)
		first := f.login(t)
		second := f.login(t)
		observer.take()
		if err := f.svc.ChangePassword(t.Context(), first.ID, testPassword, "new password value"); err != nil {
			t.Fatal(err)
		}
		calls := observer.take()
		slices.Sort(calls)
		want := []string{"ended " + SessionKey(first.ID) + " revoked", "ended " + SessionKey(second.ID) + " revoked"}
		slices.Sort(want)
		if !slices.Equal(calls, want) {
			t.Errorf("calls = %v, want %v", calls, want)
		}
	})
	t.Run("fifth wrong current password", func(t *testing.T) {
		f, observer := observed(t, nil)
		session := f.login(t)
		other := f.login(t)
		observer.take()
		for range DefaultFailureLimit {
			if err := f.svc.ChangePassword(t.Context(), session.ID, "wrong password value", "new password value"); err == nil {
				t.Fatal("wrong current password accepted")
			}
		}
		if calls := observer.take(); !slices.Equal(calls, []string{"ended " + SessionKey(session.ID) + " revoked"}) {
			t.Errorf("calls = %v; %s stays signed in", calls, SessionKey(other.ID))
		}
	})
}

func TestObserverHearsNothingWhenTheCommitFails(t *testing.T) {
	f, observer := observed(t, nil)
	session := f.login(t)
	observer.take()
	f.clock.Advance(time.Minute)
	f.store.setErr(fmt.Errorf("disk full: %w", ErrStorageUnavailable))
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrSessionStorageUnavailable) {
		t.Fatalf("Authenticate = %v", err)
	}
	if err := f.svc.Logout(session.ID); !errors.Is(err, ErrSessionStorageUnavailable) {
		t.Fatalf("Logout = %v", err)
	}
	if calls := observer.take(); len(calls) != 0 {
		t.Errorf("failed commits notified %v", calls)
	}
}

func TestObserverRunsOutsideTheServiceMutex(t *testing.T) {
	f, observer := observed(t, nil)
	session := f.login(t)
	peeked := make(chan error, 1)
	observer.mu.Lock()
	observer.onCall = func() {
		_, _, err := f.svc.Peek(session.ID)
		peeked <- err
	}
	observer.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- f.svc.Logout(session.ID) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observer called under the service mutex: Logout deadlocked")
	}
	if err := <-peeked; !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("observer saw the session before the commit: %v", err)
	}
}
