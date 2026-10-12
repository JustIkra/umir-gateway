package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func digestOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

var errDiskFull = fmt.Errorf("%w: disk full", ErrStorageUnavailable)

func TestLoginCommitsOnlyTheTokenDigest(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	state := f.store.last()
	if len(state.Sessions) != 1 || state.Sessions[0].Digest != digestOf(session.ID) || state.Sessions[0].RememberMe {
		t.Fatalf("stored sessions = %+v", state.Sessions)
	}
	if stored := fmt.Sprintf("%+v", state); strings.Contains(stored, session.ID) || strings.Contains(stored, session.CSRFToken) {
		t.Errorf("the store received a raw token: %s", stored)
	}
	if session.CSRFToken == session.ID || session.RememberMe {
		t.Errorf("session = %+v", session)
	}
}

func TestLoginStorageFailureKeepsThePreviousSession(t *testing.T) {
	f := newFixture(t, nil)
	previous := f.login(t)
	f.store.setErr(errDiskFull)
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, previous.ID, false); !errors.Is(err, ErrSessionStorageUnavailable) {
		t.Fatalf("Login = %v, want ErrSessionStorageUnavailable", err)
	}
	if _, _, err := f.svc.Authenticate(previous.ID); err != nil {
		t.Errorf("previous session after a definite failure: %v", err)
	}
	if n := len(f.svc.sessions); n != 1 {
		t.Errorf("sessions = %d, want only the previous one", n)
	}
	f.store.setErr(errors.New("rename outcome unknown"))
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, previous.ID, false); !errors.Is(err, ErrSessionUpdateOutcomeUnknown) {
		t.Fatalf("Login = %v, want ErrSessionUpdateOutcomeUnknown", err)
	}
	if _, _, err := f.svc.Authenticate(previous.ID); !errors.Is(err, ErrAuthUnavailable) {
		t.Errorf("after an unknown outcome: %v, want recovery", err)
	}
}

func TestRememberedSessionHasAFixedThirtyDayDeadline(t *testing.T) {
	f := newFixture(t, nil)
	start := f.clock.Now()
	_, session, err := f.svc.Login(t.Context(), "operator", testPassword, "", true)
	if err != nil {
		t.Fatal(err)
	}
	deadline := start.Add(30 * 24 * time.Hour)
	if !session.RememberMe || !session.AbsoluteExpiresAt.Equal(deadline) || !session.IdleExpiresAt.Equal(deadline) || !session.ExpiresAt.Equal(deadline) {
		t.Fatalf("session = %+v", session)
	}
	writes := len(f.store.states())
	// Daily activity neither ends the session after 30 idle minutes nor moves its deadline.
	for range 29 {
		f.clock.Advance(24 * time.Hour)
		_, got, err := f.svc.Current(session.ID)
		if err != nil || !got.AbsoluteExpiresAt.Equal(deadline) || !got.ExpiresAt.Equal(deadline) {
			t.Fatalf("after %v: %+v, %v", f.clock.Now().Sub(start), got, err)
		}
	}
	if len(f.store.states()) != writes {
		t.Errorf("reading a remembered session wrote the store")
	}
	f.clock.Advance(24 * time.Hour)
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("after 30 days: %v", err)
	}
}

func TestCurrentStoresTheOrdinaryIdleDeadlineBeforeReportingIt(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	writes := len(f.store.states())
	f.clock.Advance(10 * time.Minute)
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.store.states()) != writes {
		t.Errorf("a business request wrote the store")
	}
	f.clock.Advance(10 * time.Minute)
	_, got, err := f.svc.Current(session.ID)
	if err != nil || !got.IdleExpiresAt.Equal(f.clock.Now().Add(30*time.Minute)) {
		t.Fatalf("Current = %+v, %v", got, err)
	}
	if stored := f.store.last().Sessions; len(stored) != 1 || !stored[0].LastSeen.Equal(f.clock.Now()) {
		t.Errorf("stored sessions = %+v, want the reported activity", stored)
	}
}

func TestCurrentReportsTheStoredDeadlineWhileStorageFails(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.clock.Advance(5 * time.Minute)
	if _, _, err := f.svc.Current(session.ID); err != nil {
		t.Fatal(err)
	}
	stored := f.clock.Now().Add(DefaultIdleTimeout)
	f.clock.Advance(5 * time.Minute)
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		t.Fatal(err)
	}
	f.store.setErr(errDiskFull)
	f.clock.Advance(time.Minute)
	_, got, err := f.svc.Current(session.ID)
	if err != nil || !got.IdleExpiresAt.Equal(stored) || !got.ExpiresAt.Equal(stored) {
		t.Fatalf("Current with a failing store = %+v, %v; want the stored deadline %v", got, err, stored)
	}
	// Once the store works again, the renewed deadline is stored and reported.
	f.store.setErr(nil)
	f.clock.Advance(time.Minute)
	if _, got, err = f.svc.Current(session.ID); err != nil || !got.IdleExpiresAt.Equal(f.clock.Now().Add(DefaultIdleTimeout)) {
		t.Fatalf("Current after the store recovered = %+v, %v", got, err)
	}
}

func TestSessionsSurviveARestart(t *testing.T) {
	f := newFixture(t, nil)
	ordinary := f.login(t)
	_, remembered, err := f.svc.Login(t.Context(), "operator", testPassword, "", true)
	if err != nil {
		t.Fatal(err)
	}
	restarted := f.restart(t)
	for _, s := range []Session{ordinary, remembered} {
		if _, got, err := restarted.Authenticate(s.ID); err != nil || got.CSRFToken != s.CSRFToken || got.RememberMe != s.RememberMe {
			t.Errorf("restored %+v: %+v, %v", s, got, err)
		}
		if token, ok := restarted.SessionCSRF(s.ID); !ok || token != s.CSRFToken {
			t.Errorf("restored CSRF token = %q, %v", token, ok)
		}
	}
	// Nine hours later only the remembered session can be restored.
	f.clock.Advance(9 * time.Hour)
	restarted = f.restart(t)
	if _, _, err := restarted.Authenticate(ordinary.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expired ordinary session restored: %v", err)
	}
	if _, _, err := restarted.Authenticate(remembered.ID); err != nil {
		t.Errorf("remembered session after 9 hours: %v", err)
	}
}

func TestRestoreDropsStaleRecords(t *testing.T) {
	f := newFixture(t, nil)
	now := f.clock.Now()
	account := testAccount()
	account.CredentialVersion = 2
	record := func(token string, version int64, expires time.Time) StoredSession {
		return StoredSession{Digest: digestOf(token), CredentialVersion: version, Created: now.Add(-time.Hour), LastSeen: now.Add(-time.Minute), ExpiresAt: expires}
	}
	svc, err := NewService(State{Account: account, Sessions: []StoredSession{
		record("old-password", 1, now.Add(time.Hour)),
		record("expired", 2, now),
		record("valid", 2, now.Add(time.Hour)),
	}}, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Authenticate("valid"); err != nil {
		t.Errorf("valid record: %v", err)
	}
	for _, token := range []string{"old-password", "expired"} {
		if _, _, err := svc.Authenticate(token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s record restored: %v", token, err)
		}
	}
}

func TestSessionLimitCoversBothModesAndIsStored(t *testing.T) {
	f := newFixture(t, nil)
	var first Session
	for i := range DefaultMaxSessions + 1 {
		_, s, err := f.svc.Login(t.Context(), "operator", testPassword, "", i%2 == 1)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = s
		}
		f.clock.Advance(time.Second)
	}
	if got := len(f.store.last().Sessions); got != DefaultMaxSessions {
		t.Errorf("stored sessions = %d, want %d", got, DefaultMaxSessions)
	}
	if _, _, err := f.restart(t).Authenticate(first.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("the evicted session came back after a restart: %v", err)
	}
}

func TestLogoutIsStoredBeforeItSucceeds(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.store.setErr(errDiskFull)
	if err := f.svc.Logout(session.ID); !errors.Is(err, ErrSessionStorageUnavailable) {
		t.Fatalf("Logout = %v, want ErrSessionStorageUnavailable", err)
	}
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		t.Errorf("a failed logout ended the session: %v", err)
	}
	f.store.setErr(nil)
	if err := f.svc.Logout(session.ID); err != nil {
		t.Fatal(err)
	}
	if stored := f.store.last().Sessions; len(stored) != 0 {
		t.Errorf("stored sessions after logout = %+v", stored)
	}
	if _, _, err := f.restart(t).Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("logged-out session came back after a restart: %v", err)
	}
}

func TestLogoutDuringRecovery(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.store.setErr(errors.New("rename outcome unknown"))
	if _, err := f.svc.UpdateDisplayName(session.ID, "Смена"); !errors.Is(err, ErrUpdateOutcomeUnknown) {
		t.Fatalf("UpdateDisplayName = %v", err)
	}
	if err := f.svc.Logout(""); err != nil {
		t.Errorf("logout without a session during recovery = %v", err)
	}
	if err := f.svc.Logout(session.ID); !errors.Is(err, ErrAuthUnavailable) {
		t.Errorf("logout of a session during recovery = %v, want ErrAuthUnavailable", err)
	}
}

func TestPasswordChangeStoresNoSessions(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, "", true); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	if last := f.store.last(); len(last.Sessions) != 0 || last.Account.CredentialVersion != 2 {
		t.Errorf("stored state = %+v", last)
	}
}

func TestBackwardClockStepKeepsTheStoredStateLoadable(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	writes := len(f.store.states())
	f.clock.Advance(-2 * time.Second)
	if _, _, err := f.svc.Current(session.ID); err != nil {
		t.Fatalf("Current after the clock stepped back = %v", err)
	}
	if len(f.store.states()) == writes {
		t.Fatal("Current stored nothing")
	}
	if err := ValidateState(f.store.last()); err != nil {
		t.Fatalf("stored state: %v", err)
	}
	f.restart(t)
}

func TestCommitNeverStoresAStateTheLoaderRejects(t *testing.T) {
	f := newFixture(t, nil)
	broken, other := f.login(t), f.login(t)
	f.svc.mu.Lock()
	f.svc.sessions[digestOf(broken.ID)].created = time.Time{}
	f.svc.mu.Unlock()
	writes := len(f.store.states())
	if err := f.svc.Logout(other.ID); !errors.Is(err, ErrSessionStorageUnavailable) {
		t.Fatalf("Logout = %v", err)
	}
	if len(f.store.states()) != writes {
		t.Error("an invalid state was stored")
	}
	if _, _, err := f.svc.Authenticate(other.ID); err != nil {
		t.Errorf("session after the refused commit: %v", err)
	}
}

func TestLogoutOfAnExpiredSessionStoresNothing(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.clock.Advance(DefaultIdleTimeout)
	f.store.setErr(fmt.Errorf("%w: lost reply", ErrUpdateOutcomeUnknown))
	if err := f.svc.Logout(session.ID); err != nil {
		t.Fatalf("Logout of an expired session = %v", err)
	}
	f.store.setErr(nil)
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, "", false); err != nil {
		t.Errorf("login after the logout: %v", err)
	}
}
