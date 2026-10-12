package operator

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const wrongCurrent = "wrong current value"

// failPasswordChanges sends n wrong current passwords from session id, one second apart.
func (f fixture) failPasswordChanges(t *testing.T, id string, n int) {
	t.Helper()
	for i := range n {
		if err := f.svc.ChangePassword(t.Context(), id, wrongCurrent, newPassword); !errors.Is(err, ErrCurrentPasswordIncorrect) {
			t.Fatalf("wrong current password %d = %v", i+1, err)
		}
		f.clock.Advance(time.Second)
	}
}

func TestPasswordChangeLimit(t *testing.T) {
	f := newFixture(t, nil)
	caller, other := f.login(t), f.login(t)
	f.failPasswordChanges(t, caller.ID, DefaultFailureLimit-1)
	// The fifth wrong password within 60 seconds revokes only the calling session and changes nothing else.
	writes := len(f.store.states())
	var limited *PasswordChangeLimitError
	err := f.svc.ChangePassword(t.Context(), caller.ID, wrongCurrent, newPassword)
	if !errors.As(err, &limited) || limited.RetryAfter != DefaultCooldown || !limited.SessionRevoked {
		t.Fatalf("fifth wrong password = %v", err)
	}
	if len(f.store.states()) != writes+1 || f.store.last().Account != testAccount() {
		t.Errorf("stored %d states, account %+v; want one revocation and the same account", len(f.store.states())-writes, f.store.last().Account)
	}
	if _, _, err := f.svc.Authenticate(caller.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("calling session after the limit: %v", err)
	}
	if stored := f.store.last().Sessions; len(stored) != 1 || stored[0].Digest != digestOf(other.ID) {
		t.Errorf("stored sessions = %+v, want only the other session", stored)
	}
	// During the cooldown every change is refused before any password check and revokes nothing.
	f.clock.Advance(20*time.Second + 500*time.Millisecond)
	verified := len(f.hasher.verifiedHashes())
	err = f.svc.ChangePassword(t.Context(), other.ID, testPassword, newPassword)
	if !errors.As(err, &limited) || limited.RetryAfter != 40*time.Second || limited.SessionRevoked {
		t.Fatalf("change during the cooldown = %v", err)
	}
	if len(f.hasher.verifiedHashes()) != verified {
		t.Error("a password was checked during the cooldown")
	}
	if _, _, err := f.svc.Authenticate(other.ID); err != nil {
		t.Errorf("other session during the cooldown: %v", err)
	}
	// A fresh login is not blocked by the cooldown and does not bypass it.
	fresh := f.login(t)
	if err := f.svc.ChangePassword(t.Context(), fresh.ID, testPassword, newPassword); !errors.As(err, &limited) || limited.SessionRevoked {
		t.Fatalf("change from a fresh login during the cooldown = %v", err)
	}
	f.clock.Advance(40 * time.Second)
	if err := f.svc.ChangePassword(t.Context(), other.ID, testPassword, newPassword); err != nil {
		t.Fatalf("change after the cooldown = %v", err)
	}
}

func TestPasswordChangeLimitIsOperatorWide(t *testing.T) {
	f := newFixture(t, nil)
	first, second := f.login(t), f.login(t)
	f.failPasswordChanges(t, first.ID, 2)
	f.failPasswordChanges(t, second.ID, 2)
	var limited *PasswordChangeLimitError
	if err := f.svc.ChangePassword(t.Context(), second.ID, wrongCurrent, newPassword); !errors.As(err, &limited) || !limited.SessionRevoked {
		t.Fatalf("fifth wrong password across sessions = %v", err)
	}
	if _, _, err := f.svc.Authenticate(first.ID); err != nil {
		t.Errorf("a session that did not make the fifth attempt was revoked: %v", err)
	}
}

func TestPasswordChangeLimitCountsOnlyCredentialChecks(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	for range 10 {
		if err := f.svc.ChangePassword(t.Context(), session.ID, wrongCurrent, "short"); errors.Is(err, ErrCurrentPasswordIncorrect) {
			t.Fatal("an invalid new password reached the current password check")
		}
		if err := f.svc.ChangePassword(t.Context(), "unknown", wrongCurrent, newPassword); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("unknown session = %v", err)
		}
	}
	f.failPasswordChanges(t, session.ID, DefaultFailureLimit-1)
}

func TestOverlongCurrentPasswordCountsTowardsTheLimit(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.failPasswordChanges(t, session.ID, DefaultFailureLimit-1)
	var limited *PasswordChangeLimitError
	err := f.svc.ChangePassword(t.Context(), session.ID, strings.Repeat("x", maxPassword+1), newPassword)
	if !errors.As(err, &limited) || !limited.SessionRevoked {
		t.Fatalf("fifth wrong password, overlong = %v", err)
	}
}

func TestLimitDoesNotClaimASessionThatEndedDuringVerification(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.failPasswordChanges(t, session.ID, DefaultFailureLimit-1)
	f.hasher.setOnVerify(func() {
		if err := f.svc.Logout(session.ID); err != nil {
			t.Errorf("logout during verification: %v", err)
		}
	})
	stored := len(f.store.calls())
	var limited *PasswordChangeLimitError
	err := f.svc.ChangePassword(t.Context(), session.ID, wrongCurrent, newPassword)
	if !errors.As(err, &limited) || limited.SessionRevoked {
		t.Fatalf("fifth wrong password after the session ended = %v", err)
	}
	if calls := len(f.store.calls()) - stored; calls != 1 {
		t.Errorf("store calls = %d, want only the logout", calls)
	}
}

func TestPasswordChangeLimitWindowRolls(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.failPasswordChanges(t, session.ID, DefaultFailureLimit-1)
	f.clock.Advance(DefaultFailureWindow)
	f.failPasswordChanges(t, session.ID, 1)
}

func TestFailedRevocationIsNotReportedAsRevoked(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.failPasswordChanges(t, session.ID, DefaultFailureLimit-1)
	f.store.setErr(errDiskFull)
	err := f.svc.ChangePassword(t.Context(), session.ID, wrongCurrent, newPassword)
	var limited *PasswordChangeLimitError
	if !errors.Is(err, ErrSessionStorageUnavailable) || errors.As(err, &limited) {
		t.Fatalf("fifth wrong password with a failing store = %v", err)
	}
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		t.Errorf("session after a failed revocation: %v", err)
	}
	f.store.setErr(nil)
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, newPassword); !errors.As(err, &limited) || limited.SessionRevoked {
		t.Errorf("the cooldown did not start: %v", err)
	}
}

func TestRecoveryDuringVerificationAnswersAuthUnavailable(t *testing.T) {
	for _, earlier := range []int{0, DefaultFailureLimit - 1} {
		f := newFixture(t, nil)
		caller, other := f.login(t), f.login(t)
		f.failPasswordChanges(t, caller.ID, earlier)
		f.hasher.setOnVerify(func() {
			f.store.setErr(fmt.Errorf("%w: lost reply", ErrUpdateOutcomeUnknown))
			if err := f.svc.Logout(other.ID); !errors.Is(err, ErrSessionUpdateOutcomeUnknown) {
				t.Errorf("logout = %v", err)
			}
		})
		if err := f.svc.ChangePassword(t.Context(), caller.ID, wrongCurrent, newPassword); !errors.Is(err, ErrAuthUnavailable) {
			t.Errorf("after %d wrong passwords, recovery during the verification = %v", earlier, err)
		}
	}
}

func TestLimitIgnoresASessionThatExpiredDuringVerification(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.IdleTimeout, o.AbsoluteTimeout = 10*time.Second, 10*time.Second })
	session := f.login(t)
	f.failPasswordChanges(t, session.ID, DefaultFailureLimit-1)
	// The session reaches its absolute deadline while the fifth password is verified.
	f.hasher.setOnVerify(func() {
		f.clock.Advance(6 * time.Second)
		f.store.setErr(errDiskFull)
	})
	var limited *PasswordChangeLimitError
	err := f.svc.ChangePassword(t.Context(), session.ID, wrongCurrent, newPassword)
	if !errors.As(err, &limited) || limited.SessionRevoked {
		t.Fatalf("fifth wrong password after the session expired = %v", err)
	}
}

func TestSuccessfulChangeClearsTheWrongPasswordCount(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.failPasswordChanges(t, session.ID, DefaultFailureLimit-1)
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	_, next, err := f.svc.Login(t.Context(), "operator", newPassword, "", false)
	if err != nil {
		t.Fatal(err)
	}
	f.failPasswordChanges(t, next.ID, 1)
}
