package operator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

const newPassword = "new correct horse battery staple" // 32 code points

func TestUpdateDisplayName(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	profile, err := f.svc.UpdateDisplayName(session.ID, "  Смена\u00a0 ")
	if err != nil || profile.DisplayName != "Смена" {
		t.Fatalf("UpdateDisplayName = %+v, %v", profile, err)
	}
	calls := f.store.calls()
	if len(calls) != 1 || calls[0].DisplayName != "Смена" || calls[0].CredentialVersion != 1 {
		t.Fatalf("store calls = %+v", calls)
	}
	if got, _, err := f.svc.Authenticate(session.ID); err != nil || got.DisplayName != "Смена" {
		t.Errorf("Authenticate = %+v, %v", got, err)
	}
}

func TestUpdateDisplayNameRejectsBeforeStorage(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	if _, err := f.svc.UpdateDisplayName(session.ID, "Я"); fieldOf(t, err) != "displayName" {
		t.Errorf("short name: %v", err)
	}
	if _, err := f.svc.UpdateDisplayName("unknown", "Смена"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("unknown session: %v", err)
	}
	if len(f.store.calls()) != 0 {
		t.Errorf("store called for rejected input")
	}
}

func TestDefiniteStorageFailureChangesNothing(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.store.setErr(fmt.Errorf("%w: disk full", ErrStorageUnavailable))
	if _, err := f.svc.UpdateDisplayName(session.ID, "Смена"); !errors.Is(err, ErrStorageUnavailable) || errors.Is(err, ErrUpdateOutcomeUnknown) {
		t.Fatalf("UpdateDisplayName = %v", err)
	}
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, newPassword); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("ChangePassword = %v", err)
	}
	profile, _, err := f.svc.Authenticate(session.ID)
	if err != nil || profile.DisplayName != "Оператор" {
		t.Fatalf("after failures: %+v, %v", profile, err)
	}
	f.store.setErr(nil)
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, ""); err != nil {
		t.Errorf("old password stopped working: %v", err)
	}
}

func TestUnknownOutcomeEntersRecovery(t *testing.T) {
	for name, storeErr := range map[string]error{
		"classified":   fmt.Errorf("%w: rename", ErrUpdateOutcomeUnknown),
		"unclassified": errors.New("unexpected store failure"),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			session := f.login(t)
			other := f.login(t)
			f.store.setErr(storeErr)
			if _, err := f.svc.UpdateDisplayName(session.ID, "Смена"); !errors.Is(err, ErrUpdateOutcomeUnknown) {
				t.Fatalf("UpdateDisplayName = %v", err)
			}
			f.store.setErr(nil)
			if _, _, err := f.svc.Authenticate(other.ID); !errors.Is(err, ErrAuthUnavailable) {
				t.Errorf("Authenticate = %v", err)
			}
			if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, ""); !errors.Is(err, ErrAuthUnavailable) {
				t.Errorf("Login = %v", err)
			}
			if _, err := f.svc.UpdateDisplayName(other.ID, "Смена"); !errors.Is(err, ErrAuthUnavailable) {
				t.Errorf("UpdateDisplayName = %v", err)
			}
			if err := f.svc.ChangePassword(t.Context(), other.ID, testPassword, newPassword); !errors.Is(err, ErrAuthUnavailable) {
				t.Errorf("ChangePassword = %v", err)
			}
			if len(f.svc.sessions) != 0 {
				t.Errorf("sessions from before recovery kept: %d", len(f.svc.sessions))
			}
		})
	}
}

func TestChangePasswordRevokesEverySession(t *testing.T) {
	f := newFixture(t, nil)
	session, other := f.login(t), f.login(t)
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	calls := f.store.calls()
	if len(calls) != 1 || calls[0].PasswordHash != "hash:"+newPassword || calls[0].CredentialVersion != 2 {
		t.Fatalf("store calls = %+v", calls)
	}
	for _, id := range []string{session.ID, other.ID} {
		if _, _, err := f.svc.Authenticate(id); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("session survived: %v", err)
		}
	}
	if _, _, err := f.svc.Login(t.Context(), "operator", testPassword, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("old password: %v", err)
	}
	if _, _, err := f.svc.Login(t.Context(), "operator", newPassword, ""); err != nil {
		t.Errorf("new password: %v", err)
	}
}

func TestChangePasswordRejections(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	if err := f.svc.ChangePassword(t.Context(), session.ID, "wrong current password", newPassword); !errors.Is(err, ErrCurrentPasswordIncorrect) {
		t.Errorf("wrong current: %v", err)
	}
	for _, rejected := range []string{"short12", strings.Repeat("я", 33)} {
		if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, rejected); fieldOf(t, err) != "newPassword" {
			t.Errorf("ChangePassword(%q) = %v", rejected, err)
		}
	}
	if err := f.svc.ChangePassword(t.Context(), "unknown", testPassword, newPassword); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("unknown session: %v", err)
	}
	f.hasher.hashErr = errors.New("entropy unavailable")
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, newPassword); !errors.Is(err, ErrStorageUnavailable) {
		t.Errorf("hash failure: %v", err)
	}
	if len(f.store.calls()) != 0 {
		t.Errorf("store called for rejected change")
	}
	if _, _, err := f.svc.Authenticate(session.ID); err != nil {
		t.Errorf("session revoked by a rejected change: %v", err)
	}
}

func TestPasswordIsStoredAndVerifiedRaw(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	decomposed := " pass e\u0301e\u0301 word " // spaces and a decomposed é are part of the password
	if err := f.svc.ChangePassword(t.Context(), session.ID, testPassword, decomposed); err != nil {
		t.Fatal(err)
	}
	if calls := f.store.calls(); len(calls) != 1 || calls[0].PasswordHash != "hash:"+decomposed {
		t.Fatalf("stored = %+v", calls)
	}
	for _, variant := range []string{"pass e\u0301e\u0301 word", " pass \u00e9\u00e9 word "} {
		if _, _, err := f.svc.Login(t.Context(), "operator", variant, ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Login(%q) = %v", variant, err)
		}
	}
	if _, _, err := f.svc.Login(t.Context(), "operator", decomposed, ""); err != nil {
		t.Errorf("exact password: %v", err)
	}
}

func TestLoginDuringPasswordChangeGetsNoStaleSession(t *testing.T) {
	f := newFixture(t, nil)
	changer := f.login(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f.hasher.setOnVerify(func() { once.Do(func() { close(entered); <-release }) })
	result := make(chan error, 1)
	go func() {
		_, _, err := f.svc.Login(context.Background(), "operator", testPassword, "")
		result <- err
	}()
	<-entered
	f.hasher.setOnVerify(nil)
	if err := f.svc.ChangePassword(t.Context(), changer.ID, testPassword, newPassword); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	if len(f.svc.sessions) != 0 {
		t.Errorf("stale session issued")
	}
}

func TestConcurrentPasswordChangesCommitOnce(t *testing.T) {
	f := newFixture(t, nil)
	first, second := f.login(t), f.login(t)
	errs := make(chan error, 2)
	for _, id := range []string{first.ID, second.ID} {
		go func() { errs <- f.svc.ChangePassword(context.Background(), id, testPassword, newPassword) }()
	}
	var ok, unauthenticated int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrUnauthenticated):
			unauthenticated++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 || unauthenticated != 1 || len(f.store.calls()) != 1 {
		t.Fatalf("ok=%d unauthenticated=%d commits=%d", ok, unauthenticated, len(f.store.calls()))
	}
}
