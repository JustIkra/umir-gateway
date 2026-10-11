package operator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoginOpensSession(t *testing.T) {
	f := newFixture(t, nil)
	profile, session, err := f.svc.Login(t.Context(), "operator", testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if profile != (Profile{ID: "PROFILE1", Login: "operator", DisplayName: "Оператор"}) {
		t.Errorf("profile = %+v", profile)
	}
	if session.ID == "" || session.CSRFToken == "" || session.ID == session.CSRFToken {
		t.Errorf("session = %+v", session)
	}
	if want := f.clock.Now().Add(30 * time.Minute); !session.ExpiresAt.Equal(want) {
		t.Errorf("expiresAt = %v, want %v", session.ExpiresAt, want)
	}
	if _, got, err := f.svc.Authenticate(session.ID); err != nil || got.CSRFToken != session.CSRFToken {
		t.Errorf("Authenticate = %+v, %v", got, err)
	}
}

func TestLoginErrorsAreGenericAndAlwaysVerify(t *testing.T) {
	f := newFixture(t, nil)
	if f.svc.dummyHash == "" || f.svc.dummyHash == testAccount().PasswordHash {
		t.Fatalf("dummy verifier = %q", f.svc.dummyHash)
	}
	for _, attempt := range []struct{ login, password, verifiedWith string }{
		{"operator", "wrong password value", testAccount().PasswordHash},
		{"nobody", testPassword, f.svc.dummyHash},
		{"Operator", testPassword, f.svc.dummyHash}, // logins are compared exactly
		{"", "", f.svc.dummyHash},
	} {
		before := len(f.hasher.verifiedHashes())
		_, _, err := f.svc.Login(t.Context(), attempt.login, attempt.password, "")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Login(%q) error = %v", attempt.login, err)
		}
		verified := f.hasher.verifiedHashes()
		if len(verified) != before+1 || verified[before] != attempt.verifiedWith {
			t.Errorf("Login(%q) verified against %v, want one check of %q", attempt.login, verified[before:], attempt.verifiedWith)
		}
	}
	before := len(f.hasher.verifiedHashes())
	if _, _, err := f.svc.Login(t.Context(), "operator", strings.Repeat("я", 33), ""); !errors.Is(err, ErrInvalidCredentials) || len(f.hasher.verifiedHashes()) != before {
		t.Errorf("over-long password: %v, verifications %d", err, len(f.hasher.verifiedHashes())-before)
	}
	if len(f.svc.sessions) != 0 {
		t.Errorf("failed logins created %d sessions", len(f.svc.sessions))
	}
}

func TestLoginRotatesSession(t *testing.T) {
	f := newFixture(t, nil)
	first := f.login(t)
	_, second, err := f.svc.Login(t.Context(), "operator", testPassword, first.ID)
	if err != nil || second.ID == first.ID {
		t.Fatalf("second = %+v, %v", second, err)
	}
	if _, _, err := f.svc.Authenticate(first.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("previous session still valid: %v", err)
	}
}

func TestAuthenticateRejectsUnknownAndRevoked(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	for _, id := range []string{"", "token-999", session.CSRFToken} {
		if _, _, err := f.svc.Authenticate(id); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) = %v", id, err)
		}
	}
	f.svc.Logout(session.ID)
	f.svc.Logout(session.ID) // idempotent
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("after logout: %v", err)
	}
}

func TestIdleExpiry(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.clock.Advance(29*time.Minute + 59*time.Second)
	_, refreshed, err := f.svc.Authenticate(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if want := f.clock.Now().Add(30 * time.Minute); !refreshed.ExpiresAt.Equal(want) {
		t.Errorf("expiresAt = %v, want %v", refreshed.ExpiresAt, want)
	}
	f.clock.Advance(30 * time.Minute)
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("after 30 idle minutes: %v", err)
	}
}

func TestAbsoluteExpiry(t *testing.T) {
	f := newFixture(t, nil)
	start := f.clock.Now()
	session := f.login(t)
	for f.clock.Now().Before(start.Add(8*time.Hour - 20*time.Minute)) {
		f.clock.Advance(20 * time.Minute)
		if _, _, err := f.svc.Authenticate(session.ID); err != nil {
			t.Fatalf("at %v: %v", f.clock.Now().Sub(start), err)
		}
	}
	_, near, err := f.svc.Authenticate(session.ID)
	if err != nil || !near.ExpiresAt.Equal(start.Add(8*time.Hour)) {
		t.Fatalf("expiresAt near the absolute deadline = %v, %v", near.ExpiresAt, err)
	}
	f.clock.Advance(20 * time.Minute)
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("after 8 hours: %v", err)
	}
}

func TestClockMovingBackwardsKeepsAbsoluteDeadline(t *testing.T) {
	f := newFixture(t, nil)
	start := f.clock.Now()
	session := f.login(t)
	f.clock.Advance(-time.Hour)
	_, got, err := f.svc.Authenticate(session.ID)
	if err != nil || got.ExpiresAt.After(start.Add(8*time.Hour)) {
		t.Fatalf("expiresAt = %v, %v", got.ExpiresAt, err)
	}
	f.clock.Advance(9 * time.Hour)
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("past the absolute deadline: %v", err)
	}
}

func TestSessionCountIsBounded(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxSessions = 2 })
	oldest := f.login(t)
	f.clock.Advance(time.Second)
	f.login(t)
	f.clock.Advance(time.Second)
	newest := f.login(t)
	if len(f.svc.sessions) != 2 {
		t.Fatalf("sessions = %d", len(f.svc.sessions))
	}
	if _, _, err := f.svc.Authenticate(oldest.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("oldest session survived: %v", err)
	}
	if _, _, err := f.svc.Authenticate(newest.ID); err != nil {
		t.Errorf("newest session: %v", err)
	}
}

func TestLoginRejectsCredentialChangeDuringVerification(t *testing.T) {
	f := newFixture(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	f.hasher.setOnVerify(func() { close(entered); <-release })
	result := make(chan error, 1)
	go func() {
		_, _, err := f.svc.Login(context.Background(), "operator", testPassword, "")
		result <- err
	}()
	<-entered
	f.svc.mu.Lock()
	f.svc.account.CredentialVersion++ // a password change committed meanwhile
	f.svc.mu.Unlock()
	close(release)
	if err := <-result; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login = %v", err)
	}
	if len(f.svc.sessions) != 0 {
		t.Errorf("session issued for the old password")
	}
}

func TestCancelledLoginCreatesNoSession(t *testing.T) {
	f := newFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	f.hasher.setOnVerify(cancel)
	if _, _, err := f.svc.Login(ctx, "operator", testPassword, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("Login = %v", err)
	}
	if len(f.svc.sessions) != 0 {
		t.Errorf("cancelled login created a session")
	}
}

func TestNewServiceRejectsInvalidSetup(t *testing.T) {
	valid := func() Options {
		return Options{
			Store: &fakeStore{}, Hasher: &fakeHasher{}, Now: time.Now, NewToken: (&tokens{}).New,
			IdleTimeout: DefaultIdleTimeout, AbsoluteTimeout: DefaultAbsoluteTimeout, MaxSessions: DefaultMaxSessions,
			MaxAnonymous: DefaultMaxAnonymous, AnonymousTTL: DefaultAnonymousTTL,
		}
	}
	for name, change := range map[string]func(*Options, *Account){
		"store":           func(o *Options, _ *Account) { o.Store = nil },
		"hasher":          func(o *Options, _ *Account) { o.Hasher = nil },
		"clock":           func(o *Options, _ *Account) { o.Now = nil },
		"tokens":          func(o *Options, _ *Account) { o.NewToken = nil },
		"idle":            func(o *Options, _ *Account) { o.IdleTimeout = 0 },
		"absolute":        func(o *Options, _ *Account) { o.AbsoluteTimeout = 0 },
		"sessions":        func(o *Options, _ *Account) { o.MaxSessions = 0 },
		"anonymous bound": func(o *Options, _ *Account) { o.MaxAnonymous = 0 },
		"anonymous ttl":   func(o *Options, _ *Account) { o.AnonymousTTL = 0 },
		"account":         func(_ *Options, a *Account) { a.CredentialVersion = 0 },
		"hash format":     func(_ *Options, a *Account) { a.PasswordHash = "plain" },
	} {
		opts, account := valid(), testAccount()
		change(&opts, &account)
		if _, err := NewService(account, opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
