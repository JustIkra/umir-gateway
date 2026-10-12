package operator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// wantDeadlines checks both deadlines; the idle one never passes the absolute one, so it is also expiresAt.
func wantDeadlines(t *testing.T, s Session, idle, absolute time.Time) {
	t.Helper()
	if !s.IdleExpiresAt.Equal(idle) || !s.AbsoluteExpiresAt.Equal(absolute) || !s.ExpiresAt.Equal(idle) {
		t.Errorf("deadlines = expires %v, idle %v, absolute %v; want idle %v, absolute %v",
			s.ExpiresAt, s.IdleExpiresAt, s.AbsoluteExpiresAt, idle, absolute)
	}
}

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
	wantDeadlines(t, session, f.clock.Now().Add(30*time.Minute), f.clock.Now().Add(8*time.Hour))
	if _, got, err := f.svc.Authenticate(session.ID); err != nil || got.CSRFToken != session.CSRFToken {
		t.Errorf("Authenticate = %+v, %v", got, err)
	}
}

func TestLoginErrorsAreGenericAndAlwaysVerify(t *testing.T) {
	f := newFixture(t, nil)
	// An unknown login is checked against the account's own hash, so both cost the same by construction.
	for _, attempt := range []struct{ login, password string }{
		{"operator", "wrong password value"},
		{"nobody", testPassword},
		{"Operator", testPassword}, // logins are compared exactly
		{"", ""},
	} {
		before := len(f.hasher.verifiedHashes())
		_, _, err := f.svc.Login(t.Context(), attempt.login, attempt.password, "")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Login(%q) error = %v", attempt.login, err)
		}
		verified := f.hasher.verifiedHashes()
		if len(verified) != before+1 || verified[before] != testAccount().PasswordHash {
			t.Errorf("Login(%q) verified against %v, want one check of the account hash", attempt.login, verified[before:])
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
	start := f.clock.Now()
	session := f.login(t)
	f.clock.Advance(29*time.Minute + 59*time.Second)
	_, refreshed, err := f.svc.Authenticate(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A request moves only the idle deadline.
	wantDeadlines(t, refreshed, f.clock.Now().Add(30*time.Minute), start.Add(8*time.Hour))
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
	if err != nil {
		t.Fatal(err)
	}
	// Twenty minutes before the absolute deadline a request cannot extend the session past it.
	wantDeadlines(t, near, start.Add(8*time.Hour), start.Add(8*time.Hour))
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
	if err != nil {
		t.Fatal(err)
	}
	wantDeadlines(t, got, f.clock.Now().Add(30*time.Minute), start.Add(8*time.Hour))
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
			MaxVerifications: DefaultMaxVerifications, MaxQueuedLogins: DefaultMaxQueuedLogins,
			FailureLimit: DefaultFailureLimit, FailureWindow: DefaultFailureWindow, Cooldown: DefaultCooldown,
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
		"verifications":   func(o *Options, _ *Account) { o.MaxVerifications = 0 },
		"queue":           func(o *Options, _ *Account) { o.MaxQueuedLogins = 0 },
		"failure limit":   func(o *Options, _ *Account) { o.FailureLimit = 0 },
		"failure window":  func(o *Options, _ *Account) { o.FailureWindow = 0 },
		"cooldown":        func(o *Options, _ *Account) { o.Cooldown = 0 },
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

func TestAuthorizeRequiresTheSessionCSRFToken(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	other := f.login(t)
	f.clock.Advance(10 * time.Minute)
	for _, token := range []string{"", "token-999", session.ID, other.CSRFToken} {
		if _, _, err := f.svc.Authorize(session.ID, token); !errors.Is(err, ErrInvalidCSRFToken) {
			t.Errorf("Authorize(%q) = %v", token, err)
		}
	}
	// Rejected tokens did not extend the session: thirty minutes after login it is gone.
	f.clock.Advance(20 * time.Minute)
	if _, _, err := f.svc.Authorize(session.ID, session.CSRFToken); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("after 30 minutes without an admitted request: %v", err)
	}
}

func TestAuthorizeExtendsTheSession(t *testing.T) {
	f := newFixture(t, nil)
	start := f.clock.Now()
	session := f.login(t)
	f.clock.Advance(20 * time.Minute)
	profile, got, err := f.svc.Authorize(session.ID, session.CSRFToken)
	if err != nil || profile.Login != "operator" {
		t.Fatalf("Authorize = %+v, %v", profile, err)
	}
	wantDeadlines(t, got, f.clock.Now().Add(30*time.Minute), start.Add(8*time.Hour))
	if _, _, err := f.svc.Authorize("unknown", session.CSRFToken); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("unknown session: %v", err)
	}
}

func TestAuthorizeDuringRecovery(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.store.setErr(errors.New("disk vanished"))
	if _, err := f.svc.UpdateDisplayName(session.ID, "Смена"); !errors.Is(err, ErrUpdateOutcomeUnknown) {
		t.Fatalf("UpdateDisplayName = %v", err)
	}
	if _, _, err := f.svc.Authorize(session.ID, session.CSRFToken); !errors.Is(err, ErrAuthUnavailable) {
		t.Errorf("Authorize during recovery = %v", err)
	}
}
