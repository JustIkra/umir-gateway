package operator

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"
)

// Author-selected defaults from gateway#8.
const (
	DefaultIdleTimeout     = 30 * time.Minute
	DefaultAbsoluteTimeout = 8 * time.Hour
	DefaultMaxSessions     = 32
	// The anonymous bound and lifetime are implementation defaults, not gateway#8 values.
	DefaultMaxAnonymous = 1024
	DefaultAnonymousTTL = 30 * time.Minute
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthenticated    = errors.New("unauthenticated")
	// ErrAuthUnavailable is returned in fail-closed recovery after an account update with unknown outcome.
	ErrAuthUnavailable = errors.New("authentication unavailable")
)

type Options struct {
	Store  Store
	Hasher PasswordHasher
	Now    func() time.Time
	// NewToken returns an unpredictable URL-safe token for session IDs and CSRF tokens.
	NewToken        func() (string, error)
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	MaxSessions     int
	MaxAnonymous    int
	AnonymousTTL    time.Duration
	// MaxVerifications bounds concurrent Argon2id work; MaxQueuedLogins bounds logins waiting for it.
	MaxVerifications int
	MaxQueuedLogins  int
	// FailureLimit failed logins within FailureWindow start a Cooldown for every login.
	FailureLimit  int
	FailureWindow time.Duration
	Cooldown      time.Duration
}

// Session is what the HTTP layer needs about an authenticated session.
type Session struct {
	ID        string
	CSRFToken string
	// ExpiresAt is the earlier of the idle and absolute deadlines.
	ExpiresAt time.Time
}

type session struct {
	csrfToken         string
	credentialVersion int64
	created           time.Time
	lastSeen          time.Time
}

// Service owns the account cache, sessions and recovery mode. One mutex guards all of them, and account
// commits happen under it, so no request sees a committed account together with stale sessions.
// Expensive password work runs outside the mutex. The service starts no goroutines; expired state is
// removed when it is touched or when a new entry needs room.
type Service struct {
	opts Options
	// dummyHash is verified for an unknown login, so it costs the same as checking the real account.
	dummyHash string
	gate      *verificationGate

	mu         sync.Mutex
	account    Account
	recovering bool
	sessions   map[string]*session
	anonymous  map[string]*anonymousContext
	throttle   loginThrottle
}

func NewService(account Account, opts Options) (*Service, error) {
	if opts.Store == nil || opts.Hasher == nil || opts.Now == nil || opts.NewToken == nil {
		return nil, errors.New("operator: store, hasher, clock and token source are required")
	}
	if opts.IdleTimeout <= 0 || opts.AbsoluteTimeout <= 0 || opts.MaxSessions <= 0 || opts.MaxAnonymous <= 0 || opts.AnonymousTTL <= 0 ||
		opts.MaxVerifications <= 0 || opts.MaxQueuedLogins <= 0 || opts.FailureLimit <= 0 || opts.FailureWindow <= 0 || opts.Cooldown <= 0 {
		return nil, errors.New("operator: session timeouts and bounds must be positive")
	}
	if err := ValidateAccount(account); err != nil {
		return nil, err
	}
	if err := opts.Hasher.Check(account.PasswordHash); err != nil {
		return nil, fmt.Errorf("account passwordHash: %w", err)
	}
	secret, err := opts.NewToken()
	if err != nil {
		return nil, fmt.Errorf("dummy verifier: %w", err)
	}
	dummyHash, err := opts.Hasher.Hash(secret)
	if err != nil {
		return nil, fmt.Errorf("dummy verifier: %w", err)
	}
	return &Service{
		opts:      opts,
		dummyHash: dummyHash,
		account:   account,
		sessions:  make(map[string]*session),
		anonymous: make(map[string]*anonymousContext),
		gate:      newVerificationGate(opts.MaxVerifications, opts.MaxQueuedLogins),
		throttle:  loginThrottle{failures: make([]time.Time, 0, opts.FailureLimit)},
	}, nil
}

// Login verifies the credentials and opens a new session; previousID, when present, is revoked.
// An unknown login is verified against the dummy hash, so timing and errors do not reveal whether the
// login exists. A credential change during verification rejects the attempt.
func (s *Service) Login(ctx context.Context, login, password, previousID string) (Profile, Session, error) {
	s.mu.Lock()
	if s.recovering {
		s.mu.Unlock()
		return Profile{}, Session{}, ErrAuthUnavailable
	}
	if wait := s.cooldownLocked(s.opts.Now()); wait > 0 {
		s.mu.Unlock()
		return Profile{}, Session{}, rateLimited(wait)
	}
	snapshot := s.account
	s.mu.Unlock()

	if !utf8.ValidString(password) || utf8.RuneCountInString(password) > maxPassword {
		s.recordFailure()
		return Profile{}, Session{}, ErrInvalidCredentials
	}
	loginOK := subtle.ConstantTimeCompare([]byte(login), []byte(snapshot.Login)) == 1
	encoded := s.dummyHash
	if loginOK {
		encoded = snapshot.PasswordHash
	}
	passwordOK, err := s.verifyLogin(ctx, password, encoded)
	if err != nil {
		return Profile{}, Session{}, err
	}
	if !passwordOK || !loginOK {
		s.recordFailure()
		return Profile{}, Session{}, ErrInvalidCredentials
	}
	if err := ctx.Err(); err != nil {
		return Profile{}, Session{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recovering {
		return Profile{}, Session{}, ErrAuthUnavailable
	}
	if s.account.CredentialVersion != snapshot.CredentialVersion {
		return Profile{}, Session{}, ErrInvalidCredentials
	}
	s.throttle.failures = s.throttle.failures[:0]
	if previousID != "" {
		delete(s.sessions, previousID)
	}
	now := s.opts.Now()
	id, csrf, err := s.newPairLocked()
	if err != nil {
		return Profile{}, Session{}, err
	}
	s.makeRoomLocked(now)
	st := &session{csrfToken: csrf, credentialVersion: s.account.CredentialVersion, created: now, lastSeen: now}
	s.sessions[id] = st
	return s.account.Profile(), s.view(id, st), nil
}

// Authenticate returns the profile and session for id and extends its idle deadline.
func (s *Service) Authenticate(id string) (Profile, Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	st, err := s.activeLocked(id, now)
	if err != nil {
		return Profile{}, Session{}, err
	}
	st.lastSeen = now
	return s.account.Profile(), s.view(id, st), nil
}

// verifyLogin runs a login check through the bounded queue.
func (s *Service) verifyLogin(ctx context.Context, password, encoded string) (bool, error) {
	return s.check(ctx, true, password, encoded)
}

// verify runs a password-change check; it waits for a slot without the login queue bound.
func (s *Service) verify(ctx context.Context, password, encoded string) (bool, error) {
	return s.check(ctx, false, password, encoded)
}

func (s *Service) check(ctx context.Context, bounded bool, password, encoded string) (bool, error) {
	release, err := s.gate.acquire(ctx, bounded)
	if err != nil {
		return false, err
	}
	defer release()
	ok, err := s.opts.Hasher.Verify(password, encoded)
	if err != nil {
		return false, fmt.Errorf("verify password: %w", err)
	}
	return ok, nil
}

// Logout revokes id. It works during recovery, which blocks only authentication.
func (s *Service) Logout(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *Service) activeLocked(id string, now time.Time) (*session, error) {
	if s.recovering {
		return nil, ErrAuthUnavailable
	}
	st, ok := s.sessions[id]
	if !ok {
		return nil, ErrUnauthenticated
	}
	if s.expired(st, now) || st.credentialVersion != s.account.CredentialVersion {
		delete(s.sessions, id)
		return nil, ErrUnauthenticated
	}
	return st, nil
}

// expired measures the absolute deadline from creation, so a clock moving backwards cannot extend it.
func (s *Service) expired(st *session, now time.Time) bool {
	return !now.Before(st.lastSeen.Add(s.opts.IdleTimeout)) || !now.Before(st.created.Add(s.opts.AbsoluteTimeout))
}

func (s *Service) view(id string, st *session) Session {
	idle := st.lastSeen.Add(s.opts.IdleTimeout)
	if absolute := st.created.Add(s.opts.AbsoluteTimeout); absolute.Before(idle) {
		idle = absolute
	}
	return Session{ID: id, CSRFToken: st.csrfToken, ExpiresAt: idle}
}

func (s *Service) newPairLocked() (id, csrf string, err error) {
	if id, err = s.opts.NewToken(); err == nil {
		csrf, err = s.opts.NewToken()
	}
	if err != nil {
		return "", "", fmt.Errorf("session token: %w", err)
	}
	if _, taken := s.sessions[id]; taken || id == "" || csrf == "" || id == csrf {
		return "", "", errors.New("session token: unusable token")
	}
	return id, csrf, nil
}

// makeRoomLocked drops expired sessions, then the oldest one while the bound is reached.
func (s *Service) makeRoomLocked(now time.Time) {
	for id, st := range s.sessions {
		if s.expired(st, now) {
			delete(s.sessions, id)
		}
	}
	for len(s.sessions) >= s.opts.MaxSessions {
		var oldestID string
		var oldest *session
		for id, st := range s.sessions {
			if oldest == nil || st.created.Before(oldest.created) {
				oldestID, oldest = id, st
			}
		}
		delete(s.sessions, oldestID)
	}
}
