package operator

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"
	"unicode/utf8"
)

// Author-selected defaults from gateway#8.
const (
	DefaultIdleTimeout     = 30 * time.Minute
	DefaultAbsoluteTimeout = 8 * time.Hour
	DefaultMaxSessions     = 32
	// DefaultRememberTimeout is the fixed lifetime of a "remember me" login (gateway#8).
	DefaultRememberTimeout = 30 * 24 * time.Hour
	// The anonymous bound and lifetime are implementation defaults, not gateway#8 values.
	DefaultMaxAnonymous = 1024
	DefaultAnonymousTTL = 30 * time.Minute
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthenticated    = errors.New("unauthenticated")
	// ErrAuthUnavailable is returned in fail-closed recovery after an account update with unknown outcome.
	ErrAuthUnavailable = errors.New("authentication unavailable")
	// ErrInvalidCSRFToken rejects an unsafe request whose token does not belong to its session.
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
)

type Options struct {
	Store  Store
	Hasher PasswordHasher
	Now    func() time.Time
	// NewToken returns an unpredictable URL-safe token for session and anonymous context IDs.
	NewToken        func() (string, error)
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	// RememberTimeout is the fixed lifetime of a remembered login; activity never extends it.
	RememberTimeout time.Duration
	// MaxSessions bounds ordinary and remembered sessions together.
	MaxSessions  int
	MaxAnonymous int
	AnonymousTTL time.Duration
	// MaxVerifications bounds concurrent Argon2id work; MaxQueuedLogins bounds logins waiting for it.
	MaxVerifications int
	MaxQueuedLogins  int
	// FailureLimit failed logins within FailureWindow start a Cooldown for every login.
	FailureLimit  int
	FailureWindow time.Duration
	Cooldown      time.Duration
}

// Session is what the HTTP layer needs about an authenticated session. ID is the bearer token for the
// cookie; the service itself keeps only its digest.
type Session struct {
	ID        string
	CSRFToken string
	// ExpiresAt is the earlier of the idle and absolute deadlines.
	ExpiresAt time.Time
	// IdleExpiresAt moves with authenticated requests of an ordinary session but never past
	// AbsoluteExpiresAt, which is fixed at login. A remembered session has no earlier idle deadline.
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RememberMe        bool
}

// Service owns the account cache, sessions and recovery mode. One mutex guards all of them, and every
// commit happens under it, so no request sees a committed state together with stale sessions. Expensive
// password work runs outside the mutex. The service starts no goroutines; expired state is removed when
// it is touched or when a commit is prepared.
type Service struct {
	opts Options
	gate *verificationGate
	// changing admits one password change at a time.
	changing chan struct{}

	mu         sync.Mutex
	account    Account
	recovering bool
	// sessions are keyed by token digest and mirror the last committed state, except that ordinary idle
	// activity of business requests is stored with the next commit.
	sessions  map[string]*session
	anonymous map[string]*anonymousContext
	throttle  loginThrottle
}

// NewService starts from the persisted state. Stored sessions that expired or belong to an older
// credential version are not restored.
func NewService(state State, opts Options) (*Service, error) {
	if opts.Store == nil || opts.Hasher == nil || opts.Now == nil || opts.NewToken == nil {
		return nil, errors.New("operator: store, hasher, clock and token source are required")
	}
	if opts.IdleTimeout <= 0 || opts.AbsoluteTimeout <= 0 || opts.RememberTimeout <= 0 || opts.MaxSessions <= 0 ||
		opts.MaxAnonymous <= 0 || opts.AnonymousTTL <= 0 || opts.MaxVerifications <= 0 || opts.MaxQueuedLogins <= 0 ||
		opts.FailureLimit <= 0 || opts.FailureWindow <= 0 || opts.Cooldown <= 0 {
		return nil, errors.New("operator: session timeouts and bounds must be positive")
	}
	if err := ValidateState(state); err != nil {
		return nil, err
	}
	if err := opts.Hasher.Check(state.Account.PasswordHash); err != nil {
		return nil, fmt.Errorf("account passwordHash: %w", err)
	}
	s := &Service{
		opts:      opts,
		changing:  make(chan struct{}, 1),
		account:   state.Account,
		sessions:  make(map[string]*session),
		anonymous: make(map[string]*anonymousContext),
		gate:      newVerificationGate(opts.MaxVerifications, opts.MaxQueuedLogins),
		throttle:  loginThrottle{failures: make([]time.Time, 0, opts.FailureLimit)},
	}
	s.restore(state.Sessions)
	return s, nil
}

// Login verifies the credentials and opens a new session, remembered for RememberTimeout or ordinary.
// The session is stored before it is returned; previousID, when present, is revoked in the same commit,
// and a failed commit keeps it. An unknown login is verified against the account's own hash and the
// result discarded, so timing and errors do not reveal whether the login exists, whatever parameters
// that hash carries. A credential change during verification rejects the attempt.
func (s *Service) Login(ctx context.Context, login, password, previousID string, rememberMe bool) (Profile, Session, error) {
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
	ok, err := s.verifyLogin(ctx, loginOK, password, snapshot.PasswordHash)
	if err != nil {
		return Profile{}, Session{}, err
	}
	if !ok {
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
	// The caller may have gone while this login waited for the lock; it then gets no session.
	if err := ctx.Err(); err != nil {
		return Profile{}, Session{}, err
	}
	token, err := s.newTokenLocked()
	if err != nil {
		return Profile{}, Session{}, err
	}
	now := s.opts.Now()
	next := maps.Clone(s.sessions)
	if previousID != "" {
		delete(next, sessionDigest(previousID))
	}
	for digest, st := range next {
		if s.expired(st, now) {
			delete(next, digest)
		}
	}
	evictOldest(next, s.opts.MaxSessions-1)
	st := &session{rememberMe: rememberMe, credentialVersion: s.account.CredentialVersion, created: now, lastSeen: now}
	st.expires = now.Add(s.opts.AbsoluteTimeout)
	if rememberMe {
		st.expires = now.Add(s.opts.RememberTimeout)
	}
	next[sessionDigest(token)] = st
	if err := s.commitLocked(s.account, next, sessionChange); err != nil {
		return Profile{}, Session{}, err
	}
	s.throttle.failures = s.throttle.failures[:0]
	return s.account.Profile(), s.view(token, st), nil
}

// Authenticate admits a safe request of session id. Ordinary idle activity is kept in memory and stored
// with the next commit; nothing is written here.
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

// Authorize admits an unsafe request of session id, which must carry the session's CSRF token.
// A wrong token neither extends nor revokes the session.
func (s *Service) Authorize(id, csrfToken string) (Profile, Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	st, err := s.activeLocked(id, now)
	if err != nil {
		return Profile{}, Session{}, err
	}
	if !MatchToken(sessionCSRF(id), csrfToken) {
		return Profile{}, Session{}, ErrInvalidCSRFToken
	}
	st.lastSeen = now
	return s.account.Profile(), s.view(id, st), nil
}

// Current returns the profile and session for the operator's own view. An ordinary session's renewed
// idle deadline is stored before it is reported; a remembered session has nothing to renew. If the
// store definitely failed, the session stays usable and the deadline the store holds is reported.
func (s *Service) Current(id string) (Profile, Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	st, err := s.activeLocked(id, now)
	if err != nil {
		return Profile{}, Session{}, err
	}
	if st.rememberMe {
		st.lastSeen = now
		return s.account.Profile(), s.view(id, st), nil
	}
	next := maps.Clone(s.sessions)
	renewed := *st
	renewed.lastSeen = now
	next[sessionDigest(id)] = &renewed
	if err := s.commitLocked(s.account, next, sessionChange); err != nil {
		if !errors.Is(err, ErrSessionStorageUnavailable) {
			return Profile{}, Session{}, err
		}
		st.lastSeen = now
		stored := *st
		stored.lastSeen = st.storedLastSeen
		return s.account.Profile(), s.view(id, &stored), nil
	}
	return s.account.Profile(), s.view(id, &renewed), nil
}

// verifyLogin checks a login inside a verification slot. The cooldown is checked again after the wait,
// and a failure is recorded before the slot is released, so logins queued before a cooldown began are
// rejected instead of verified.
func (s *Service) verifyLogin(ctx context.Context, loginOK bool, password, encoded string) (bool, error) {
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		return false, err
	}
	defer release()
	s.mu.Lock()
	wait := s.cooldownLocked(s.opts.Now())
	s.mu.Unlock()
	if wait > 0 {
		return false, rateLimited(wait)
	}
	ok, err := s.opts.Hasher.Verify(password, encoded)
	if err != nil {
		return false, fmt.Errorf("verify password: %w", err)
	}
	if !ok || !loginOK {
		s.recordFailure()
		return false, nil
	}
	return true, nil
}

// verify runs a password-change check in a verification slot, waiting without the login queue bound.
func (s *Service) verify(ctx context.Context, password, encoded string) (bool, error) {
	release, err := s.gate.acquire(ctx, false)
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

// Logout revokes id and stores the revocation before it reports success. An absent, expired or
// outdated session is never restored, so it needs nothing stored. During recovery the stored state is
// not authoritative, so only a request without a session can succeed.
func (s *Service) Logout(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recovering {
		if id == "" {
			return nil
		}
		return ErrAuthUnavailable
	}
	if _, err := s.activeLocked(id, s.opts.Now()); err != nil {
		return nil
	}
	next := maps.Clone(s.sessions)
	delete(next, sessionDigest(id))
	return s.commitLocked(s.account, next, sessionChange)
}

func (s *Service) newTokenLocked() (string, error) {
	token, err := s.opts.NewToken()
	if err != nil {
		return "", fmt.Errorf("session token: %w", err)
	}
	if _, taken := s.sessions[sessionDigest(token)]; taken || token == "" {
		return "", errors.New("session token: unusable token")
	}
	return token, nil
}
