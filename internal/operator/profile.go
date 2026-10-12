package operator

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"unicode/utf8"
)

// ErrCurrentPasswordIncorrect is a definite no-change result of a password change.
var ErrCurrentPasswordIncorrect = errors.New("current password incorrect")

// UpdateDisplayName persists the canonical display name for the operator of session id.
func (s *Service) UpdateDisplayName(id, raw string) (Profile, error) {
	s.mu.Lock()
	defer s.unlock()
	now := s.opts.Now()
	st, err := s.activeLocked(id, now)
	if err != nil {
		return Profile{}, err
	}
	st.lastSeen = now
	name, err := CanonicalDisplayName(raw)
	if err != nil {
		return Profile{}, err
	}
	next := s.account
	next.DisplayName = name
	if err := s.commitLocked(next, maps.Clone(s.sessions), accountChange); err != nil {
		return Profile{}, err
	}
	s.extendedLocked(id, st)
	return s.account.Profile(), nil
}

// ChangePassword replaces the password and revokes every session, including id. Verification and
// hashing run outside the mutex; the commit rechecks that the session and credentials did not change.
// Changes run one at a time, so parallel requests cannot hold verification slots or the login queue.
// FailureLimit wrong current passwords within FailureWindow, across all sessions, start a Cooldown in
// which every change is refused before any password check; the change that starts it revokes id.
func (s *Service) ChangePassword(ctx context.Context, id, current, next string) error {
	select {
	case s.changing <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.changing }()

	s.mu.Lock()
	now := s.opts.Now()
	st, err := s.activeLocked(id, now)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	// During the cooldown a change is refused before any password check and revokes nothing.
	if wait := s.changeThrottle.wait(now); wait > 0 {
		s.mu.Unlock()
		return &PasswordChangeLimitError{RetryAfter: wholeSeconds(wait)}
	}
	st.lastSeen = now
	snapshot := s.account
	s.mu.Unlock()

	if err := CheckPassword(next); err != nil {
		return err
	}
	if !utf8.ValidString(current) {
		return &FieldError{Field: "currentPassword", Code: CodeInvalidCharacters}
	}
	if utf8.RuneCountInString(current) > maxPassword {
		return &FieldError{Field: "currentPassword", Code: CodeTooLong}
	}
	ok, err := s.verify(ctx, current, snapshot.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		return s.recordWrongCurrent(id)
	}
	hash, err := s.hash(ctx, next)
	if err != nil {
		return fmt.Errorf("%w: hash password: %w", ErrStorageUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.unlock()
	now = s.opts.Now()
	if _, err := s.activeLocked(id, now); err != nil {
		return err
	}
	updated := s.account
	updated.PasswordHash = hash
	updated.CredentialVersion++
	revoked := s.sessions
	if err := s.commitLocked(updated, map[string]*session{}, accountChange); err != nil {
		return err
	}
	for digest, st := range revoked {
		if !s.expired(st, now) {
			s.endedLocked(digest, EndRevoked)
		}
	}
	// The earlier wrong passwords were made against a password that no longer exists.
	s.changeThrottle.failures = s.changeThrottle.failures[:0]
	return nil
}

// recordWrongCurrent counts a wrong current password for the whole operator and returns
// ErrCurrentPasswordIncorrect. The FailureLimit-th within FailureWindow starts a Cooldown for every
// password change and revokes the calling session; the revocation is stored before it is reported.
func (s *Service) recordWrongCurrent(id string) error {
	s.mu.Lock()
	defer s.unlock()
	// Recovery may have begun during the verification; no answer about the session is reliable then.
	if s.recovering {
		return ErrAuthUnavailable
	}
	now := s.opts.Now()
	if !s.changeThrottle.fail(now, s.opts.FailureLimit, s.opts.FailureWindow, s.opts.Cooldown) {
		return ErrCurrentPasswordIncorrect
	}
	limited := &PasswordChangeLimitError{RetryAfter: wholeSeconds(s.opts.Cooldown)}
	// A session that ended during the verification is never restored; there is nothing to revoke.
	if _, err := s.activeLocked(id, now); err != nil {
		return limited
	}
	next := maps.Clone(s.sessions)
	delete(next, sessionDigest(id))
	if err := s.commitLocked(s.account, next, sessionChange); err != nil {
		return err
	}
	s.endedLocked(sessionDigest(id), EndRevoked)
	limited.SessionRevoked = true
	return limited
}

// hash creates the verifier for a new password inside a verification slot.
func (s *Service) hash(ctx context.Context, password string) (string, error) {
	release, err := s.gate.acquire(ctx, false)
	if err != nil {
		return "", err
	}
	defer release()
	return s.opts.Hasher.Hash(password)
}
