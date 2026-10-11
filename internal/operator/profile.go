package operator

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"
)

// ErrCurrentPasswordIncorrect is a definite no-change result of a password change.
var ErrCurrentPasswordIncorrect = errors.New("current password incorrect")

// UpdateDisplayName persists the canonical display name for the operator of session id.
func (s *Service) UpdateDisplayName(id, raw string) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	if err := s.commitLocked(next); err != nil {
		return Profile{}, err
	}
	return s.account.Profile(), nil
}

// ChangePassword replaces the password and revokes every session, including id. Verification and
// hashing run outside the mutex; the commit rechecks that the session and credentials did not change.
// Changes run one at a time, so parallel requests cannot hold verification slots or the login queue,
// and FailureLimit wrong current passwords revoke the session, sending a guesser back to login.
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
	st.lastSeen = now
	snapshot := s.account
	s.mu.Unlock()

	if err := CheckPassword(next); err != nil {
		return err
	}
	if !utf8.ValidString(current) || utf8.RuneCountInString(current) > maxPassword {
		s.recordWrongCurrent(id)
		return ErrCurrentPasswordIncorrect
	}
	ok, err := s.verify(ctx, current, snapshot.PasswordHash)
	if err != nil {
		return err
	}
	if !ok {
		s.recordWrongCurrent(id)
		return ErrCurrentPasswordIncorrect
	}
	hash, err := s.hash(ctx, next)
	if err != nil {
		return fmt.Errorf("%w: hash password: %w", ErrStorageUnavailable, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.activeLocked(id, s.opts.Now()); err != nil {
		return err
	}
	updated := s.account
	updated.PasswordHash = hash
	updated.CredentialVersion++
	if err := s.commitLocked(updated); err != nil {
		return err
	}
	clear(s.sessions)
	return nil
}

// recordWrongCurrent counts a wrong current password and revokes the session at FailureLimit.
func (s *Service) recordWrongCurrent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.sessions[id]; ok {
		st.wrongCurrent++
		if st.wrongCurrent >= s.opts.FailureLimit {
			delete(s.sessions, id)
		}
	}
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

// commitLocked persists next while s.mu is held. A definite storage failure leaves everything unchanged;
// any other failure enters fail-closed recovery until a restart reloads the authoritative file.
func (s *Service) commitLocked(next Account) error {
	err := s.opts.Store.Replace(next)
	switch {
	case err == nil:
		s.account = next
		return nil
	case errors.Is(err, ErrStorageUnavailable) && !errors.Is(err, ErrUpdateOutcomeUnknown):
		return err
	default:
		s.recovering = true
		clear(s.sessions)
		if errors.Is(err, ErrUpdateOutcomeUnknown) {
			return err
		}
		return fmt.Errorf("%w: %w", ErrUpdateOutcomeUnknown, err)
	}
}
