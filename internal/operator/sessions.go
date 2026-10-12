package operator

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	// ErrSessionStorageUnavailable reports that a session change was not stored: nothing changed.
	ErrSessionStorageUnavailable = errors.New("session storage unavailable")
	// ErrSessionUpdateOutcomeUnknown reports a session change whose commit cannot be determined; the
	// service has entered fail-closed recovery.
	ErrSessionUpdateOutcomeUnknown = errors.New("session update outcome unknown")
)

// session is a live server session. Its bearer token exists only in the browser's cookie; the service
// keys sessions by the token's digest.
type session struct {
	rememberMe        bool
	credentialVersion int64
	created           time.Time
	lastSeen          time.Time
	// expires is the absolute deadline fixed at login.
	expires time.Time
	// wrongCurrent counts wrong current passwords in password changes made with this session.
	wrongCurrent int
}

// sessionDigest identifies a session in memory and in the store.
func sessionDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// sessionCSRF derives a session's CSRF token from its bearer token, so a restored session keeps its
// token without the token being stored. A page that cannot read the HttpOnly cookie cannot compute it.
func sessionCSRF(token string) string {
	sum := sha256.Sum256([]byte("umir-operator-csrf\x00" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// expired applies the absolute deadline to every session and the idle timeout to ordinary ones. A
// remembered session's idle window equals its fixed deadline, so activity never moves it.
func (s *Service) expired(st *session, now time.Time) bool {
	return !now.Before(st.expires) || !st.rememberMe && !now.Before(st.lastSeen.Add(s.opts.IdleTimeout))
}

func (s *Service) view(token string, st *session) Session {
	idle := st.expires
	if ordinary := st.lastSeen.Add(s.opts.IdleTimeout); !st.rememberMe && ordinary.Before(idle) {
		idle = ordinary
	}
	return Session{
		ID: token, CSRFToken: sessionCSRF(token), ExpiresAt: idle, IdleExpiresAt: idle,
		AbsoluteExpiresAt: st.expires, RememberMe: st.rememberMe,
	}
}

// activeLocked returns the live session of token. An expired or outdated session is forgotten here; the
// next commit drops its record.
func (s *Service) activeLocked(token string, now time.Time) (*session, error) {
	if s.recovering {
		return nil, ErrAuthUnavailable
	}
	digest := sessionDigest(token)
	st, ok := s.sessions[digest]
	if !ok || token == "" {
		return nil, ErrUnauthenticated
	}
	if s.expired(st, now) || st.credentialVersion != s.account.CredentialVersion {
		delete(s.sessions, digest)
		return nil, ErrUnauthenticated
	}
	return st, nil
}

// restore keeps the stored sessions that are still valid for the account, the newest ones up to the bound.
func (s *Service) restore(stored []StoredSession) {
	now := s.opts.Now()
	for _, r := range stored {
		st := &session{
			rememberMe: r.RememberMe, credentialVersion: r.CredentialVersion,
			created: r.Created, lastSeen: r.LastSeen, expires: r.ExpiresAt,
		}
		if !s.expired(st, now) && st.credentialVersion == s.account.CredentialVersion {
			s.sessions[r.Digest] = st
		}
	}
	evictOldest(s.sessions, s.opts.MaxSessions)
}

// evictOldest drops the oldest sessions until at most keep remain.
func evictOldest(sessions map[string]*session, keep int) {
	for len(sessions) > keep {
		var oldestDigest string
		var oldest *session
		for digest, st := range sessions {
			if oldest == nil || st.created.Before(oldest.created) {
				oldestDigest, oldest = digest, st
			}
		}
		delete(sessions, oldestDigest)
	}
}

// stateOf is what the store holds for account and sessions, oldest session first.
func stateOf(account Account, sessions map[string]*session) State {
	stored := make([]StoredSession, 0, len(sessions))
	for digest, st := range sessions {
		stored = append(stored, StoredSession{
			Digest: digest, RememberMe: st.rememberMe, CredentialVersion: st.credentialVersion,
			Created: st.created, LastSeen: st.lastSeen, ExpiresAt: st.expires,
		})
	}
	slices.SortFunc(stored, func(a, b StoredSession) int {
		if c := a.Created.Compare(b.Created); c != 0 {
			return c
		}
		return strings.Compare(a.Digest, b.Digest)
	})
	return State{Account: account, Sessions: stored}
}

// change tells commitLocked which errors describe a failed commit.
type change int

const (
	accountChange change = iota
	sessionChange
)

// commitLocked stores account and sessions while s.mu is held and publishes them only after the store
// confirms; sessions is a copy the caller prepared, and expired or outdated records are dropped from it.
// A definite storage failure changes nothing. Any other failure enters fail-closed recovery until a
// restart reloads the authoritative file.
func (s *Service) commitLocked(account Account, sessions map[string]*session, kind change) error {
	now := s.opts.Now()
	for digest, st := range sessions {
		if s.expired(st, now) || st.credentialVersion != account.CredentialVersion {
			delete(sessions, digest)
		}
	}
	err := s.opts.Store.Replace(stateOf(account, sessions))
	switch {
	case err == nil:
		s.account, s.sessions = account, sessions
		return nil
	case errors.Is(err, ErrStorageUnavailable) && !errors.Is(err, ErrUpdateOutcomeUnknown):
		if kind == sessionChange {
			return fmt.Errorf("%w: %w", ErrSessionStorageUnavailable, err)
		}
		return err
	}
	s.recovering = true
	clear(s.sessions)
	if kind == sessionChange {
		return fmt.Errorf("%w: %w", ErrSessionUpdateOutcomeUnknown, err)
	}
	if errors.Is(err, ErrUpdateOutcomeUnknown) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUpdateOutcomeUnknown, err)
}
