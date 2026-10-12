package operator

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// anonymousContext lets an unauthenticated browser obtain a CSRF token for login or logout.
type anonymousContext struct {
	token   string
	created time.Time
}

// AnonymousCSRF returns the token of pre-auth context id, creating a new context when id is unknown
// or expired. It never creates a session and stays available during recovery.
func (s *Service) AnonymousCSRF(id string) (contextID, token string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	if c, ok := s.anonymous[id]; ok && s.anonymousLive(c, now) {
		return id, c.token, nil
	}
	delete(s.anonymous, id)
	if contextID, err = s.opts.NewToken(); err == nil {
		token, err = s.opts.NewToken()
	}
	if err != nil {
		return "", "", fmt.Errorf("CSRF token: %w", err)
	}
	if _, taken := s.anonymous[contextID]; taken || contextID == "" || token == "" || contextID == token {
		return "", "", errors.New("CSRF token: unusable token")
	}
	s.makeAnonymousRoomLocked(now)
	s.anonymous[contextID] = &anonymousContext{token: token, created: now}
	return contextID, token, nil
}

// CheckAnonymousCSRF reports whether token belongs to the live pre-auth context id.
func (s *Service) CheckAnonymousCSRF(id, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.anonymous[id]
	return ok && s.anonymousLive(c, s.opts.Now()) && MatchToken(c.token, token)
}

// DiscardAnonymous removes a pre-auth context once it is no longer needed, for example after login.
func (s *Service) DiscardAnonymous(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.anonymous, id)
}

// SessionCSRF returns the CSRF token of a live session. It neither extends the session nor authorizes
// anything else. Recovery clears sessions, so logout then uses an anonymous context.
func (s *Service) SessionCSRF(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sessions[sessionDigest(id)]
	if !ok || id == "" || s.expired(st, s.opts.Now()) || st.credentialVersion != s.account.CredentialVersion {
		return "", false
	}
	return sessionCSRF(id), true
}

// MatchToken compares tokens in constant time; an empty token never matches.
func MatchToken(want, got string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func (s *Service) anonymousLive(c *anonymousContext, now time.Time) bool {
	return now.Before(c.created.Add(s.opts.AnonymousTTL))
}

// makeAnonymousRoomLocked drops expired contexts, then the oldest one while the bound is reached.
func (s *Service) makeAnonymousRoomLocked(now time.Time) {
	for id, c := range s.anonymous {
		if !s.anonymousLive(c, now) {
			delete(s.anonymous, id)
		}
	}
	for len(s.anonymous) >= s.opts.MaxAnonymous {
		var oldestID string
		var oldest *anonymousContext
		for id, c := range s.anonymous {
			if oldest == nil || c.created.Before(oldest.created) {
				oldestID, oldest = id, c
			}
		}
		delete(s.anonymous, oldestID)
	}
}
