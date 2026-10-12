package operator

import "time"

// EndReason says why a session ended before its deadline.
type EndReason string

const (
	// EndSignedOut is a sign-out, or a new sign-in that replaced the session.
	EndSignedOut EndReason = "signed_out"
	// EndRevoked is a password change, the revocation after wrong current passwords or an eviction
	// at the session bound.
	EndRevoked EndReason = "revoked"
	// EndExpired is a deadline that passed. The service never reports it; watchers find it themselves.
	EndExpired EndReason = "expired"
)

// SessionObserver learns about committed session changes. The service calls it after the commit and
// outside its mutex, so an observer may call the service again; it must not block. key is SessionKey of
// the session's token. Expiry is not reported: nothing commits it, and a watcher knows the deadline.
type SessionObserver interface {
	// SessionExtended reports the deadlines of an ordinary session that a user request extended.
	SessionExtended(key string, idleExpiresAt, absoluteExpiresAt time.Time)
	// SessionEnded reports a session that can no longer be used.
	SessionEnded(key string, reason EndReason)
}

// SessionKey names the session of token in observer calls without the token itself.
func SessionKey(token string) string { return sessionDigest(token) }

// sessionEvent is a committed change waiting for the observer; ended is empty for an extension.
type sessionEvent struct {
	key            string
	ended          EndReason
	idle, absolute time.Time
}

// extendedLocked queues the new deadlines of id after a commit. A remembered session never moves.
func (s *Service) extendedLocked(id string, st *session) {
	if st.rememberMe {
		return
	}
	view := s.view(id, st)
	s.events = append(s.events, sessionEvent{key: sessionDigest(id), idle: view.IdleExpiresAt, absolute: view.AbsoluteExpiresAt})
}

// endedLocked queues the end of the session with digest after a commit.
func (s *Service) endedLocked(digest string, reason EndReason) {
	s.events = append(s.events, sessionEvent{key: digest, ended: reason})
}

// unlock releases s.mu and then reports the changes committed under it, so the observer never runs
// under the mutex.
func (s *Service) unlock() {
	events := s.events
	s.events = nil
	s.mu.Unlock()
	if s.opts.Observer == nil {
		return
	}
	for _, e := range events {
		if e.ended != "" {
			s.opts.Observer.SessionEnded(e.key, e.ended)
			continue
		}
		s.opts.Observer.SessionExtended(e.key, e.idle, e.absolute)
	}
}
