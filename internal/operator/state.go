package operator

import (
	"errors"
	"strings"
	"time"
)

// State is everything the operator module persists: the account and every server session.
type State struct {
	Account  Account
	Sessions []StoredSession
}

// StoredSession is a server session as persisted. Digest identifies it; the bearer token itself is
// never stored.
type StoredSession struct {
	// Digest is the lowercase hex SHA-256 of the session token.
	Digest            string
	RememberMe        bool
	CredentialVersion int64
	Created           time.Time
	LastSeen          time.Time
	// ExpiresAt is the absolute deadline fixed at login.
	ExpiresAt time.Time
}

// ValidateState checks the account and every session record. Errors name the field and never contain
// values.
func ValidateState(s State) error {
	if err := ValidateAccount(s.Account); err != nil {
		return err
	}
	if len(s.Sessions) > DefaultMaxSessions {
		return errors.New("sessions: exceeds the maximum count")
	}
	seen := make(map[string]bool, len(s.Sessions))
	for _, st := range s.Sessions {
		switch {
		case !isDigest(st.Digest):
			return errors.New("session digest: expected 64 lowercase hex characters")
		case seen[st.Digest]:
			return errors.New("session digest: duplicate")
		case st.CredentialVersion < 1 || st.CredentialVersion > s.Account.CredentialVersion:
			return errors.New("session credentialVersion: expected 1 up to the account's credentialVersion")
		case st.Created.IsZero() || st.LastSeen.Before(st.Created) || !st.ExpiresAt.After(st.Created):
			return errors.New("session times: expected createdAt <= lastSeenAt and expiresAt after createdAt")
		}
		seen[st.Digest] = true
	}
	return nil
}

func isDigest(s string) bool {
	return len(s) == 64 && !strings.ContainsFunc(s, func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'a' || r > 'f')
	})
}
