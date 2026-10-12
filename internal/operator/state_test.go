package operator

import (
	"strings"
	"testing"
	"time"
)

func validState() State {
	created := time.Date(2026, 10, 11, 12, 0, 0, 0, moscow)
	return State{Account: testAccount(), Sessions: []StoredSession{{
		Digest: strings.Repeat("a1", 32), CredentialVersion: 1,
		Created: created, LastSeen: created.Add(time.Minute), ExpiresAt: created.Add(8 * time.Hour),
	}}}
}

func TestValidateState(t *testing.T) {
	if err := ValidateState(validState()); err != nil {
		t.Fatalf("valid state: %v", err)
	}
	if err := ValidateState(State{Account: testAccount()}); err != nil {
		t.Fatalf("state without sessions: %v", err)
	}
	for name, change := range map[string]func(*State){
		"invalid account":           func(s *State) { s.Account.Login = "" },
		"short digest":              func(s *State) { s.Sessions[0].Digest = strings.Repeat("a", 63) },
		"upper-case digest":         func(s *State) { s.Sessions[0].Digest = strings.Repeat("A1", 32) },
		"non-hex digest":            func(s *State) { s.Sessions[0].Digest = strings.Repeat("g1", 32) },
		"duplicate digest":          func(s *State) { s.Sessions = append(s.Sessions, s.Sessions[0]) },
		"zero credential version":   func(s *State) { s.Sessions[0].CredentialVersion = 0 },
		"future credential version": func(s *State) { s.Sessions[0].CredentialVersion = s.Account.CredentialVersion + 1 },
		"zero creation time":        func(s *State) { s.Sessions[0].Created = time.Time{} },
		"last seen before creation": func(s *State) { s.Sessions[0].LastSeen = s.Sessions[0].Created.Add(-time.Second) },
		"expiry at creation":        func(s *State) { s.Sessions[0].ExpiresAt = s.Sessions[0].Created },
	} {
		s := validState()
		change(&s)
		err := ValidateState(s)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "a1a1") {
			t.Errorf("%s: error repeats the digest: %v", name, err)
		}
	}
}
