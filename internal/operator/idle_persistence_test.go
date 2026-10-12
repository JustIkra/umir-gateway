package operator

import (
	"errors"
	"testing"
	"time"
)

func TestBusinessActivitySurvivesRestart(t *testing.T) {
	for name, admit := range map[string]func(*Service, Session) error{
		"safe": func(s *Service, session Session) error {
			_, _, err := s.Authenticate(session.ID)
			return err
		},
		"unsafe": func(s *Service, session Session) error {
			_, _, err := s.Authorize(session.ID, session.CSRFToken)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			session := f.login(t)
			f.clock.Advance(20 * time.Minute)
			if err := admit(f.svc, session); err != nil {
				t.Fatal(err)
			}
			if got := f.store.last().Sessions[0].LastSeen; !got.Equal(f.clock.Now()) {
				t.Fatalf("persisted LastSeen = %v, want %v", got, f.clock.Now())
			}
			restarted := f.restart(t)
			f.clock.Advance(20 * time.Minute)
			if err := admit(restarted, session); err != nil {
				t.Fatalf("recent activity did not survive restart: %v", err)
			}
		})
	}
}

func TestRememberedBusinessActivityDoesNotPersistOrExtendDeadline(t *testing.T) {
	f := newFixture(t, nil)
	_, session, err := f.svc.Login(t.Context(), "operator", testPassword, "", true)
	if err != nil {
		t.Fatal(err)
	}
	deadline := session.AbsoluteExpiresAt
	writes := len(f.store.states())
	f.clock.Advance(24 * time.Hour)
	_, got, err := f.svc.Authenticate(session.ID)
	if err != nil || !got.AbsoluteExpiresAt.Equal(deadline) {
		t.Fatalf("remembered Authenticate = %+v, %v", got, err)
	}
	if len(f.store.states()) != writes {
		t.Fatal("remembered business activity wrote the session store")
	}
}

func TestBusinessActivityStorageFailureDoesNotAdmitSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		storeErr error
		wantErr  error
	}{
		{"known", errDiskFull, ErrSessionStorageUnavailable},
		{"unknown", errors.New("rename outcome unknown"), ErrSessionUpdateOutcomeUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			session := f.login(t)
			storedBefore := f.store.last().Sessions[0].LastSeen
			f.clock.Advance(time.Minute)
			f.store.setErr(tc.storeErr)
			if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Authenticate = %v, want %v", err, tc.wantErr)
			}
			if got := f.store.last().Sessions[0].LastSeen; !got.Equal(storedBefore) {
				t.Fatalf("failed update changed persisted LastSeen to %v", got)
			}
		})
	}
}
