package operator

import (
	"errors"
	"testing"
	"time"
)

// anonymousToken opens a new anonymous CSRF context.
func (f fixture) anonymousToken(t *testing.T) (id, token string) {
	t.Helper()
	id, token, err := f.svc.AnonymousCSRF("")
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

func wantFeedbackLimit(t *testing.T, err error, retryAfter time.Duration) {
	t.Helper()
	var limited *FeedbackLimitError
	if !errors.As(err, &limited) || limited.RetryAfter != retryAfter {
		t.Fatalf("AdmitFeedback = %v, want a limit with Retry-After %v", err, retryAfter)
	}
}

func TestFeedbackAcceptsAnonymousAndSessionTokensWithoutExtendingTheSession(t *testing.T) {
	f := newFixture(t, nil)
	anonymous, anonymousToken := f.anonymousToken(t)
	if err := f.svc.AdmitFeedback("", anonymous, anonymousToken); err != nil {
		t.Fatalf("anonymous post = %v", err)
	}
	session := f.login(t)
	f.clock.Advance(20 * time.Minute)
	if err := f.svc.AdmitFeedback(session.ID, "", session.CSRFToken); err != nil {
		t.Fatalf("post with the session token = %v", err)
	}
	// A live anonymous context is accepted alongside the session; over HTTP a login discards the
	// browser's own anonymous context.
	if err := f.svc.AdmitFeedback(session.ID, anonymous, anonymousToken); err != nil {
		t.Fatalf("post with the anonymous token and a session = %v", err)
	}
	f.clock.Advance(10 * time.Minute)
	if _, _, err := f.svc.Authenticate(session.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("feedback posts extended the session: %v", err)
	}
}

func TestFeedbackRejectsTokensOfNoLiveContext(t *testing.T) {
	f := newFixture(t, nil)
	anonymous, anonymousToken := f.anonymousToken(t)
	session := f.login(t)
	for name, post := range map[string][3]string{
		"no token":                    {session.ID, anonymous, ""},
		"another value":               {session.ID, anonymous, "forged"},
		"session token, no session":   {"", anonymous, session.CSRFToken},
		"anonymous token, no context": {"", "", anonymousToken},
		"token of another context":    {"", "unknown", anonymousToken},
	} {
		for range DefaultFeedbackContextLimit + 1 {
			if err := f.svc.AdmitFeedback(post[0], post[1], post[2]); !errors.Is(err, ErrInvalidCSRFToken) {
				t.Fatalf("%s: AdmitFeedback = %v", name, err)
			}
		}
	}
	// Refused posts count against nothing.
	for range DefaultFeedbackContextLimit {
		if err := f.svc.AdmitFeedback("", anonymous, anonymousToken); err != nil {
			t.Fatalf("valid post after refused ones = %v", err)
		}
	}
	f.clock.Advance(DefaultAnonymousTTL)
	if err := f.svc.AdmitFeedback("", anonymous, anonymousToken); !errors.Is(err, ErrInvalidCSRFToken) {
		t.Errorf("post with an expired context = %v", err)
	}
}

func TestFeedbackContextLimit(t *testing.T) {
	f := newFixture(t, nil)
	anonymous, token := f.anonymousToken(t)
	for i := range DefaultFeedbackContextLimit {
		if err := f.svc.AdmitFeedback("", anonymous, token); err != nil {
			t.Fatalf("post %d = %v", i+1, err)
		}
		f.clock.Advance(time.Second)
	}
	// The sixth post within ten minutes waits until the first one leaves the window.
	f.clock.Advance(500 * time.Millisecond)
	wantFeedbackLimit(t, f.svc.AdmitFeedback("", anonymous, token), DefaultFeedbackWindow-5*time.Second)
	f.clock.Advance(DefaultFeedbackWindow - 5*time.Second - 500*time.Millisecond)
	if err := f.svc.AdmitFeedback("", anonymous, token); err != nil {
		t.Fatalf("post after the first one left the window = %v", err)
	}
	// A refused post did not take a place: the next place frees one second after the second post.
	wantFeedbackLimit(t, f.svc.AdmitFeedback("", anonymous, token), time.Second)
	// A new anonymous context has its own places.
	other, otherToken := f.anonymousToken(t)
	if err := f.svc.AdmitFeedback("", other, otherToken); err != nil {
		t.Errorf("post from a new context = %v", err)
	}
}

func TestFeedbackSessionLimit(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	for i := range DefaultFeedbackContextLimit {
		if err := f.svc.AdmitFeedback(session.ID, "", session.CSRFToken); err != nil {
			t.Fatalf("post %d = %v", i+1, err)
		}
	}
	wantFeedbackLimit(t, f.svc.AdmitFeedback(session.ID, "", session.CSRFToken), DefaultFeedbackWindow)
}

func TestFeedbackProcessLimit(t *testing.T) {
	f := newFixture(t, nil)
	for i := range DefaultFeedbackProcessLimit {
		if i%DefaultFeedbackContextLimit == 0 {
			f.clock.Advance(time.Second)
		}
		id, token := f.anonymousToken(t)
		if err := f.svc.AdmitFeedback("", id, token); err != nil {
			t.Fatalf("post %d = %v", i+1, err)
		}
	}
	id, token := f.anonymousToken(t)
	wantFeedbackLimit(t, f.svc.AdmitFeedback("", id, token), DefaultFeedbackWindow-11*time.Second)
	f.clock.Advance(DefaultFeedbackWindow - 11*time.Second)
	if err := f.svc.AdmitFeedback("", id, token); err != nil {
		t.Fatalf("post after the oldest left the window = %v", err)
	}
}
