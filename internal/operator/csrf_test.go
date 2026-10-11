package operator

import (
	"fmt"
	"testing"
	"time"
)

func TestAnonymousCSRFContext(t *testing.T) {
	f := newFixture(t, nil)
	id, token, err := f.svc.AnonymousCSRF("")
	if err != nil || id == "" || token == "" {
		t.Fatalf("AnonymousCSRF = %q, %q, %v", id, token, err)
	}
	againID, againToken, err := f.svc.AnonymousCSRF(id)
	if err != nil || againID != id || againToken != token {
		t.Fatalf("reuse = %q, %q, %v", againID, againToken, err)
	}
	if !f.svc.CheckAnonymousCSRF(id, token) {
		t.Fatal("valid token rejected")
	}
	for _, tc := range []struct{ id, token string }{{id, ""}, {id, token + "x"}, {"unknown", token}, {"", ""}} {
		if f.svc.CheckAnonymousCSRF(tc.id, tc.token) {
			t.Errorf("CheckAnonymousCSRF(%q, %q) accepted", tc.id, tc.token)
		}
	}
	if len(f.svc.sessions) != 0 {
		t.Error("anonymous context created a session")
	}
	f.clock.Advance(DefaultAnonymousTTL)
	if f.svc.CheckAnonymousCSRF(id, token) {
		t.Error("expired context accepted")
	}
	newID, newToken, err := f.svc.AnonymousCSRF(id)
	if err != nil || newID == id || newToken == token {
		t.Errorf("expired context reused: %q, %q, %v", newID, newToken, err)
	}
	f.svc.DiscardAnonymous(newID)
	if f.svc.CheckAnonymousCSRF(newID, newToken) {
		t.Error("discarded context accepted")
	}
}

func TestAnonymousContextsAreBounded(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.MaxAnonymous = 2 })
	type ctx struct{ id, token string }
	var made []ctx
	for range 3 {
		id, token, err := f.svc.AnonymousCSRF("")
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, ctx{id, token})
		f.clock.Advance(time.Second)
	}
	if len(f.svc.anonymous) != 2 {
		t.Fatalf("anonymous contexts = %d", len(f.svc.anonymous))
	}
	if f.svc.CheckAnonymousCSRF(made[0].id, made[0].token) {
		t.Error("oldest context survived")
	}
	if !f.svc.CheckAnonymousCSRF(made[2].id, made[2].token) {
		t.Error("newest context evicted")
	}
}

func TestAnonymousCSRFWorksDuringRecovery(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	f.store.setErr(fmt.Errorf("%w: rename", ErrUpdateOutcomeUnknown))
	if _, err := f.svc.UpdateDisplayName(session.ID, "Смена"); err == nil {
		t.Fatal("expected recovery")
	}
	id, token, err := f.svc.AnonymousCSRF("")
	if err != nil || !f.svc.CheckAnonymousCSRF(id, token) {
		t.Fatalf("anonymous CSRF during recovery: %v", err)
	}
	if _, ok := f.svc.SessionCSRF(session.ID); ok {
		t.Error("session from before recovery still offers CSRF")
	}
}

func TestSessionCSRFDoesNotExtendSession(t *testing.T) {
	f := newFixture(t, nil)
	session := f.login(t)
	if token, ok := f.svc.SessionCSRF(session.ID); !ok || token != session.CSRFToken {
		t.Fatalf("SessionCSRF = %q, %v", token, ok)
	}
	f.clock.Advance(20 * time.Minute)
	if _, ok := f.svc.SessionCSRF(session.ID); !ok {
		t.Fatal("live session not found")
	}
	f.clock.Advance(11 * time.Minute)
	if _, ok := f.svc.SessionCSRF(session.ID); ok {
		t.Error("SessionCSRF extended the idle deadline")
	}
	if _, ok := f.svc.SessionCSRF("unknown"); ok {
		t.Error("unknown session offered CSRF")
	}
}

func TestMatchToken(t *testing.T) {
	for _, tc := range []struct {
		want, got string
		match     bool
	}{{"abc", "abc", true}, {"abc", "abd", false}, {"abc", "ab", false}, {"", "", false}, {"abc", "", false}} {
		if MatchToken(tc.want, tc.got) != tc.match {
			t.Errorf("MatchToken(%q, %q) != %v", tc.want, tc.got, tc.match)
		}
	}
}
