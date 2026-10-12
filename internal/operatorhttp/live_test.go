package operatorhttp

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

// streamRecorder stands in for the live stream and remembers what the guard passed on.
type streamRecorder struct {
	calls   int
	id      string
	session operator.Session
}

func (s *streamRecorder) serve(w http.ResponseWriter, _ *http.Request, id string, session operator.Session) {
	s.calls++
	s.id, s.session = id, session
	w.WriteHeader(http.StatusOK)
}

func TestGuardLiveRejectsBeforeTheStream(t *testing.T) {
	f := loopbackFixture(t)
	stream := &streamRecorder{}
	guarded := f.api.GuardLive(stream.serve)
	session, _ := f.login()
	preauth, _ := f.anonymous()
	for _, tc := range []struct {
		name   string
		c      call
		status int
		code   string
	}{
		{"POST", call{method: http.MethodPost, path: "/api/live", cookies: []*http.Cookie{session}, origin: testOrigin}, http.StatusMethodNotAllowed, "MethodNotAllowed"},
		{"HEAD", call{method: http.MethodHead, path: "/api/live", cookies: []*http.Cookie{session}}, http.StatusMethodNotAllowed, "MethodNotAllowed"},
		{"cross-site", call{method: http.MethodGet, path: "/api/live", cookies: []*http.Cookie{session}, header: map[string]string{"Sec-Fetch-Site": "cross-site"}}, http.StatusForbidden, "InvalidOrigin"},
		{"same-site", call{method: http.MethodGet, path: "/api/live", cookies: []*http.Cookie{session}, header: map[string]string{"Sec-Fetch-Site": "same-site"}}, http.StatusForbidden, "InvalidOrigin"},
		{"without session", call{method: http.MethodGet, path: "/api/live"}, http.StatusUnauthorized, "Unauthenticated"},
		{"pre-auth cookie only", call{method: http.MethodGet, path: "/api/live", cookies: []*http.Cookie{preauth}}, http.StatusUnauthorized, "Unauthenticated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.send(guarded, tc.c)
			wantProblem(t, w, tc.status, tc.code)
			if tc.status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodGet {
				t.Errorf("Allow = %q", w.Header().Get("Allow"))
			}
			if tc.status == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") != challenge {
				t.Errorf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
			}
		})
	}
	if stream.calls != 0 {
		t.Fatalf("rejected requests opened %d streams", stream.calls)
	}
}

func TestGuardLiveDuringRecovery(t *testing.T) {
	f := loopbackFixture(t)
	stream := &streamRecorder{}
	session, _ := f.login()
	f.store.fail(errors.New("disk vanished"))
	if _, err := f.accounts.UpdateDisplayName(session.Value, "Смена"); !errors.Is(err, operator.ErrUpdateOutcomeUnknown) {
		t.Fatalf("UpdateDisplayName = %v", err)
	}
	wantProblem(t, f.send(f.api.GuardLive(stream.serve), call{method: http.MethodGet, path: "/api/live", cookies: []*http.Cookie{session}}),
		http.StatusServiceUnavailable, "AuthUnavailable")
	if stream.calls != 0 {
		t.Fatal("a stream opened during recovery")
	}
}

func TestGuardLiveAdmitsWithoutExtending(t *testing.T) {
	f := loopbackFixture(t)
	stream := &streamRecorder{}
	session, _ := f.login()
	before := f.idleDeadline(session)
	f.clock.Advance(10 * time.Minute)
	saved := f.store.savedCount()
	for _, site := range []string{"", "same-origin"} {
		c := call{method: http.MethodGet, path: "/api/live", cookies: []*http.Cookie{session}}
		if site != "" {
			c.header = map[string]string{"Sec-Fetch-Site": site}
		}
		if w := f.send(f.api.GuardLive(stream.serve), c); w.Code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site %q: %d %s", site, w.Code, w.Body)
		}
	}
	if stream.calls != 2 || stream.id != session.Value || !stream.session.IdleExpiresAt.Equal(before) {
		t.Fatalf("stream got %d calls, %q, %+v", stream.calls, stream.id, stream.session)
	}
	if !f.idleDeadline(session).Equal(before) || f.store.savedCount() != saved {
		t.Fatal("opening a stream extended the session or wrote the store")
	}
}
