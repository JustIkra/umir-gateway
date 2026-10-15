package live

import (
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

func TestG3ReversedDeadlineCallbacks(t *testing.T) {
	for _, drain := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "already sent"}[drain], func(t *testing.T) {
			events := NewSessionEvents()
			w, stop := events.watch("session")
			defer stop()
			absolute := start.Add(8 * time.Hour)
			newer, older := start.Add(40*time.Minute), start.Add(35*time.Minute)
			events.SessionExtended("session", 2, newer, absolute)
			if drain {
				if got, ok := w.take(); !ok || !got.idle.Equal(newer) {
					t.Fatal("newer deadline absent")
				}
			}
			events.SessionExtended("session", 1, older, absolute)
			got, ok := w.take()
			if drain {
				if ok {
					t.Fatalf("stale callback published after current: %+v", got)
				}
			} else if !ok || !got.idle.Equal(newer) {
				t.Fatalf("reversed callbacks downgraded deadline: %+v", got)
			}
		})
	}
}

func TestG3SessionEndSurvivesDrainedNotification(t *testing.T) {
	events := NewSessionEvents()
	w, stop := events.watch("session")
	defer stop()
	events.SessionEnded("session", 2, operator.EndRevoked)
	if got, ok := w.take(); !ok || got.ended != operator.EndRevoked {
		t.Fatal("missing end")
	}
	events.SessionExtended("session", 3, start.Add(time.Hour), start.Add(8*time.Hour))
	if got, ok := w.take(); ok {
		t.Fatalf("ended watcher revived: %+v", got)
	}
}

func TestG3OlderDeadlineCannotReachSSEClient(t *testing.T) {
	f := newFixture(t, 8, 64)
	stream := f.greeted(t, f.serve(t), "session-token")
	key := operator.SessionKey("session-token")
	newer := start.Add(32 * time.Minute)
	f.events.SessionExtended(key, 2, newer, start.Add(8*time.Hour))
	if got := stream.next(); !strings.Contains(got, newer.Format(time.RFC3339)) {
		t.Fatalf("newer deadline: %s", got)
	}
	f.events.SessionExtended(key, 1, start.Add(31*time.Minute), start.Add(8*time.Hour))
	f.changes.append()
	if got := stream.next(); !strings.HasPrefix(got, "change ") {
		t.Fatalf("old deadline reached stream: %s", got)
	}
}

func TestG3RevisionOrdersDeadlineInsteadOfClockValue(t *testing.T) {
	events := NewSessionEvents()
	w, stop := events.watch("session")
	defer stop()
	events.SessionExtended("session", 1, start.Add(time.Hour), start.Add(8*time.Hour))
	events.SessionExtended("session", 2, start.Add(30*time.Minute), start.Add(8*time.Hour))
	events.SessionExtended("session", 2, start.Add(2*time.Hour), start.Add(8*time.Hour))
	got, ok := w.take()
	if !ok || !got.idle.Equal(start.Add(30*time.Minute)) {
		t.Fatalf("revision ignored: %+v", got)
	}
}

func TestG3DelayedPreWatchCallbackCannotDowngradeGreeting(t *testing.T) {
	f := newFixture(t, 8, 64)
	newer := start.Add(32 * time.Minute)
	f.sessions.set(operator.Session{PublicationRevision: 2, IdleExpiresAt: newer, AbsoluteExpiresAt: start.Add(8 * time.Hour)}, nil)
	stream := f.greeted(t, f.serve(t), "session-token")
	f.events.SessionExtended(operator.SessionKey("session-token"), 1, start.Add(31*time.Minute), start.Add(8*time.Hour))
	f.changes.append()
	if got := stream.next(); !strings.HasPrefix(got, "change ") {
		t.Fatalf("old pre-watch deadline reached stream: %s", got)
	}
}
