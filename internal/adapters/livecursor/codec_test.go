package livecursor

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/journal"
)

func TestG4CursorAuthenticatesEncryptedPositionAcrossRestarts(t *testing.T) {
	first, err := New("synthetic-private-key")
	if err != nil {
		t.Fatal(err)
	}
	position := journal.CursorPosition{Tenant: "restaurant", Actor: "session-digest", Epoch: "old-epoch", Sequence: 9007199254740993, Generation: 3, Expires: time.Date(2026, 10, 13, 2, 0, 0, 0, time.FixedZone("MSK", 10800))}
	handle, err := first.Encode(position)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(handle, position.Actor) || strings.Contains(handle, position.Tenant) || len(handle) > 1024 {
		t.Fatal("cursor exposes identity or exceeds bound")
	}
	another, err := first.Encode(position)
	if err != nil {
		t.Fatal(err)
	}
	if handle == another {
		t.Fatal("cursor nonce reused")
	}
	restarted, err := New("synthetic-private-key")
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Decode(handle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tenant != position.Tenant || got.Actor != position.Actor || got.Epoch != position.Epoch || got.Sequence != position.Sequence || got.Generation != position.Generation || !got.Expires.Equal(position.Expires) {
		t.Fatalf("cursor position changed: %+v", got)
	}
	wrong, err := New("different-private-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Decode(handle); !errors.Is(err, journal.ErrCursor) {
		t.Fatalf("wrong key=%v", err)
	}
	for _, bad := range []string{"browser-selected", strings.Repeat("a", 1025), handle[:len(handle)-1], "!" + handle, handle[:5] + "!" + handle[6:]} {
		if _, err := restarted.Decode(bad); !errors.Is(err, journal.ErrCursor) {
			t.Fatalf("unauthenticated cursor=%v", err)
		}
	}
}
