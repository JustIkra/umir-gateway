package journal

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func g4Journal(t *testing.T, capacity, maxScopes, maxCursors int) (*Scoped, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 13, 2, 0, 0, 0, time.FixedZone("MSK", 3*60*60))
	next := 0
	j, err := NewScoped("11111111-1111-4111-8111-111111111111", capacity, maxScopes, maxCursors, func() time.Time { return now }, func() string { next++; return fmt.Sprintf("opaque-%d", next) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	return j, &now
}

func TestG4RestaurantCursorReplayIsolation(t *testing.T) {
	j, _ := g4Journal(t, 2, 2, 4)
	if err := j.Append("A", []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	c, err := j.Cursor("A", "actor-A", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	topics := []string{"orders"}
	if err := j.Append("A", topics); err != nil {
		t.Fatal(err)
	}
	topics[0] = "stock"
	if err := j.Append("B", []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	replay, err := j.Read("A", "actor-A", c, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Refresh || len(replay.Changes) != 1 || replay.Changes[0].Sequence != 2 || replay.Changes[0].Topics[0] != "orders" {
		t.Fatalf("replay=%+v", replay)
	}
	replay.Changes[0].Topics[0] = "stock"
	replay, err = j.Read("A", "actor-A", c, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Changes[0].Topics[0] != "orders" {
		t.Fatal("shared retained topics")
	}
	for _, tc := range []struct{ scope, actor, cursor string }{{"B", "actor-A", c}, {"A", "actor-B", c}, {"A", "actor-A", "invented"}} {
		if _, err := j.Read(tc.scope, tc.actor, tc.cursor, 0, 0); !errors.Is(err, ErrCursor) {
			t.Fatalf("spoof allowed: %+v %v", tc, err)
		}
	}
}

func TestG4CursorExpirationOverflowAndRuntimeReset(t *testing.T) {
	for _, why := range []string{"expired", "overflow", "reset"} {
		t.Run(why, func(t *testing.T) {
			j, now := g4Journal(t, 1, 2, 4)
			if err := j.Append("A", []string{"stock"}); err != nil {
				t.Fatal(err)
			}
			c, err := j.Cursor("A", "actor", 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			switch why {
			case "expired":
				*now = now.Add(5 * time.Minute)
			case "overflow":
				for range 2 {
					if err := j.Append("A", []string{"stock"}); err != nil {
						t.Fatal(err)
					}
				}
			case "reset":
				if err := j.Reset("A"); err != nil {
					t.Fatal(err)
				}
			}
			got, err := j.Read("A", "actor", c, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Refresh || len(got.Changes) != 0 {
				t.Fatalf("old journal replayed %+v", got)
			}
		})
	}
}

func TestG4ScopeCloseCannotReviveOrAffectNeighbor(t *testing.T) {
	j, _ := g4Journal(t, 2, 2, 4)
	a, stopA, err := j.Watch("A")
	if err != nil {
		t.Fatal(err)
	}
	defer stopA()
	b, stopB, err := j.Watch("B")
	if err != nil {
		t.Fatal(err)
	}
	defer stopB()
	if err := j.CloseScope("A"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a:
	default:
		t.Fatal("deleted subscriber not woken")
	}
	select {
	case <-b:
		t.Fatal("neighbor invalidated")
	default:
	}
	if err := j.Append("A", []string{"stock"}); err == nil {
		t.Fatal("deleted scope appended")
	}
	if err := j.Reset("A"); err == nil {
		t.Fatal("deleted scope revived")
	}
	if err := j.Append("B", []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	stopA()
	stopB()
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.scopes["A"].subscribers)+len(j.scopes["B"].subscribers) != 0 {
		t.Fatal("subscriber retained after stop")
	}
}

func TestG4JournalCapacityAndCursorBounds(t *testing.T) {
	j, _ := g4Journal(t, 1, 1, 1)
	if err := j.Append("A", []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Append("B", []string{"stock"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("scope capacity=%v", err)
	}
	first, err := j.Cursor("A", "actor", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = j.Cursor("A", "actor", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Read("A", "actor", first, 0, 0); !errors.Is(err, ErrCursor) {
		t.Fatalf("eviction=%v", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.cursors) != 1 || len(j.cursorOrder) != 1 {
		t.Fatal("cursor bound exceeded")
	}
}
