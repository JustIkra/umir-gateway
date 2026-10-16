package journal

import (
	"errors"
	"fmt"
	"runtime"
	"testing"
)

func heapInUse() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// Observing or closing a scope, and watching it, never allocates a ring: only a first Append does.
func TestW1ObserveAndCloseAllocateNoRing(t *testing.T) {
	j, _ := g4Journal(t, 4096, 10000, 10)
	before := heapInUse()
	for i := range 5000 {
		if err := j.ObserveRuntime(fmt.Sprintf("observed-%d", i), "warehouse", "epoch"); err != nil {
			t.Fatal(err)
		}
		_, stop, err := j.Watch(fmt.Sprintf("watched-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		stop()
	}
	for i := range 10000 {
		if err := j.CloseScope(fmt.Sprintf("closed-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	after := heapInUse()
	if after > before && after-before > 2<<20 {
		t.Fatalf("10 000 observed or closed scopes hold %d bytes, want under 2 MiB", after-before)
	}
	for _, scope := range j.scopes {
		if scope.ring != nil {
			t.Fatal("a ring was allocated without an Append")
		}
	}
	runtime.KeepAlive(j)
}

// Closed scopes live outside the live slots: they never block a new restaurant.
func TestW1ClosedScopesDoNotUseLiveSlots(t *testing.T) {
	j, _ := g4Journal(t, 4, 3, 10)
	for _, tenant := range []string{"A", "B", "C"} {
		if err := j.CloseScope(tenant); err != nil {
			t.Fatalf("close %s: %v", tenant, err)
		}
	}
	for _, tenant := range []string{"D", "E", "F"} {
		if err := j.Append(tenant, []string{"stock"}); err != nil {
			t.Fatalf("append %s after three closures: %v", tenant, err)
		}
	}
	if err := j.Append("G", []string{"stock"}); err != nil {
		t.Fatalf("oldest idle scope should be evicted: %v", err)
	}
	if j.scopes["D"] != nil || j.scopes["G"] == nil {
		t.Fatal("capacity eviction did not remove the oldest idle scope")
	}
	var stops []func()
	for _, tenant := range []string{"E", "F", "G"} {
		_, stop, err := j.Watch(tenant)
		if err != nil {
			t.Fatal(err)
		}
		stops = append(stops, stop)
	}
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()
	if err := j.Append("H", []string{"stock"}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("active scopes must not be evicted: %v", err)
	}
	if err := j.Append("A", []string{"stock"}); err == nil {
		t.Fatal("a closed scope accepted a change")
	}
	snapshot, err := j.Read("A", "actor", "", 0, 0)
	if err != nil || !snapshot.Closed {
		t.Fatalf("closed scope read: %+v %v", snapshot, err)
	}
	if err := j.CloseScope("A"); err != nil {
		t.Fatalf("closing twice: %v", err)
	}
	ch, stop, err := j.Watch("A")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	select {
	case <-ch:
	default:
		t.Fatal("a watcher of a closed scope is not woken")
	}
}

// A scope that became live again by being reset never shares a generation with an earlier ring.
func TestW1RecreatedRingNeverAcceptsOldCursor(t *testing.T) {
	j, _ := g4Journal(t, 4, 10, 10)
	if err := j.Append("A", []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	first, err := j.Read("A", "actor", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := j.Cursor("A", "actor", 1, first.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Reset("A"); err != nil {
		t.Fatal(err)
	}
	if err := j.Append("A", []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	second, err := j.Read("A", "actor", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation == first.Generation {
		t.Fatalf("recreated ring reuses generation %d", first.Generation)
	}
	replay, err := j.Read("A", "actor", handle, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Refresh || len(replay.Changes) != 0 {
		t.Fatalf("old cursor on the recreated ring: %+v", replay)
	}
	// Another scope never starts at generation 1 once the process has issued generations.
	if err := j.Append("B", []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	other, err := j.Read("B", "actor", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if other.Generation <= second.Generation {
		t.Fatalf("generation did not come from the process counter: %d after %d", other.Generation, second.Generation)
	}
}
