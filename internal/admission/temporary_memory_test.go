package admission

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func body(i int) []byte { return []byte(fmt.Sprintf("body-%d", i)) }

func TestPreauthWindowAndBoundary(t *testing.T) {
	m := &TemporaryMemory{}
	for i := range 5 {
		if wait := m.Admit("p", "c", body(i), t0.Add(time.Duration(i)*time.Second)); wait != 0 {
			t.Fatalf("attempt %d refused for %s", i, wait)
		}
	}
	wait := m.Admit("p", "c", body(5), t0.Add(5*time.Second))
	if want := 10*time.Minute - 5*time.Second; wait != want {
		t.Fatalf("wait %s, want %s (first attempt leaves the window)", wait, want)
	}
	// Exactly at the boundary the oldest attempt has left the window.
	if wait := m.Admit("p", "c", body(5), t0.Add(10*time.Minute)); wait != 0 {
		t.Fatalf("at the window boundary: %s", wait)
	}
	if wait := m.Admit("other", "c", body(0), t0.Add(5*time.Second)); wait != 0 {
		t.Fatalf("another preauth: %s", wait)
	}
}

func TestRepeatedFingerprintIsNotChargedAndStaysAdmitted(t *testing.T) {
	m := &TemporaryMemory{}
	for i := range 5 {
		m.Admit("p", "c", body(i), t0)
	}
	if wait := m.Admit("p", "c", body(3), t0); wait != 0 {
		t.Fatalf("repeat of an admitted submission refused: %s", wait)
	}
	if wait := m.Admit("p", "c", body(9), t0); wait == 0 {
		t.Fatal("a new submission over the budget admitted")
	}
}

func TestRefusedAttemptChargesNothing(t *testing.T) {
	m := &TemporaryMemory{PerClient: true}
	for i := range 5 {
		m.Admit("p", "c", body(i), t0)
	}
	m.Admit("p", "c", body(9), t0)
	if len(m.process) != 5 || len(m.clients["c"]) != 5 {
		t.Fatalf("refused attempt was charged: process=%d client=%d", len(m.process), len(m.clients["c"]))
	}
}

func TestClientBudgetOnlyWhenEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		m := &TemporaryMemory{PerClient: enabled}
		refused := 0
		for i := range 25 {
			if m.Admit(fmt.Sprint("p", i), "same-client", body(i), t0) != 0 {
				refused++
			}
		}
		if want := map[bool]int{false: 0, true: 5}[enabled]; refused != want {
			t.Fatalf("PerClient=%v: %d refused, want %d", enabled, refused, want)
		}
	}
}

func TestProcessBudgetAndWindow(t *testing.T) {
	m := &TemporaryMemory{}
	for i := range 200 {
		if wait := m.Admit(fmt.Sprint("p", i), "", body(i), t0); wait != 0 {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if wait := m.Admit("p-new", "", body(1000), t0.Add(time.Minute)); wait != time.Hour-time.Minute {
		t.Fatalf("over the process budget: %s", wait)
	}
	if wait := m.Admit("p-new", "", body(1000), t0.Add(time.Hour)); wait != 0 {
		t.Fatalf("after the window: %s", wait)
	}
}

func TestMemoryIsBounded(t *testing.T) {
	m := &TemporaryMemory{PerClient: true}
	now := t0
	for i := range maxPreauthKeys + 100 {
		m.Admit(fmt.Sprint("p", i), fmt.Sprint("c", i), body(i), now)
		if i%150 == 149 {
			now = now.Add(time.Hour) // processLimit would otherwise stop the loop first
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.preauths) > maxPreauthKeys || len(m.clients) > maxClientKeys {
		t.Fatalf("tables grew past their ceilings: %d %d", len(m.preauths), len(m.clients))
	}
	m.sweep(now.Add(48 * time.Hour))
	if len(m.preauths)+len(m.clients)+len(m.process) != 0 {
		t.Fatal("expired entries kept")
	}
}

func TestFullTableRefusesNewKeysOnly(t *testing.T) {
	m := &TemporaryMemory{}
	m.preauths, m.clients = map[[32]byte][]attempt{}, map[string][]attempt{}
	for i := range maxPreauthKeys {
		m.preauths[[32]byte{byte(i), byte(i >> 8), 1}] = []attempt{{t0, [32]byte{1}}}
	}
	if wait := m.Admit("brand-new", "", body(1), t0); wait != fullWait {
		t.Fatalf("new key in a full table: %s", wait)
	}
}

func TestConcurrentAttemptsAreCountedOnce(t *testing.T) {
	m := &TemporaryMemory{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := range 50 {
		wg.Go(func() {
			if m.Admit("p", "c", body(i), t0) == 0 {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if admitted != 5 {
		t.Fatalf("admitted %d, want 5", admitted)
	}
}
