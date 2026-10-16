package journal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

const applyOrg = "22222222-2222-4222-8222-222222222222"
const applyGenerationA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const applyGenerationB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const applyAuthGeneration = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

var applyOccurredAt = time.Date(2026, 10, 16, 12, 0, 0, 0, time.FixedZone("MSK", 3*60*60))

func applyJournal(t *testing.T, mode string) (*Scoped, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.FixedZone("MSK", 3*60*60))
	j, err := NewScopedWithOptions(ScopedOptions{
		Epoch: "gateway-boot", Capacity: 4, MaxScopes: 2, MaxClosedScopes: 10, MaxCursors: 4,
		RingIdle: time.Minute, TopicsMode: mode, Now: func() time.Time { return now },
		NewCursor: func() string { return "cursor" }, Codec: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	return j, &now
}

func warehouseEvent(id string, revision int64, generation string, topics ...string) Event {
	return Event{EventID: id, Owner: "warehouse", Type: "warehouse.OrderPlaced", SchemaVersion: 1, OrgID: applyOrg, RestaurantID: "33333333-3333-4333-8333-333333333333", AggregateID: "33333333-3333-4333-8333-333333333333", AggregateRevision: revision, Generation: generation, OccurredAt: applyOccurredAt, Topics: topics}
}

func TestScopedApplyDeduplicatesAndResetsOnRevisionGap(t *testing.T) {
	j, _ := applyJournal(t, TopicsAll)
	signals, stop, err := j.WatchScope(warehouseEvent("ignored", 1, applyGenerationA).RestaurantID, applyOrg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	initial, err := j.Read(warehouseEvent("ignored", 1, applyGenerationA).RestaurantID, "actor", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Apply(warehouseEvent("event-1", 1, applyGenerationA, "stock")); err != nil {
		t.Fatal(err)
	}
	first, err := j.Read(warehouseEvent("ignored", 1, applyGenerationA).RestaurantID, "actor", "", 0, initial.Generation)
	if err != nil || first.Last != 1 || len(first.Changes) != 1 || len(first.Changes[0].Topics) != 5 {
		t.Fatalf("first event snapshot=%+v err=%v", first, err)
	}
	if err := j.Apply(warehouseEvent("event-1", 1, applyGenerationA, "stock")); err != nil {
		t.Fatal(err)
	}
	if err := j.Apply(warehouseEvent("event-old", 1, applyGenerationA, "stock")); err != nil {
		t.Fatal(err)
	}
	duplicate, err := j.Read(firstTenant(first), "actor", "", 1, first.Generation)
	if err != nil || duplicate.Last != 1 || len(duplicate.Changes) != 0 {
		t.Fatalf("duplicate/late event changed ring: %+v %v", duplicate, err)
	}
	if err := j.Apply(warehouseEvent("event-gap", 3, applyGenerationA, "menu")); err != nil {
		t.Fatal(err)
	}
	reset, err := j.Read(firstTenant(first), "actor", "", 0, first.Generation)
	if err != nil || !reset.Refresh || reset.Generation == first.Generation {
		t.Fatalf("revision gap did not reset ring: %+v %v", reset, err)
	}
	select {
	case <-signals:
	default:
		t.Fatal("revision gap did not wake subscribers")
	}
}

func TestObserveRuntimeDoesNotCreateScope(t *testing.T) {
	j, _ := applyJournal(t, TopicsAll)
	if err := j.ObserveRuntime("unwatched", "warehouse", "generation"); err != nil {
		t.Fatal(err)
	}
	if len(j.scopes) != 0 {
		t.Fatalf("runtime observation created %d scopes", len(j.scopes))
	}
}

func TestApplyDropsOwnerEventBeforeTheScopeIsWatched(t *testing.T) {
	j, _ := applyJournal(t, TopicsAll)
	event := warehouseEvent("before-watch", 1, applyGenerationA, "stock")
	if err := j.Apply(event); err != nil {
		t.Fatal(err)
	}
	if len(j.scopes) != 0 {
		t.Fatal("event created a ring without an AccessCheck-backed watch")
	}
	if _, stop, err := j.WatchScope(event.RestaurantID, event.OrgID); err != nil {
		t.Fatal(err)
	} else {
		stop()
	}
	snapshot, err := j.Read(event.RestaurantID, "actor", "", 0, 0)
	if err != nil || !snapshot.Refresh || snapshot.Last != 0 {
		t.Fatalf("client without a valid cursor did not need refresh: %+v %v", snapshot, err)
	}
}

func TestScopedApplyRejectsForeignOrganizationAndResetsOnNewGeneration(t *testing.T) {
	j, _ := applyJournal(t, TopicsEvent)
	tenant := "33333333-3333-4333-8333-333333333333"
	_, stop, err := j.WatchScope(tenant, applyOrg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := j.Apply(Event{EventID: "foreign", Owner: "warehouse", Type: "warehouse.OrderPlaced", SchemaVersion: 1, OrgID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", RestaurantID: tenant, AggregateID: tenant, AggregateRevision: 1, Generation: applyGenerationA, OccurredAt: applyOccurredAt, Topics: []string{"stock"}}); err != nil {
		t.Fatal(err)
	}
	initial, err := j.Read(tenant, "actor", "", 0, 0)
	if err != nil || initial.Last != 0 {
		t.Fatalf("foreign tenant event was retained: %+v %v", initial, err)
	}
	if err := j.Apply(warehouseEvent("event-a", 1, applyGenerationA, "stock")); err != nil {
		t.Fatal(err)
	}
	active, err := j.Read(tenant, "actor", "", 0, initial.Generation)
	if err != nil || active.Last != 1 || active.Changes[0].Topics[0] != "stock" {
		t.Fatalf("event topics were not narrowed: %+v %v", active, err)
	}
	if err := j.Apply(warehouseEvent("event-b", 1, applyGenerationB, "menu")); err != nil {
		t.Fatal(err)
	}
	reset, err := j.Read(tenant, "actor", "", 0, active.Generation)
	if err != nil || !reset.Refresh || reset.Generation == active.Generation {
		t.Fatalf("generation change did not reset ring: %+v %v", reset, err)
	}
}

func TestScopedResetAllAndIdleScopes(t *testing.T) {
	j, now := applyJournal(t, TopicsAll)
	tenant := "33333333-3333-4333-8333-333333333333"
	if _, stop, err := j.WatchScope(tenant, applyOrg); err != nil {
		t.Fatal(err)
	} else {
		stop()
	}
	if err := j.Apply(warehouseEvent("event-1", 1, applyGenerationA, "stock")); err != nil {
		t.Fatal(err)
	}
	before, err := j.Read(tenant, "actor", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.ResetAll(); err != nil {
		t.Fatal(err)
	}
	reset, err := j.Read(tenant, "actor", "", 0, before.Generation)
	if err != nil || !reset.Refresh || reset.Generation == before.Generation {
		t.Fatalf("ResetAll did not invalidate scope: %+v %v", reset, err)
	}
	*now = now.Add(time.Minute)
	newTenant := "44444444-4444-4444-8444-444444444444"
	_, stop, err := j.WatchScope(newTenant, applyOrg)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if j.scopes[tenant] != nil || j.scopes[newTenant] == nil {
		t.Fatalf("idle scope was not evicted: old=%t new=%t", j.scopes[tenant] != nil, j.scopes[newTenant] != nil)
	}
}

type testCursorCodec struct{}

func (testCursorCodec) Encode(position CursorPosition) (string, error) {
	data, err := json.Marshal(position)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func (testCursorCodec) Decode(value string) (CursorPosition, error) {
	var position CursorPosition
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return position, err
	}
	err = json.Unmarshal(data, &position)
	return position, err
}

func TestScopedAEADCursorPathDoesNotRetainCursorCache(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.FixedZone("MSK", 3*60*60))
	j, err := NewScopedWithOptions(ScopedOptions{
		Epoch: "gateway-boot", Capacity: 2, MaxScopes: 2, MaxClosedScopes: 2, RingIdle: time.Minute,
		TopicsMode: TopicsAll, Now: func() time.Time { return now }, Codec: testCursorCodec{},
	})
	if err != nil {
		t.Fatal(err)
	}
	tenant := "33333333-3333-4333-8333-333333333333"
	if _, stop, err := j.WatchScope(tenant, applyOrg); err != nil {
		t.Fatal(err)
	} else {
		stop()
	}
	if err := j.Append(tenant, []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := j.Read(tenant, "actor", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := j.Cursor(tenant, "actor", 1, snapshot.Generation)
	if err != nil {
		t.Fatal(err)
	}
	j.mu.Lock()
	retained := len(j.cursors)
	j.mu.Unlock()
	if retained != 0 {
		t.Fatalf("encrypted cursor was retained in process cache: %d", retained)
	}
	replay, err := j.Read(tenant, "actor", cursor, 0, 0)
	if err != nil || replay.Refresh || replay.Last != 1 {
		t.Fatalf("encrypted cursor replay=%+v err=%v", replay, err)
	}
}

func TestScopedApplyAuthRevocationWakesAndDeletingClosesScope(t *testing.T) {
	j, _ := applyJournal(t, TopicsAll)
	tenant := "33333333-3333-4333-8333-333333333333"
	signals, stop, err := j.WatchScope(tenant, applyOrg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := j.Apply(Event{EventID: "auth-membership-1", Owner: "auth", Type: "auth.membership.revoked", SchemaVersion: 1, OrgID: applyOrg, AggregateID: "11111111-1111-4111-8111-111111111111", AggregateRevision: 5, Generation: applyAuthGeneration, OccurredAt: applyOccurredAt}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-signals:
	default:
		t.Fatal("membership revocation did not wake organization streams")
	}
	if err := j.Apply(Event{EventID: "auth-deleting-1", Owner: "auth", Type: "auth.restaurant.deleting", SchemaVersion: 1, OrgID: applyOrg, RestaurantID: tenant, AggregateID: tenant, AggregateRevision: 6, Generation: applyAuthGeneration, OccurredAt: applyOccurredAt}); err != nil {
		t.Fatal(err)
	}
	closed, err := j.Read(tenant, "actor", "", 0, 0)
	if err != nil || !closed.Closed {
		t.Fatalf("deleting event did not close scope: %+v %v", closed, err)
	}
}

func TestScopedApplyDoesNotCloseRestaurantFromForeignOrganization(t *testing.T) {
	j, _ := applyJournal(t, TopicsAll)
	tenant := "33333333-3333-4333-8333-333333333333"
	if _, stop, err := j.WatchScope(tenant, applyOrg); err != nil {
		t.Fatal(err)
	} else {
		stop()
	}
	if err := j.Apply(Event{EventID: "foreign-delete", Owner: "auth", Type: "auth.restaurant.deleted", SchemaVersion: 1, OrgID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", RestaurantID: tenant, AggregateID: tenant, AggregateRevision: 1, Generation: applyAuthGeneration, OccurredAt: applyOccurredAt}); err != nil {
		t.Fatal(err)
	}
	closed, err := j.Read(tenant, "actor", "", 0, 0)
	if err != nil || closed.Closed {
		t.Fatalf("foreign organization event closed tenant scope: %+v %v", closed, err)
	}
}

func TestScopedEventIDLRUIsBoundedPerOwner(t *testing.T) {
	j, _ := applyJournal(t, TopicsAll)
	tenant := "33333333-3333-4333-8333-333333333333"
	if _, stop, err := j.WatchScope(tenant, applyOrg); err != nil {
		t.Fatal(err)
	} else {
		stop()
	}
	for i := range eventIDLimit {
		if err := j.Apply(Event{EventID: fmt.Sprintf("auth-%d", i), Owner: "auth", Type: "auth.organization.settings_changed", SchemaVersion: 1, OrgID: applyOrg, AggregateID: applyOrg, AggregateRevision: int64(i + 1), Generation: applyAuthGeneration, OccurredAt: applyOccurredAt}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range eventIDLimit {
		if err := j.Apply(warehouseEvent(fmt.Sprintf("warehouse-%d", i), int64(i+1), applyGenerationB, "stock")); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(j.seenEventIDs["auth"]); got != eventIDLimit {
		t.Fatalf("Auth event LRU size %d", got)
	}
	if got := len(j.seenEventIDs["warehouse"]); got != eventIDLimit {
		t.Fatalf("Warehouse event LRU size %d", got)
	}
}

func firstTenant(snapshot Snapshot) string {
	return warehouseEvent("ignored", 1, applyGenerationA).RestaurantID
}
