package live

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/journal"
)

const g4Tenant = "33333333-3333-4333-8333-333333333333"
const g4Neighbor = "66666666-6666-4666-8666-666666666666"

type g4Checker struct {
	mu      sync.Mutex
	fail    error
	block   bool
	entered chan struct{}
	calls   int
	onCheck func()
	// orgs overrides the organization an access decision names, per restaurant.
	orgs map[string]string
}

func (a *g4Checker) AccessCheck(ctx context.Context, r httpapi.AccessCheckRequest) (httpapi.RestaurantAccess, error) {
	a.mu.Lock()
	a.calls++
	block, err, hook := a.block, a.fail, a.onCheck
	org := "22222222-2222-4222-8222-222222222222"
	if other, ok := a.orgs[r.RestaurantID]; ok {
		org = other
	}
	a.mu.Unlock()
	if hook != nil {
		hook()
	}
	if block {
		select {
		case a.entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return httpapi.RestaurantAccess{}, ctx.Err()
	}
	if err != nil {
		return httpapi.RestaurantAccess{}, err
	}
	return httpapi.RestaurantAccess{OrgID: org, RestaurantID: r.RestaurantID, Roles: []string{"Warehouse"}, OrgRoles: []string{}, Permissions: []string{"stock.read"}, Settings: httpapi.ScopeSettings{TimeZone: "Europe/Moscow", SettingsVersion: "1"}, LifecycleVersion: "1"}, nil
}
func (a *g4Checker) deny(err error) { a.mu.Lock(); defer a.mu.Unlock(); a.fail = err }

type g4LiveFixture struct {
	handler *Handler
	journal *journal.Scoped
	checker *g4Checker
	server  *httptest.Server
	clock   *fakeClock
}

func g4Live(t *testing.T, per, total int) *g4LiveFixture {
	t.Helper()
	return g4LiveLimits(t, per, total, total)
}

func g4LiveLimits(t *testing.T, per, total, perOrg int) *g4LiveFixture {
	t.Helper()
	clock := &fakeClock{now: start}
	j, err := journal.NewScoped("44444444-4444-4444-8444-444444444444", 2, 10, 100, clock.Now, func() string { return rand.Text() }, nil)
	if err != nil {
		t.Fatal(err)
	}
	checker := &g4Checker{entered: make(chan struct{}, 1)}
	h, err := NewHandler(ScopedOptions{Auth: checker, Journal: j, Clock: clock, PerSession: per, Total: total, PerOrg: perOrg, WriteTimeout: time.Second, Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeScope(w, r, r.URL.Query().Get("tenant"), r.URL.Query().Get("actor"), r.URL.Query().Get("cursor"))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(h.Close)
	return &g4LiveFixture{h, j, checker, server, clock}
}
func g4LiveOpen(t *testing.T, f *g4LiveFixture, tenant, actor, cursor string) *http.Response {
	t.Helper()
	response, err := (&http.Client{Timeout: 3 * time.Second}).Get(f.server.URL + "/?tenant=" + tenant + "&actor=" + actor + "&cursor=" + cursor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	return response
}
func g4Event(t *testing.T, r *bufio.Reader) (string, string) {
	t.Helper()
	var name, id string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimSuffix(line, "\n")
		if strings.HasPrefix(line, "id: ") {
			id = strings.TrimPrefix(line, "id: ")
		}
		if strings.HasPrefix(line, "event: ") {
			name = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			name += " " + strings.TrimPrefix(line, "data: ")
		}
		if line == "" && name != "" {
			return name, id
		}
	}
}

func TestG4RevalidatesBeforeEveryChangeAndStopsReplay(t *testing.T) {
	f := g4Live(t, 2, 4)
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	g4Event(t, reader)
	f.checker.deny(&httpapi.ScopeError{Status: 403, Code: "Forbidden"})
	if err := f.journal.Append(g4Tenant, []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	event, _ := g4Event(t, reader)
	if !strings.Contains(event, `"reason":"revoked"`) || strings.HasPrefix(event, "change") {
		t.Fatalf("denied bytes=%s", event)
	}
	if _, err := reader.ReadString('\n'); !errors.Is(err, io.EOF) {
		t.Fatalf("not closed %v", err)
	}
}

func TestScopedAuthRevocationSignalRechecksAccessImmediately(t *testing.T) {
	f := g4Live(t, 2, 4)
	checks := make(chan struct{}, 4)
	f.checker.mu.Lock()
	f.checker.onCheck = func() {
		select {
		case checks <- struct{}{}:
		default:
		}
	}
	f.checker.mu.Unlock()
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	g4Event(t, reader)
	select {
	case <-checks:
	case <-time.After(time.Second):
		t.Fatal("initial Auth check did not complete")
	}
	f.checker.deny(&httpapi.ScopeError{Status: http.StatusForbidden, Code: "Forbidden"})
	event := journal.Event{EventID: "membership-revoked", Owner: "auth", Type: "auth.membership.revoked", SchemaVersion: 1, OrgID: "22222222-2222-4222-8222-222222222222", AggregateID: "11111111-1111-4111-8111-111111111111", AggregateRevision: 1, Generation: "44444444-4444-4444-8444-444444444444", OccurredAt: time.Now()}
	if err := f.journal.Apply(event); err != nil {
		t.Fatal(err)
	}
	select {
	case <-checks:
	case <-time.After(time.Second):
		t.Fatal("Auth revocation signal did not trigger an immediate access check")
	}
	terminal, _ := g4Event(t, reader)
	if !strings.HasPrefix(terminal, "access-ended ") || !strings.Contains(terminal, `"reason":"revoked"`) {
		t.Fatalf("unexpected terminal frame: %s", terminal)
	}
}

func TestG4OpaqueCursorBoundToRestaurantAndSession(t *testing.T) {
	f := g4Live(t, 3, 5)
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	g4Event(t, reader)
	if err := f.journal.Append(g4Tenant, []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	event, cursor := g4Event(t, reader)
	if cursor == "" || !strings.HasPrefix(event, "change") {
		t.Fatalf("missing cursor: %s %s", event, cursor)
	}
	for _, tc := range []struct{ tenant, actor string }{{g4Neighbor, "actor"}, {g4Tenant, "other"}} {
		bad := g4LiveOpen(t, f, tc.tenant, tc.actor, cursor)
		defer func() {
			if err := bad.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
		if bad.StatusCode != 403 {
			t.Fatalf("cursor replay=%d", bad.StatusCode)
		}
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.journal.Append(g4Tenant, []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	replay := g4LiveOpen(t, f, g4Tenant, "actor", cursor)
	defer func() {
		if err := replay.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	event, _ = g4Event(t, bufio.NewReader(replay.Body))
	if !strings.Contains(event, `"sequence":"2"`) || !strings.Contains(event, `"topics":["menu"]`) {
		t.Fatalf("replay=%s", event)
	}
}

func TestG4LocalDeletionClosesOnlyItsRestaurant(t *testing.T) {
	f := g4Live(t, 4, 4)
	first := g4LiveOpen(t, f, g4Tenant, "same-global-session", "")
	defer func() {
		if err := first.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(first.Body)
	g4Event(t, reader)
	second := g4LiveOpen(t, f, g4Neighbor, "same-global-session", "")
	defer func() {
		if err := second.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	neighbor := bufio.NewReader(second.Body)
	g4Event(t, neighbor)
	if err := f.journal.CloseScope(g4Tenant); err != nil {
		t.Fatal(err)
	}
	event, _ := g4Event(t, reader)
	if !strings.Contains(event, `"reason":"deleted"`) {
		t.Fatalf("scope cutoff=%s", event)
	}
	if _, err := reader.ReadString('\n'); err != io.EOF {
		t.Fatalf("scope not closed: %v", err)
	}
	if err := f.journal.Append(g4Neighbor, []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	event, _ = g4Event(t, neighbor)
	if !strings.HasPrefix(event, "change") {
		t.Fatalf("neighbor session lost: %s", event)
	}
}

func TestG4StreamBoundsCancellationAndCompletion(t *testing.T) {
	f := g4Live(t, 1, 1)
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	g4Event(t, bufio.NewReader(response.Body))
	limited := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := limited.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if limited.StatusCode != 429 {
		t.Fatalf("session bound=%d", limited.StatusCode)
	}
	limited = g4LiveOpen(t, f, g4Neighbor, "other", "")
	defer func() {
		if err := limited.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if limited.StatusCode != 429 {
		t.Fatalf("global bound=%d", limited.StatusCode)
	}
	f.handler.Close()
	if _, err := response.Body.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("shutdown did not close: %v", err)
	}
	f.handler.mu.Lock()
	defer f.handler.mu.Unlock()
	if f.handler.total != 0 || len(f.handler.open) != 0 {
		t.Fatal("stream owner retained connections")
	}
}

func TestG4BlockedAuthHasOwnerCancellation(t *testing.T) {
	f := g4Live(t, 1, 2)
	f.checker.mu.Lock()
	f.checker.block = true
	f.checker.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.handler.ServeScope(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), g4Tenant, "actor", "")
	}()
	select {
	case <-f.checker.entered:
	case <-time.After(time.Second):
		t.Fatal("Auth check not entered")
	}
	f.handler.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked Auth owner did not complete")
	}
}

func TestG4ResetSignalsRefreshWithCurrentEpoch(t *testing.T) {
	f := g4Live(t, 2, 3)
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	g4Event(t, reader)
	if err := f.journal.Append(g4Tenant, []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	event, _ := g4Event(t, reader)
	if !strings.HasPrefix(event, "change") {
		t.Fatal(event)
	}
	if err := f.journal.Reset(g4Tenant); err != nil {
		t.Fatal(err)
	}
	event, _ = g4Event(t, reader)
	if !strings.HasPrefix(event, "refresh-required") || !strings.Contains(event, `"epoch":"44444444-4444-4444-8444-444444444444"`) {
		t.Fatalf("runtime reset=%s", event)
	}
	if err := f.journal.Append(g4Tenant, []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	event, _ = g4Event(t, reader)
	if !strings.Contains(event, `"sequence":"1"`) {
		t.Fatalf("reset sequence=%s", event)
	}
}

func TestG4UnknownAuthOutcomeClosesBeforeChange(t *testing.T) {
	f := g4Live(t, 2, 3)
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	g4Event(t, reader)
	f.checker.deny(errors.New("unknown Auth outcome"))
	if err := f.journal.Append(g4Tenant, []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	event, _ := g4Event(t, reader)
	if !strings.Contains(event, `"reason":"auth-unavailable"`) {
		t.Fatalf("unknown result kept stream=%s", event)
	}
	if _, err := reader.ReadString('\n'); err != io.EOF {
		t.Fatalf("unknown result not closed %v", err)
	}
}

func TestG4ResetDuringEventRevalidationDoesNotSendOldSequence(t *testing.T) {
	f := g4Live(t, 2, 3)
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	g4Event(t, reader)
	var once sync.Once
	f.checker.mu.Lock()
	f.checker.onCheck = func() {
		once.Do(func() {
			if err := f.journal.Reset(g4Tenant); err != nil {
				t.Error(err)
			}
		})
	}
	f.checker.mu.Unlock()
	if err := f.journal.Append(g4Tenant, []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	event, _ := g4Event(t, reader)
	if !strings.HasPrefix(event, "refresh-required") {
		t.Fatalf("stale sequence sent after reset during Auth check: %s", event)
	}
	f.checker.mu.Lock()
	f.checker.onCheck = nil
	f.checker.mu.Unlock()
	if err := f.journal.Append(g4Tenant, []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	event, _ = g4Event(t, reader)
	if !strings.Contains(event, `"sequence":"1"`) {
		t.Fatalf("new runtime sequence=%s", event)
	}
}

func TestG4HeartbeatRevalidatesWithoutSessionActivity(t *testing.T) {
	f := g4Live(t, 2, 3)
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := bufio.NewReader(response.Body)
	g4Event(t, reader)
	limit := time.Now().Add(time.Second)
	for {
		f.clock.mu.Lock()
		ready := false
		for _, timer := range f.clock.timers {
			if timer.at.Equal(start.Add(DefaultPing)) {
				timer.c <- start
				ready = true
				break
			}
		}
		f.clock.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("heartbeat owner did not install timer")
		}
		time.Sleep(time.Millisecond)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != ": ping\n" {
		t.Fatalf("heartbeat=%q", line)
	}
	f.checker.mu.Lock()
	defer f.checker.mu.Unlock()
	if f.checker.calls != 3 {
		t.Fatalf("heartbeat did not make exactly one passive Auth check: %d", f.checker.calls)
	}
}

func TestG4AdmissionFailureMatchesFrozenWire(t *testing.T) {
	f := g4Live(t, 1, 1)
	active := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := active.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	g4Event(t, bufio.NewReader(active.Body))
	limited := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := limited.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := io.ReadAll(limited.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpapi.ValidateScopeWire("Error", data); err != nil {
		t.Fatalf("stream admission invented unfrozen error: %s: %v", data, err)
	}
	if limited.StatusCode != 429 || limited.Header.Get("Retry-After") != "1" || !strings.Contains(string(data), `"code":"RateLimited"`) {
		t.Fatalf("admission=%d %s %v", limited.StatusCode, data, limited.Header)
	}
}

func TestG4AuthAdmissionRateLimitPreservesRetryMetadata(t *testing.T) {
	f := g4Live(t, 1, 2)
	f.checker.deny(&httpapi.ScopeError{Status: 429, Code: "RateLimited", RetryAfter: 60, Retryable: true})
	response := g4LiveOpen(t, f, g4Tenant, "actor", "")
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Retry-After") != "60" || !strings.Contains(string(data), `"retryAfterSeconds":60`) {
		t.Fatalf("Auth retry metadata lost: %v %s", response.Header, data)
	}
}
