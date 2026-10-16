package live

import (
	"context"
	"crypto/rand"
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
	"github.com/JustIkra/umir-gateway/internal/operator"
)

type g4TimedChecker struct {
	times  chan time.Time
	calls  int
	denied bool
}

func (a *g4TimedChecker) AccessCheck(ctx context.Context, r httpapi.AccessCheckRequest) (httpapi.RestaurantAccess, error) {
	a.calls++
	a.times <- time.Now()
	if a.calls >= 3 && a.denied {
		return httpapi.RestaurantAccess{}, &httpapi.ScopeError{Status: 403, Code: "Forbidden"}
	}
	return httpapi.RestaurantAccess{OrgID: "22222222-2222-4222-8222-222222222222", RestaurantID: r.RestaurantID, Roles: []string{"Warehouse"}, OrgRoles: []string{}, Permissions: []string{"stock.read"}, Settings: httpapi.ScopeSettings{TimeZone: "Europe/Moscow", SettingsVersion: "1"}, LifecycleVersion: "1"}, nil
}

type g4SlowWriter struct {
	header http.Header
	once   sync.Once
	target string
	body   strings.Builder
}

func (w *g4SlowWriter) Header() http.Header { return w.header }
func (w *g4SlowWriter) WriteHeader(int)     {}
func (w *g4SlowWriter) Flush()              {}
func (w *g4SlowWriter) Write(b []byte) (int, error) {
	if strings.Contains(string(b), w.target) {
		w.once.Do(func() { time.Sleep(3 * time.Second) })
	}
	return w.body.Write(b)
}
func TestG4IdleCheckIncludesWriteLatency(t *testing.T) {
	for _, target := range []string{"event: refresh-required", "event: change"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			j, err := journal.NewScoped("44444444-4444-4444-8444-444444444444", 2, 10, 10, time.Now, rand.Text, nil)
			if err != nil {
				t.Fatal(err)
			}
			cursor := ""
			if target == "event: change" {
				cursor = g4ReplayCursor(t, j)
			}
			a := &g4TimedChecker{times: make(chan time.Time, 20), denied: true}
			h, err := NewHandler(ScopedOptions{Auth: a, Journal: j, Clock: SystemClock{}, PerSession: 1, Total: 1, PerOrg: 1, WriteTimeout: 5 * time.Second, Logger: log.New(io.Discard, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
			done := make(chan struct{})
			writer := &g4SlowWriter{header: make(http.Header), target: target}
			go func() {
				defer close(done)
				h.ServeScope(writer, r, g4Tenant, "actor", cursor)
			}()
			<-a.times
			last := <-a.times
			select {
			case next := <-a.times:
				gap := next.Sub(last)
				t.Logf("consecutive passive Auth checks separated by %s with a 3s write within the 5s write budget", gap)
				if gap > 5*time.Second {
					t.Errorf("idle revalidation exceeded frozen five-second window: %s", gap)
				}
			case <-time.After(9 * time.Second):
				t.Error("idle Auth check did not arrive")
			}
			select {
			case <-done:
				if body := writer.body.String(); strings.Count(body, "event: access-ended") != 1 || !strings.Contains(body, `"reason":"revoked"`) {
					t.Errorf("terminal frames=%q", body)
				}
			case <-time.After(time.Second):
				t.Error("denied stream did not finish")
			}
		})
	}
}

type g4BudgetWriter struct {
	header   http.Header
	target   string
	deadline time.Time
	budget   chan time.Duration
	body     strings.Builder
}

func (w *g4BudgetWriter) Header() http.Header { return w.header }
func (w *g4BudgetWriter) WriteHeader(int)     {}
func (w *g4BudgetWriter) Flush()              {}
func (w *g4BudgetWriter) FlushError() error {
	if w.target != "flush" {
		return nil
	}
	remaining := time.Until(w.deadline)
	w.budget <- remaining
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	<-timer.C
	return context.DeadlineExceeded
}
func (w *g4BudgetWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}
func (w *g4BudgetWriter) Write(b []byte) (int, error) {
	if strings.Contains(string(b), w.target) {
		remaining := time.Until(w.deadline)
		w.budget <- remaining
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		<-timer.C
		return 0, context.DeadlineExceeded
	}
	return w.body.Write(b)
}
func g4ReplayCursor(t *testing.T, j *journal.Scoped) string {
	t.Helper()
	if err := j.Append(g4Tenant, []string{"stock"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := j.Read(g4Tenant, "actor", "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := j.Cursor(g4Tenant, operator.SessionKey("actor"), 1, snapshot.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Append(g4Tenant, []string{"menu"}); err != nil {
		t.Fatal(err)
	}
	return cursor
}
func TestG4BlockedInitialFramesHaveCutoffDeadline(t *testing.T) {
	for _, target := range []string{"retry:", "event: refresh-required", "event: change", "flush"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			j, err := journal.NewScoped("44444444-4444-4444-8444-444444444444", 4, 10, 10, time.Now, rand.Text, nil)
			if err != nil {
				t.Fatal(err)
			}
			cursor := ""
			if target == "event: change" {
				cursor = g4ReplayCursor(t, j)
			}
			a := &g4TimedChecker{times: make(chan time.Time, 20)}
			h, err := NewHandler(ScopedOptions{Auth: a, Journal: j, Clock: SystemClock{}, PerSession: 1, Total: 1, PerOrg: 1, WriteTimeout: 8 * time.Second, Logger: log.New(io.Discard, "", 0)})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &g4BudgetWriter{header: make(http.Header), target: target, budget: make(chan time.Duration, 1)}
			done := make(chan struct{})
			started := time.Now()
			go func() {
				defer close(done)
				h.ServeScope(w, httptest.NewRequest("GET", "/", nil).WithContext(ctx), g4Tenant, "actor", cursor)
			}()
			select {
			case budget := <-w.budget:
				if budget > 4*time.Second || budget <= 0 {
					t.Errorf("write budget=%s; must reserve the Auth cutoff", budget)
				}
			case <-time.After(time.Second):
				t.Fatal("write not reached")
			}
			select {
			case <-done:
				if elapsed := time.Since(started); elapsed > 5*time.Second {
					t.Errorf("blocked stream completed after %s", elapsed)
				}
			case <-time.After(9 * time.Second):
				t.Fatal("blocked stream did not complete")
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.total != 0 || len(h.open) != 0 {
				t.Error("stream permit retained")
			}
		})
	}
}
