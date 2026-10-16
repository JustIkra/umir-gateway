package live

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

const (
	w1OrgA     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	w1OrgB     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	w1TenantB  = "77777777-7777-4777-8777-777777777777"
	w1TenantA2 = "88888888-8888-4888-8888-888888888888"
)

// w1Result is what a client sees of an opened stream; the body, if any, stays open for the test.
type w1Result struct {
	status int
	retry  string
	body   io.Closer
	reader *bufio.Reader
}

func w1Refused(t *testing.T, r w1Result) {
	t.Helper()
	if r.status != http.StatusTooManyRequests || r.retry != "1" {
		t.Fatalf("refusal: %d Retry-After=%q", r.status, r.retry)
	}
}

// w1Open opens a stream and, when it is admitted, waits for its first frame.
func w1Open(t *testing.T, f *g4LiveFixture, tenant, actor string) w1Result {
	t.Helper()
	response, err := (&http.Client{Timeout: 10 * time.Second}).Get(f.server.URL + "/?tenant=" + tenant + "&actor=" + actor)
	if err != nil {
		t.Fatal(err)
	}
	result := w1Result{status: response.StatusCode, retry: response.Header.Get("Retry-After"), body: response.Body, reader: bufio.NewReader(response.Body)}
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	})
	if result.status == http.StatusOK {
		g4Event(t, result.reader) // admitted once its first frame arrives
	}
	return result
}

// The three limits are the ones the options carry, not constants of the package.
func TestW1StreamLimitsComeFromOptions(t *testing.T) {
	t.Run("per session", func(t *testing.T) {
		f := g4LiveLimits(t, 3, 100, 100)
		for i := range 3 {
			if r := w1Open(t, f, g4Tenant, "actor"); r.status != http.StatusOK {
				t.Fatalf("stream %d: %d", i, r.status)
			}
		}
		w1Refused(t, w1Open(t, f, g4Tenant, "actor"))
		if r := w1Open(t, f, g4Tenant, "another"); r.status != http.StatusOK {
			t.Fatalf("another session: %d", r.status)
		}
	})
	t.Run("total", func(t *testing.T) {
		f := g4LiveLimits(t, 100, 3, 100)
		for i := range 3 {
			if r := w1Open(t, f, g4Tenant, "actor-"+string(rune('a'+i))); r.status != http.StatusOK {
				t.Fatalf("stream %d: %d", i, r.status)
			}
		}
		w1Refused(t, w1Open(t, f, g4Tenant, "actor-z"))
	})
	t.Run("per organization", func(t *testing.T) {
		f := g4LiveLimits(t, 100, 100, 3)
		for i := range 3 {
			if r := w1Open(t, f, g4Tenant, "actor-"+string(rune('a'+i))); r.status != http.StatusOK {
				t.Fatalf("stream %d: %d", i, r.status)
			}
		}
		w1Refused(t, w1Open(t, f, g4Tenant, "actor-z"))
	})
	t.Run("invalid", func(t *testing.T) {
		if _, err := NewHandler(ScopedOptions{PerSession: 1, Total: 1}); err == nil {
			t.Fatal("handler without the organization limit accepted")
		}
	})
}

// An organization at its cap does not keep another organization out, and the refused session keeps
// no slot of its own.
func TestW1OrgCapDoesNotStarveOtherOrganization(t *testing.T) {
	f := g4LiveLimits(t, 8, 10, 2)
	f.checker.mu.Lock()
	f.checker.orgs = map[string]string{g4Tenant: w1OrgA, w1TenantA2: w1OrgA, w1TenantB: w1OrgB}
	f.checker.mu.Unlock()
	for _, actor := range []string{"a1", "a2"} {
		if r := w1Open(t, f, g4Tenant, actor); r.status != http.StatusOK {
			t.Fatalf("organization A stream %s: %d", actor, r.status)
		}
	}
	w1Refused(t, w1Open(t, f, w1TenantA2, "a3"))
	if r := w1Open(t, f, w1TenantB, "b1"); r.status != http.StatusOK {
		t.Fatalf("organization B starved by A: %d", r.status)
	}
	f.handler.mu.Lock()
	total, sessions, orgs := f.handler.total, len(f.handler.open), len(f.handler.openOrg)
	f.handler.mu.Unlock()
	if total != 3 || sessions != 3 || orgs != 2 {
		t.Fatalf("refused stream kept slots: total=%d sessions=%d orgs=%d", total, sessions, orgs)
	}
}

func w1Slots(f *g4LiveFixture) (total, sessions, orgs int) {
	f.handler.mu.Lock()
	defer f.handler.mu.Unlock()
	return f.handler.total, len(f.handler.open), len(f.handler.openOrg)
}

func w1WaitFree(t *testing.T, f *g4LiveFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		total, sessions, orgs := w1Slots(f)
		if total == 0 && sessions == 0 && orgs == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("slots not released: total=%d sessions=%d orgs=%d", total, sessions, orgs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Session, organization and total slots are freed on every way out of a stream.
func TestW1ReleaseFreesSessionOrgAndTotalOnEveryExit(t *testing.T) {
	t.Run("client cancel", func(t *testing.T) {
		f := g4LiveLimits(t, 1, 1, 1)
		r := w1Open(t, f, g4Tenant, "actor")
		if err := r.body.Close(); err != nil {
			t.Fatal(err)
		}
		w1WaitFree(t, f)
		if r := w1Open(t, f, g4Tenant, "actor"); r.status != http.StatusOK {
			t.Fatalf("reopen after cancel: %d", r.status)
		}
	})
	t.Run("access error ends the stream", func(t *testing.T) {
		f := g4LiveLimits(t, 1, 1, 1)
		reader := w1Open(t, f, g4Tenant, "actor").reader
		f.checker.deny(&httpapi.ScopeError{Status: 403, Code: "Forbidden"})
		if err := f.journal.Append(g4Tenant, []string{"stock"}); err != nil {
			t.Fatal(err)
		}
		if event, _ := g4Event(t, reader); !strings.Contains(event, "access-ended") {
			t.Fatalf("event: %s", event)
		}
		w1WaitFree(t, f)
	})
	t.Run("refused first check", func(t *testing.T) {
		f := g4LiveLimits(t, 1, 1, 1)
		f.checker.deny(&httpapi.ScopeError{Status: 403, Code: "Forbidden"})
		if r := w1Open(t, f, g4Tenant, "actor"); r.status != http.StatusForbidden {
			t.Fatalf("status %d", r.status)
		}
		w1WaitFree(t, f)
	})
	t.Run("handler completion", func(t *testing.T) {
		f := g4LiveLimits(t, 1, 1, 1)
		w1Open(t, f, g4Tenant, "actor")
		f.handler.Close()
		w1WaitFree(t, f)
	})
}
