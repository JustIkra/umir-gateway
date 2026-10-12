package expiration

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/journal"
)

// upstreamState records what the runner reports about the warehouse.
type upstreamState struct {
	mu     sync.Mutex
	values []bool
}

func (u *upstreamState) Set(available bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.values) == 0 || u.values[len(u.values)-1] != available {
		u.values = append(u.values, available)
	}
}

func (u *upstreamState) changes() []bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]bool(nil), u.values...)
}

// warehouse answers each run with the next of answers; the last one repeats.
type warehouse struct {
	mu      sync.Mutex
	answers []func(w http.ResponseWriter)
	runs    int
}

func (s *warehouse) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) != 0 || r.Method != http.MethodPost || r.URL.Path != "/base/expiration-runs" ||
		r.URL.RawQuery != "" || r.Header.Get("Accept") != "application/json" {
		w.WriteHeader(http.StatusTeapot)
		return
	}
	s.mu.Lock()
	answer := s.answers[min(s.runs, len(s.answers)-1)]
	s.runs++
	s.mu.Unlock()
	answer(w)
}

func answer(status int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil {
			return
		}
	}
}

func run(version string, expired int) func(w http.ResponseWriter) {
	list := ""
	for i := range expired {
		if i > 0 {
			list += ","
		}
		list += `{"batchID":"b","productID":"p","writtenOffQuantity":"1000","reason":"EXPIRATION","expiresAt":"2026-10-12T14:00:00+03:00","processedAt":"2026-10-12T14:00:01+03:00"}`
	}
	return answer(http.StatusOK, `{"evaluatedAt":"2026-10-12T14:00:01+03:00","stateVersion":"`+version+`","expired":[`+list+`]}`)
}

type harness struct {
	runner   *Runner
	journal  *journal.Journal
	upstream *upstreamState
}

func newHarness(t *testing.T, address string, timeout time.Duration) *harness {
	t.Helper()
	j, err := journal.New(16, func() string { return "epoch-1" }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse(address + "/base")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{journal: j, upstream: &upstreamState{}}
	h.runner, err = New(Options{
		Client: &http.Client{}, Warehouse: base, Interval: time.Second, Timeout: timeout, Journal: j, Upstream: h.upstream,
		NewTicker: func(time.Duration) (<-chan time.Time, func()) { return nil, func() {} },
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func serve(t *testing.T, w *warehouse) string {
	t.Helper()
	server := httptest.NewServer(w)
	t.Cleanup(server.Close)
	return server.URL
}

func (h *harness) entries() []journal.Entry { return h.journal.Entries(0) }

func TestRunsWithoutWriteOffsLeaveNoEntry(t *testing.T) {
	h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){run("7", 0)}}), time.Second)
	h.runner.runOnce(context.Background())
	h.runner.runOnce(context.Background())
	if got := h.entries(); len(got) != 0 {
		t.Fatalf("entries: %+v", got)
	}
	if got := h.upstream.changes(); len(got) != 1 || !got[0] {
		t.Fatalf("upstream: %v", got)
	}
}

func TestWriteOffsMakeAnExpirationEntry(t *testing.T) {
	h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){run("9", 2)}}), time.Second)
	h.runner.runOnce(context.Background())
	got := h.entries()
	if len(got) != 1 || got[0].Source != journal.SourceExpiration || got[0].Outcome != journal.OutcomeSuccess ||
		got[0].Count != 2 || got[0].Status != http.StatusOK || got[0].Method != "" || got[0].Path != "" {
		t.Fatalf("entries: %+v", got)
	}
}

func TestAStateChangeOutsideTheJournalMakesAnExternalEntry(t *testing.T) {
	h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){run("5", 0), run("6", 0), run("8", 0), run("8", 0)}}), time.Second)
	h.runner.runOnce(context.Background()) // the first run only learns the version
	h.runner.runOnce(context.Background()) // 5 → 6 without a request: external
	h.journal.Append(journal.Entry{Source: journal.SourceRequest, Method: http.MethodPost, Path: "/api/warehouse/deliveries", Status: 201, Outcome: journal.OutcomeSuccess})
	h.runner.runOnce(context.Background()) // 6 → 8 after a request: already signalled
	h.runner.runOnce(context.Background()) // unchanged
	got := h.entries()
	if len(got) != 2 || got[0].Source != journal.SourceExternal || got[0].Outcome != journal.OutcomeUnknown || got[1].Source != journal.SourceRequest {
		t.Fatalf("entries: %+v", got)
	}
}

func TestAWarehouseRestartIsAnExternalChange(t *testing.T) {
	h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){run("40", 0), run("0", 0)}}), time.Second)
	h.runner.runOnce(context.Background())
	h.runner.runOnce(context.Background())
	if got := h.entries(); len(got) != 1 || got[0].Source != journal.SourceExternal {
		t.Fatalf("entries: %+v", got)
	}
}

func TestFailingRunsSignalOnceAndMarkTheWarehouseUnavailable(t *testing.T) {
	h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){
		answer(http.StatusServiceUnavailable, `{"code":"InventoryUnavailable"}`),
		answer(http.StatusServiceUnavailable, `{"code":"InventoryUnavailable"}`),
		answer(http.StatusServiceUnavailable, `{"code":"InventoryUnavailable"}`),
		run("3", 0),
	}}), time.Second)
	for range 3 {
		h.runner.runOnce(context.Background())
	}
	got := h.entries()
	if len(got) != 1 || got[0].Source != journal.SourceExpiration || got[0].Outcome != journal.OutcomeUnknown || got[0].Status != http.StatusServiceUnavailable {
		t.Fatalf("after three 503: %+v", got)
	}
	if changes := h.upstream.changes(); len(changes) != 1 || changes[0] {
		t.Fatalf("upstream after three failures: %v", changes)
	}
	h.runner.runOnce(context.Background())
	if changes := h.upstream.changes(); len(changes) != 2 || !changes[1] {
		t.Fatalf("upstream after recovery: %v", changes)
	}
}

func TestRejectedRunsLeaveNoEntry(t *testing.T) {
	h := newHarness(t, serve(t, &warehouse{answers: []func(http.ResponseWriter){answer(http.StatusBadRequest, `{"code":"InvalidArgument"}`)}}), time.Second)
	h.runner.runOnce(context.Background())
	if got := h.entries(); len(got) != 0 {
		t.Fatalf("entries: %+v", got)
	}
}

func TestAnUnreachableWarehouseLeavesNoEntry(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	h := newHarness(t, closed.URL, time.Second)
	for range 3 {
		h.runner.runOnce(context.Background())
	}
	if got := h.entries(); len(got) != 0 {
		t.Fatalf("entries: %+v", got)
	}
	if changes := h.upstream.changes(); len(changes) != 1 || changes[0] {
		t.Fatalf("upstream: %v", changes)
	}
}

func TestATimedOutRunIsUnknown(t *testing.T) {
	release := make(chan struct{})
	address := serve(t, &warehouse{answers: []func(http.ResponseWriter){func(http.ResponseWriter) { <-release }}})
	// Registered after serve, so it runs first: the server waits for the held handler when it closes.
	t.Cleanup(func() { close(release) })
	h := newHarness(t, address, 50*time.Millisecond)
	h.runner.runOnce(context.Background())
	if got := h.entries(); len(got) != 1 || got[0].Outcome != journal.OutcomeUnknown || got[0].Status != 0 {
		t.Fatalf("entries: %+v", got)
	}
}

func TestRunsNeverOverlapAndStopWithTheContext(t *testing.T) {
	var inFlight, most atomic.Int32
	release := make(chan struct{})
	slow := &warehouse{answers: []func(http.ResponseWriter){func(w http.ResponseWriter) {
		now := inFlight.Add(1)
		for {
			seen := most.Load()
			if now <= seen || most.CompareAndSwap(seen, now) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		run("1", 0)(w)
	}}}
	h := newHarness(t, serve(t, slow), 5*time.Second)
	ticks := make(chan time.Time, 3)
	h.runner.opts.NewTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.runner.Run(ctx)
	}()
	ticks <- time.Now()
	ticks <- time.Now()
	time.Sleep(100 * time.Millisecond)
	close(release)
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	if most.Load() != 1 {
		t.Fatalf("%d runs at once", most.Load())
	}
}

func TestNewRequiresEveryOption(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("empty options accepted")
	}
}
