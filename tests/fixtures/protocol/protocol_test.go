package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testID = "11111111-1111-4111-8111-111111111111"
const testProject = "umir-backend-0123456789abcdef01234567"

func testClock(t *testing.T) *Clock {
	t.Helper()
	c, e := NewClock(testID, testID, "2026-10-13T09:00:00+03:00", "1")
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestClockReadSetCheckpointAndTimers(t *testing.T) {
	c := testClock(t)
	timer := c.NewTimer(time.Minute)
	if code := c.Set(testID, "1", "2026-10-13T09:01:00+03:00"); code != "" {
		t.Fatal(code)
	}
	select {
	case instant := <-timer.C():
		if !instant.Equal(c.Now()) {
			t.Fatal("timer is not owner time")
		}
	default:
		t.Fatal("advance did not release owner timer")
	}
	if c.Read().Generation != "2" || c.Set(testID, "1", "2026-10-13T09:02:00+03:00") != "ClockConflict" || c.Set(testID, "2", "2026-10-13T09:00:00+03:00") != "ClockBackward" {
		t.Fatal("clock comparisons failed")
	}
}
func TestControlStrictAuthReplayAndCapabilities(t *testing.T) {
	c := testClock(t)
	ticks := NewTicks(c)
	h, e := NewHandler(HandlerOptions{Project: testProject, Credential: strings.Repeat("a", 64), Clock: c, Ticks: ticks, BinarySHA256: strings.Repeat("0", 64), ConfigSHA256: strings.Repeat("1", 64), Ready: func(context.Context) bool { return false }})
	if e != nil {
		t.Fatal(e)
	}
	request := func(body, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", ControlPath, strings.NewReader(body))
		r.Header.Set("Authorization", auth)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"version":1,"project":"` + testProject + `","requestID":"` + testID + `","operation":"clock.set","data":{"expectedInstanceID":"` + testID + `","expectedGeneration":"1","instant":"2026-10-13T09:01:00+03:00"}}`
	if request(body, "").Code != 401 {
		t.Fatal("unauthenticated control admitted")
	}
	first := request(body, "Bearer "+strings.Repeat("a", 64))
	if first.Code != 200 {
		t.Fatal(first.Body.String())
	}
	second := request(body, "Bearer "+strings.Repeat("a", 64))
	if second.Body.String() != first.Body.String() || c.Read().Generation != "2" {
		t.Fatal("replay reapplied clock mutation")
	}
	if request(strings.Replace(body, "09:01:00", "09:02:00", 1), "Bearer "+strings.Repeat("a", 64)).Code != 409 {
		t.Fatal("request identity conflict admitted")
	}
	bad := strings.Replace(body, `"version":1`, `"version":1,"version":1`, 1)
	if request(bad, "Bearer "+strings.Repeat("a", 64)).Code != 400 {
		t.Fatal("duplicate field admitted")
	}
	if json.Valid(first.Body.Bytes()) == false {
		t.Fatal("response is not JSON")
	}
	if request(strings.Replace(body, testProject, "umir-backend-aaaaaaaaaaaaaaaaaaaaaaaa", 1), "Bearer "+strings.Repeat("a", 64)).Code != http.StatusForbidden {
		t.Fatal("wrong project admitted")
	}
}

func TestLostObservationFailsClosed(t *testing.T) {
	c := testClock(t)
	ticks := NewTicks(c)
	ticks.Events <- 1
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if !ticks.Baseline(ctx) {
		t.Fatal("missing baseline")
	}
	if _, code := ticks.Tick(ctx, testID, "1", "22222222-2222-4222-8222-222222222222"); code != "OutcomeUnknown" {
		t.Fatal("lost completion claimed known effect", code)
	}
	ticks.Events <- 2
	if ticks.Available() {
		t.Fatal("late event restored an unprovable FIFO")
	}
	if _, code := ticks.Tick(context.Background(), testID, "1", "33333333-3333-4333-8333-333333333333"); code != "NotReady" {
		t.Fatal("late event matched a subsequent tick", code)
	}
}
func TestCheckpointRestartAndOverflow(t *testing.T) {
	c := testClock(t)
	if c.Set(testID, "1", "2026-10-13T09:00:00+03:00") != "" || c.Read().Generation != "2" {
		t.Fatal("equal instant must advance generation")
	}
	state, ok := c.ReadExpected(testID, "2")
	if !ok {
		t.Fatal("checkpoint comparison")
	}
	restarted, err := NewClock(state.FixtureID, "22222222-2222-4222-8222-222222222222", state.Instant, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Read().InstanceID == state.InstanceID || !restarted.Now().Equal(c.Now()) || restarted.Read().Generation != "2" {
		t.Fatal("restart inferred time or retained instance")
	}
	maxClock, err := NewClock(testID, testID, "2026-10-13T09:00:00+03:00", "9223372036854775807")
	if err != nil {
		t.Fatal(err)
	}
	if maxClock.Set(testID, "9223372036854775807", "2026-10-13T09:00:00+03:00") != "ClockConflict" {
		t.Fatal("generation overflow admitted")
	}
}
func TestControlSchemaRejectionsAndCacheBound(t *testing.T) {
	c := testClock(t)
	h, err := NewHandler(HandlerOptions{Project: testProject, Credential: strings.Repeat("a", 64), Clock: c, Ticks: NewTicks(c), BinarySHA256: strings.Repeat("0", 64), ConfigSHA256: strings.Repeat("1", 64), Ready: func(context.Context) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	base := `{"version":1,"project":"` + testProject + `","requestID":"` + testID + `","operation":"clock.read","data":{}}`
	invoke := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", ControlPath, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, body := range []string{base + `{}`, strings.Replace(base, `"data":{}`, `"data":{"unexpected":1}`, 1), strings.Replace(base, `"data":{}`, `"data":{"a":{"a":1,"a":2}}`, 1), strings.Replace(base, `"operation":"clock.read"`, `"operation":"clock.read","extra":1`, 1), strings.Replace(base, testID, "bad", 1), base + string([]byte{0xff}), strings.Repeat(" ", MaxRequest+1) + base} {
		if w := invoke(body); w.Code != 400 {
			t.Fatalf("malformed control admitted: %d", w.Code)
		}
	}
	for range 256 {
		id, err := UUID()
		if err != nil {
			t.Fatal(err)
		}
		if w := invoke(strings.Replace(base, testID, id, 1)); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	id, err := UUID()
	if err != nil {
		t.Fatal(err)
	}
	if w := invoke(strings.Replace(base, testID, id, 1)); w.Code != 413 {
		t.Fatal("cache silently evicted an operation", w.Code)
	}
}

func TestTickerRejectsConcurrentOutstandingIDs(t *testing.T) {
	c := testClock(t)
	ticks := NewTicks(c)
	ticks.Events <- 1
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !ticks.Baseline(ctx) {
		t.Fatal("baseline")
	}
	first := make(chan string, 1)
	go func() { _, code := ticks.Tick(ctx, testID, "1", "22222222-2222-4222-8222-222222222222"); first <- code }()
	select {
	case <-ticks.ticks:
	case <-ctx.Done():
		t.Fatal("tick ingress")
	}
	second := make(chan string, 1)
	go func() {
		_, code := ticks.Tick(ctx, testID, "1", "33333333-3333-4333-8333-333333333333")
		second <- code
	}()
	select {
	case code := <-second:
		if code != "FaultConflict" {
			t.Fatal(code)
		}
	case <-time.After(20 * time.Millisecond):
		t.Error("concurrent tick waited instead of rejecting outstanding ID")
	}
	ticks.Events <- 2
	if code := <-first; code != "" {
		t.Fatal(code)
	}
	select {
	case <-second:
	default:
	}
}

func TestClockRejectsFractionTruncation(t *testing.T) {
	c := testClock(t)
	if code := c.Set(testID, "1", "2026-10-13T09:00:00.1234567891+03:00"); code != "InvalidRequest" {
		t.Fatalf("silently rounded authoritative instant: %s", code)
	}
	if c.Read().Generation != "1" {
		t.Fatal("invalid instant changed clock")
	}
}
func TestPrivateFileModesAndSymlinkRejection(t *testing.T) {
	dir := privateFileDir(t)
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 64)), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path, 64, 0600); err == nil {
		t.Fatal("credential without exact 0600 mode accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(path, 64, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(link, 64, 0600); err == nil {
		t.Fatal("credential symlink admitted")
	}
}

func TestUnknownOperationIsNotReflected(t *testing.T) {
	c := testClock(t)
	h, err := NewHandler(HandlerOptions{Project: testProject, Credential: strings.Repeat("a", 64), Clock: c, Ticks: NewTicks(c), BinarySHA256: strings.Repeat("0", 64), ConfigSHA256: strings.Repeat("1", 64), Ready: func(context.Context) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"version":1,"project":"` + testProject + `","requestID":"` + testID + `","operation":"unrecognized-input-marker","data":{}}`
	r := httptest.NewRequest("POST", ControlPath, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Body.String(), "unrecognized-input-marker") {
		t.Fatal("invalid operation reflected into ordinary response")
	}
}
