package live

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/operator"
)

var start = time.Date(2026, 10, 12, 14, 0, 30, 0, moscow)

// fakeClock fires its timers only when the test advances it.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	clock   *fakeClock
	at      time.Time
	c       chan time.Time
	stopped bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	t.stopped = true
	return true
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, at: c.now.Add(d), c: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	return t
}

// advance moves the clock and fires every timer that is due.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.timers[:0]
	for _, t := range c.timers {
		if t.stopped {
			continue
		}
		if !t.at.After(c.now) {
			t.c <- c.now
			continue
		}
		kept = append(kept, t)
	}
	c.timers = kept
}

// fakeChanges is a journal that the test moves by hand.
type fakeChanges struct {
	mu     sync.Mutex
	seq    int64
	signal chan struct{}
}

func (c *fakeChanges) Last() (string, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return "epoch-1", c.seq
}

func (c *fakeChanges) Subscribe(context.Context) <-chan struct{} { return c.signal }

func (c *fakeChanges) append() {
	c.mu.Lock()
	c.seq++
	c.mu.Unlock()
	select {
	case c.signal <- struct{}{}:
	default:
	}
}

// fakeSessions answers Peek with the session or the error the test sets.
type fakeSessions struct {
	mu      sync.Mutex
	session operator.Session
	err     error
}

func (s *fakeSessions) Peek(string) (operator.Profile, operator.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return operator.Profile{}, s.session, s.err
}

func (s *fakeSessions) set(session operator.Session, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session, s.err = session, err
}

type fixture struct {
	clock    *fakeClock
	changes  *fakeChanges
	upstream *Upstream
	sessions *fakeSessions
	events   *SessionEvents
	streams  *Streams
}

func newFixture(t *testing.T, perSession, total int) *fixture {
	t.Helper()
	f := &fixture{
		clock:    &fakeClock{now: start},
		changes:  &fakeChanges{signal: make(chan struct{}, 1)},
		upstream: NewUpstream(),
		sessions: &fakeSessions{session: operator.Session{IdleExpiresAt: start.Add(30 * time.Minute), AbsoluteExpiresAt: start.Add(8 * time.Hour)}},
		events:   NewSessionEvents(),
	}
	streams, err := NewStreams(Options{
		Changes: f.changes, Upstream: f.upstream, Sessions: f.sessions, Events: f.events, Clock: f.clock,
		PerSession: perSession, Total: total, Ping: DefaultPing, WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.streams = streams
	return f
}

// serve starts a server whose streams belong to the session token; Close runs before the server stops.
func (f *fixture) serve(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.streams.Serve(w, r, r.URL.Query().Get("token"), operator.Session{})
	}))
	t.Cleanup(server.Close)
	t.Cleanup(f.streams.Close)
	return server.URL
}

type stream struct {
	t      *testing.T
	reader *bufio.Reader
}

// open returns the status, the headers and the stream; the body closes when the test ends.
func open(t *testing.T, address, token string) (int, http.Header, *stream) {
	t.Helper()
	response, err := http.Get(address + "/?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return response.StatusCode, response.Header, &stream{t: t, reader: bufio.NewReader(response.Body)}
}

// next returns the next event or comment: "name data" or ": ping".
func (s *stream) next() string {
	s.t.Helper()
	var name, data string
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			s.t.Fatalf("read: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")
		switch {
		case strings.HasPrefix(line, ": "):
			return line
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "" && name != "":
			return name + " " + data
		}
	}
}

// greeted opens a stream and reads its first frames.
func greeted(t *testing.T, address, token string) *stream {
	t.Helper()
	_, _, s := open(t, address, token)
	for range 4 {
		s.next()
	}
	return s
}

func TestStreamStartsWithHeadersRetryAndFourEvents(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	f.changes.append()
	status, header, s := open(t, f.serve(t), "a")
	if status != http.StatusOK || header.Get("Content-Type") != "text/event-stream; charset=utf-8" ||
		header.Get("Cache-Control") != "no-store" || header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("response: %d %v", status, header)
	}
	if line, err := s.reader.ReadString('\n'); err != nil || line != "retry: 3000\n" {
		t.Fatalf("first line %q %v", line, err)
	}
	want := []string{
		`change {"epoch":"epoch-1","seq":"1"}`,
		`tick {"serverTime":"2026-10-12T14:00:30+03:00"}`,
		`session {"idleExpiresAt":"2026-10-12T14:30:30+03:00","absoluteExpiresAt":"2026-10-12T22:00:30+03:00"}`,
		`upstream {"available":true}`,
	}
	for _, w := range want {
		if got := s.next(); got != w {
			t.Fatalf("got %s, want %s", got, w)
		}
	}
}

func TestChangeBurstsArriveAsOneEventWithTheLatestSeq(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	address := f.serve(t)
	s := greeted(t, address, "a")
	f.changes.mu.Lock()
	f.changes.seq = 41
	f.changes.mu.Unlock()
	f.changes.append()
	f.changes.append()
	if got := s.next(); got != `change {"epoch":"epoch-1","seq":"43"}` {
		t.Fatalf("got %s", got)
	}
}

func TestUpstreamChangesAreReported(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	s := greeted(t, f.serve(t), "a")
	f.upstream.Set(false)
	if got := s.next(); got != `upstream {"available":false}` {
		t.Fatalf("got %s", got)
	}
	f.upstream.Set(true)
	if got := s.next(); got != `upstream {"available":true}` {
		t.Fatalf("got %s", got)
	}
}

func TestSessionEventsReachOnlyTheirSession(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	address := f.serve(t)
	mine := greeted(t, address, "a")
	other := greeted(t, address, "b")
	f.events.SessionExtended(operator.SessionKey("a"), start.Add(40*time.Minute), start.Add(8*time.Hour))
	if got := mine.next(); got != `session {"idleExpiresAt":"2026-10-12T14:40:30+03:00","absoluteExpiresAt":"2026-10-12T22:00:30+03:00"}` {
		t.Fatalf("got %s", got)
	}
	f.events.SessionEnded(operator.SessionKey("a"), operator.EndSignedOut)
	if got := mine.next(); got != `session-ended {"reason":"signed_out"}` {
		t.Fatalf("got %s", got)
	}
	if rest, err := io.ReadAll(mine.reader); err != nil || len(rest) != 0 {
		t.Fatalf("stream stayed open: %q %v", rest, err)
	}
	f.changes.append()
	if got := other.next(); got != `change {"epoch":"epoch-1","seq":"1"}` {
		t.Fatalf("the other session heard %s", got)
	}
}

func TestAnEndIsNeverReplacedByALaterExtension(t *testing.T) {
	w := &watcher{ready: make(chan struct{}, 1)}
	w.offer(update{ended: operator.EndRevoked})
	w.offer(update{idle: start, absolute: start})
	if u, ok := w.take(); !ok || u.ended != operator.EndRevoked {
		t.Fatalf("took %+v %v", u, ok)
	}
}

func TestExpiryEndsTheStreamAfterPeekConfirmsIt(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	s := greeted(t, f.serve(t), "a")
	f.sessions.set(operator.Session{}, operator.ErrUnauthenticated)
	f.clock.advance(30 * time.Minute)
	for {
		got := s.next()
		if strings.HasPrefix(got, "tick ") || got == ": ping" {
			continue
		}
		if got != `session-ended {"reason":"expired"}` {
			t.Fatalf("got %s", got)
		}
		return
	}
}

func TestAMovedDeadlineIsReportedInsteadOfAnEnd(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	s := greeted(t, f.serve(t), "a")
	f.sessions.set(operator.Session{IdleExpiresAt: start.Add(50 * time.Minute), AbsoluteExpiresAt: start.Add(8 * time.Hour)}, nil)
	f.clock.advance(30 * time.Minute)
	for {
		got := s.next()
		if strings.HasPrefix(got, "tick ") || got == ": ping" {
			continue
		}
		if got != `session {"idleExpiresAt":"2026-10-12T14:50:30+03:00","absoluteExpiresAt":"2026-10-12T22:00:30+03:00"}` {
			t.Fatalf("got %s", got)
		}
		return
	}
}

func TestTicksFollowTheMinuteAndPingsKeepTheStreamAlive(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	s := greeted(t, f.serve(t), "a")
	f.clock.advance(15 * time.Second)
	if got := s.next(); got != ": ping" {
		t.Fatalf("after 15 s: %s", got)
	}
	f.clock.advance(15 * time.Second)
	var got []string
	got = append(got, s.next(), s.next())
	if !strings.Contains(strings.Join(got, "|"), `tick {"serverTime":"2026-10-12T14:01:00+03:00"}`) ||
		!strings.Contains(strings.Join(got, "|"), ": ping") {
		t.Fatalf("at the minute: %v", got)
	}
}

func TestStreamLimits(t *testing.T) {
	f := newFixture(t, 2, 3)
	address := f.serve(t)
	greeted(t, address, "a")
	greeted(t, address, "a")
	refused := func(token string) {
		t.Helper()
		response, err := http.Get(address + "/?token=" + token)
		if err != nil {
			t.Fatal(err)
		}
		var body struct{ Code string }
		decodeErr := json.NewDecoder(response.Body).Decode(&body)
		if err := errors.Join(decodeErr, response.Body.Close()); err != nil || response.StatusCode != http.StatusTooManyRequests || body.Code != "TooManyStreams" {
			t.Fatalf("%s: %d %+v %v", token, response.StatusCode, body, err)
		}
	}
	refused("a")
	greeted(t, address, "b")
	refused("c")
}

func TestASessionEndedBeforeTheWatchIsRefused(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	f.sessions.set(operator.Session{}, operator.ErrUnauthenticated)
	response, err := http.Get(f.serve(t) + "/?token=a")
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", response.StatusCode)
	}
}

func TestCloseEndsEveryStream(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	s := greeted(t, f.serve(t), "a")
	f.streams.Close()
	if rest, err := io.ReadAll(s.reader); err != nil || len(rest) != 0 {
		t.Fatalf("after Close: %q %v", rest, err)
	}
}

// stalledWriter accepts the first writes and then blocks until its write deadline passes.
type stalledWriter struct {
	header   http.Header
	mu       sync.Mutex
	writes   int
	deadline time.Time
}

func (w *stalledWriter) Header() http.Header { return w.header }

func (w *stalledWriter) WriteHeader(int) {}

func (w *stalledWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	n, deadline := w.writes, w.deadline
	w.mu.Unlock()
	if n <= 5 {
		return len(b), nil
	}
	time.Sleep(time.Until(deadline))
	return 0, errors.New("write deadline exceeded")
}

func (w *stalledWriter) Flush() {}

func (w *stalledWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadline = t
	return nil
}

func TestAClientThatStopsReadingIsDropped(t *testing.T) {
	f := newFixture(t, DefaultPerSession, DefaultTotal)
	w := &stalledWriter{header: http.Header{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.streams.Serve(w, httptest.NewRequest(http.MethodGet, "/api/live", nil), "a", operator.Session{})
	}()
	f.changes.append()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a stalled client held its stream")
	}
	if !f.streams.acquire(operator.SessionKey("a")) {
		t.Fatal("the dropped stream kept its slot")
	}
}
