// Package live serves GET /api/live: a server-sent event stream that tells the operator's screens when
// state may have changed, the minute ticks of the gateway clock, the session deadlines and whether the
// warehouse answers. It carries signals only; the screens re-read their data with ordinary requests.
package live

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
	"github.com/JustIkra/umir-gateway/internal/operator"
)

// Defaults of Options.
const (
	DefaultPerSession   = 8
	DefaultTotal        = 64
	DefaultPing         = 15 * time.Second
	DefaultWriteTimeout = 5 * time.Second
)

// Changes is the journal as the streams see it.
type Changes interface {
	// Last returns the epoch and the seq of the newest entry, 0 while the journal is empty.
	Last() (epoch string, seq int64)
	// Subscribe signals after entries that may have changed state until ctx ends.
	Subscribe(ctx context.Context) <-chan struct{}
}

// Sessions checks a session without extending it.
type Sessions interface {
	Peek(id string) (operator.Profile, operator.Session, error)
}

// Options are the streams' dependencies and bounds; every field is required.
type Options struct {
	Changes  Changes
	Upstream *Upstream
	Sessions Sessions
	Events   *SessionEvents
	Clock    Clock
	// PerSession and Total bound the open streams of one session and of the process.
	PerSession, Total int
	// Ping paces the keep-alive comments; WriteTimeout bounds every write to a client.
	Ping, WriteTimeout time.Duration
}

// Streams serves the live streams of one gateway process.
type Streams struct {
	opts Options
	// closing ends every stream when the server shuts down.
	closing context.Context
	close   context.CancelFunc

	mu    sync.Mutex
	open  map[string]int
	total int
}

// NewStreams checks opts.
func NewStreams(opts Options) (*Streams, error) {
	if opts.Changes == nil || opts.Upstream == nil || opts.Sessions == nil || opts.Events == nil || opts.Clock == nil ||
		opts.PerSession <= 0 || opts.Total <= 0 || opts.Ping <= 0 || opts.WriteTimeout <= 0 {
		return nil, errors.New("live: changes, upstream, sessions, events, clock and positive bounds are required")
	}
	closing, cancel := context.WithCancel(context.Background())
	return &Streams{opts: opts, closing: closing, close: cancel, open: map[string]int{}}, nil
}

// Close ends every open stream at once; register it with http.Server.RegisterOnShutdown, because
// Shutdown waits for idle connections and a stream never becomes idle.
func (s *Streams) Close() { s.close() }

// Serve streams to the operator whose session id GuardLive admitted as session.
func (s *Streams) Serve(w http.ResponseWriter, r *http.Request, id string, _ operator.Session) {
	key := operator.SessionKey(id)
	if !s.acquire(key) {
		httpapi.WriteProblem(w, r, http.StatusTooManyRequests, httpapi.Problem{Code: "TooManyStreams", Message: "too many live streams"})
		return
	}
	defer s.release(key)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer context.AfterFunc(s.closing, cancel)()
	// Every source is watched before the first frames, so no change between them is lost. The session is
	// checked again after the watch began: a sign-out right after the guard would otherwise go unheard.
	changes := s.opts.Changes.Subscribe(ctx)
	upstream := s.opts.Upstream.Subscribe(ctx)
	sessionChanges, stopWatching := s.opts.Events.watch(key)
	defer stopWatching()
	_, session, err := s.opts.Sessions.Peek(id)
	if err != nil {
		refuse(w, r, err)
		return
	}

	sessionChanges.observe(session.PublicationRevision)

	header := w.Header()
	header.Set("Content-Type", "text/event-stream; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	out := &sender{w: w, controller: http.NewResponseController(w), timeout: s.opts.WriteTimeout}
	defer func() {
		// A connection the client keeps must not inherit the last write deadline. Once the client is gone
		// or the server stops, there is nothing to keep.
		if err := out.release(); err != nil && ctx.Err() == nil {
			log.Printf("live stream %s: clear write deadline: %v", httpapi.RequestID(r), err)
		}
	}()

	clock := s.opts.Clock
	if !out.send(raw("retry: 3000\n\n"), s.change(), tick(clock.Now()), sessionFrame(session.IdleExpiresAt, session.AbsoluteExpiresAt), s.upstream()) {
		return
	}
	expiry := clock.NewTimer(until(clock, earlier(session.IdleExpiresAt, session.AbsoluteExpiresAt)))
	minute := clock.NewTimer(untilNextMinute(clock.Now()))
	ping := clock.NewTimer(s.opts.Ping)
	defer func() {
		expiry.Stop()
		minute.Stop()
		ping.Stop()
	}()
	for {
		var next frame
		select {
		case <-ctx.Done():
			return
		case <-changes:
			next = s.change()
		case <-upstream:
			next = s.upstream()
		case <-sessionChanges.ready:
			change, ok := sessionChanges.take()
			if !ok {
				continue
			}
			if change.ended != "" {
				out.send(ended(change.ended))
				return
			}
			next = sessionFrame(change.idle, change.absolute)
			expiry.Stop()
			expiry = clock.NewTimer(until(clock, earlier(change.idle, change.absolute)))
		case <-expiry.C():
			_, current, err := s.opts.Sessions.Peek(id)
			if errors.Is(err, operator.ErrUnauthenticated) {
				out.send(ended(operator.EndExpired))
				return
			}
			// During account recovery nothing is known; the deadline is checked again a second later. A
			// session that is still valid moved its deadline without an event, as a remembered one never
			// reports it.
			wait := time.Second
			if err == nil {
				sessionChanges.observe(current.PublicationRevision)
				next = sessionFrame(current.IdleExpiresAt, current.AbsoluteExpiresAt)
				wait = max(until(clock, earlier(current.IdleExpiresAt, current.AbsoluteExpiresAt)), time.Second)
			}
			expiry = clock.NewTimer(wait)
			if err != nil {
				continue
			}
		case <-minute.C():
			next = tick(clock.Now())
			minute = clock.NewTimer(untilNextMinute(clock.Now()))
		case <-ping.C():
			next = raw(": ping\n\n")
			ping = clock.NewTimer(s.opts.Ping)
		}
		if !out.send(next) {
			return
		}
	}
}

func (s *Streams) acquire(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= s.opts.Total || s.open[key] >= s.opts.PerSession {
		return false
	}
	s.total++
	s.open[key]++
	return true
}

func (s *Streams) release(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if s.open[key]--; s.open[key] == 0 {
		delete(s.open, key)
	}
}

func (s *Streams) change() frame {
	epoch, seq := s.opts.Changes.Last()
	return event("change", struct {
		Epoch string `json:"epoch"`
		Seq   string `json:"seq"`
	}{epoch, strconv.FormatInt(seq, 10)})
}

func (s *Streams) upstream() frame {
	return event("upstream", struct {
		Available bool `json:"available"`
	}{s.opts.Upstream.Available()})
}

// refuse answers a session that ended between the guard and the start of the stream, with the codes
// the account routes use.
func refuse(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, operator.ErrUnauthenticated) {
		httpapi.WriteProblem(w, r, http.StatusUnauthorized, httpapi.Problem{Code: "Unauthenticated", Message: "sign in to continue"})
		return
	}
	httpapi.WriteProblem(w, r, http.StatusServiceUnavailable, httpapi.Problem{Code: "AuthUnavailable", Message: "authentication is temporarily unavailable"})
}

var moscow = time.FixedZone("MSK", 3*60*60)

func timestamp(t time.Time) string { return t.In(moscow).Format(time.RFC3339) }

func tick(now time.Time) frame {
	return event("tick", struct {
		ServerTime string `json:"serverTime"`
	}{timestamp(now)})
}

func sessionFrame(idle, absolute time.Time) frame {
	return event("session", struct {
		IdleExpiresAt     string `json:"idleExpiresAt"`
		AbsoluteExpiresAt string `json:"absoluteExpiresAt"`
	}{timestamp(idle), timestamp(absolute)})
}

func ended(reason operator.EndReason) frame {
	return event("session-ended", struct {
		Reason operator.EndReason `json:"reason"`
	}{reason})
}

// frame is one event with data encoded as JSON on write, or raw text such as a comment.
type frame struct {
	name string
	id   string
	data any
	raw  string
}

func event(name string, data any) frame { return frame{name: name, data: data} }

func raw(text string) frame { return frame{raw: text} }

func (f frame) encode() (string, error) {
	if f.name == "" {
		return f.raw, nil
	}
	data, err := json.Marshal(f.data)
	if err != nil {
		return "", err
	}
	prefix := ""
	if f.id != "" {
		prefix = "id: " + f.id + "\n"
	}
	return prefix + "event: " + f.name + "\ndata: " + string(data) + "\n\n", nil
}

func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func until(clock Clock, t time.Time) time.Duration { return t.Sub(clock.Now()) }

func untilNextMinute(now time.Time) time.Duration {
	return now.Truncate(time.Minute).Add(time.Minute).Sub(now)
}

// sender writes frames to one client; a client that cannot take a write within timeout is dropped.
type sender struct {
	w          http.ResponseWriter
	controller *http.ResponseController
	timeout    time.Duration
}

// send writes frames and flushes them; false means the stream must end.
func (s *sender) send(frames ...frame) bool {
	if err := s.controller.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return false
	}
	for _, f := range frames {
		text, err := f.encode()
		if err != nil {
			return false
		}
		if _, err := io.WriteString(s.w, text); err != nil {
			return false
		}
	}
	return s.controller.Flush() == nil
}

// release clears the write deadline.
func (s *sender) release() error {
	if err := s.controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}
