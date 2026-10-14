package protocol

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/JustIkra/umir-gateway/internal/live"
)

var instantPattern = regexp.MustCompile(`^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var generationPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var projectPattern = regexp.MustCompile(`^umir-backend-[0-9a-f]{24}$`)

type ClockState struct {
	Owner             string   `json:"owner"`
	InstanceID        string   `json:"instanceID"`
	Source            string   `json:"source"`
	FixtureID         string   `json:"fixtureID"`
	Generation        string   `json:"generation"`
	Instant           string   `json:"instant"`
	InjectedConsumers []string `json:"injectedConsumers"`
	Healthy           bool     `json:"healthy"`
}
type Clock struct {
	mu                sync.Mutex
	instance, fixture string
	instant           time.Time
	generation        uint64
	timers            map[*clockTimer]time.Time
	healthy           bool
}

func parseInstant(s string) (time.Time, error) {
	instant, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || !instantPattern.MatchString(s) || instant.Year() < 2000 || instant.Year() > 2099 {
		return time.Time{}, errors.New("invalid owner instant")
	}
	return instant, nil
}
func NewClock(fixture, instance, instant, generation string) (*Clock, error) {
	when, err := parseInstant(instant)
	n, e := strconv.ParseUint(generation, 10, 64)
	if err != nil || e != nil || !generationPattern.MatchString(generation) || !uuidPattern.MatchString(fixture) || !uuidPattern.MatchString(instance) {
		return nil, errors.New("invalid clock config")
	}
	return &Clock{instance: instance, fixture: fixture, instant: when, generation: n, timers: map[*clockTimer]time.Time{}, healthy: true}, nil
}
func (c *Clock) Now() time.Time   { c.mu.Lock(); defer c.mu.Unlock(); return c.instant }
func (c *Clock) Read() ClockState { c.mu.Lock(); defer c.mu.Unlock(); return c.read() }
func (c *Clock) read() ClockState {
	return ClockState{Owner: "gateway", InstanceID: c.instance, FixtureID: c.fixture, Source: "owner-injected", Generation: strconv.FormatUint(c.generation, 10), Instant: c.instant.Format(time.RFC3339Nano), InjectedConsumers: []string{"authclient.tokens-and-keys", "operatorhttp.cookies", "httpapi.scoped", "journal.scoped", "live.authority-and-timers", "expiration.scoped"}, Healthy: c.healthy}
}
func (c *Clock) Matches(instance, generation string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.instance == instance && strconv.FormatUint(c.generation, 10) == generation && c.healthy
}
func (c *Clock) Set(instance, generation, instant string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if instance != c.instance || generation != strconv.FormatUint(c.generation, 10) || c.generation >= math.MaxInt64 {
		return "ClockConflict"
	}
	when, err := parseInstant(instant)
	if err != nil {
		return "InvalidRequest"
	}
	if when.Before(c.instant) {
		return "ClockBackward"
	}
	c.instant = when
	c.generation++
	for timer, due := range c.timers {
		if !when.Before(due) {
			timer.ch <- when
			delete(c.timers, timer)
		}
	}
	return ""
}

type clockTimer struct {
	clock *Clock
	ch    chan time.Time
}

func (c *Clock) NewTimer(d time.Duration) live.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &clockTimer{clock: c, ch: make(chan time.Time, 1)}
	if d <= 0 {
		timer.ch <- c.instant
	} else if len(c.timers) >= 8192 {
		c.healthy = false
		timer.ch <- c.instant
	} else {
		c.timers[timer] = c.instant.Add(d)
	}
	return timer
}
func (t *clockTimer) C() <-chan time.Time { return t.ch }
func (t *clockTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	_, ok := t.clock.timers[t]
	delete(t.clock.timers, t)
	return ok
}

func (c *Clock) ReadExpected(instance, generation string) (ClockState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read(), c.instance == instance && strconv.FormatUint(c.generation, 10) == generation && c.healthy
}
