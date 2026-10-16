// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"context"
	"strconv"
	"time"
)

// Mode is the admission mode derived from the continuity marker.
type Mode int

const (
	// Normal: the marker matches the configured generation.
	Normal Mode = iota
	// Strict: continuity of the counters is not proven; the caller applies its
	// strict limits (never zero) until the mode returns to Normal.
	Strict
)

func (m Mode) String() string {
	if m == Strict {
		return "strict"
	}
	return "normal"
}

// Reasons of a Strict State.
const (
	// ReasonMarkerMissing: the marker is absent; the strict window runs from
	// the shared umir:limiter:strict_since.
	ReasonMarkerMissing = "marker_missing"
	// ReasonMarkerMismatch: the marker holds another generation. The mode lasts
	// as long as the mismatch; nothing is written (a conflicting generation is a
	// configuration error, not a loss of counters).
	ReasonMarkerMismatch = "marker_mismatch"
)

// MaxStrictWindow is the longest strict window (R7, C47).
const MaxStrictWindow = time.Hour

// State is the result of Continuity.Check.
type State struct {
	Mode Mode
	// Reason is set in Strict mode.
	Reason string
	// Remaining is the time to the end of the strict window for
	// ReasonMarkerMissing; zero otherwise.
	Remaining time.Duration
}

// ContinuityConfig configures a Continuity.
type ContinuityConfig struct {
	// Window is the strict window: the longest admission window of the
	// policies, at most MaxStrictWindow. Zero means MaxStrictWindow.
	Window time.Duration
	// Clock returns the current time; nil means time.Now. The moment is stored
	// in strict_since, so all replicas must have synchronised clocks.
	Clock func() time.Time
}

// Continuity implements the strict-mode protocol of the limiter marker (R7,
// C17, C47). Only Gateway uses it; Auth has no Redis client (C51). Create it
// with Client.Continuity.
type Continuity struct {
	c      *Client
	marker string
	since  string
	window time.Duration
	clock  func() time.Time
	script *script
}

// Continuity returns the marker checker. Its keys are umir:limiter:generation
// and umir:limiter:strict_since below the client key root.
func (c *Client) Continuity(cfg ContinuityConfig) (*Continuity, error) {
	window := cfg.Window
	switch {
	case window == 0:
		window = MaxStrictWindow
	case window.Milliseconds() < 1 || window > MaxStrictWindow:
		return nil, invalidConfig("strict window must be 1ms..%v", MaxStrictWindow)
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	prefix := c.ownerKey("limiter")
	return &Continuity{
		c: c, marker: prefix + "generation", since: prefix + "strict_since",
		window: window, clock: clock, script: newScript(continuityScript),
	}, nil
}

// Check compares the marker with the configured generation, in one script:
//
//   - marker equals configured: Normal; a stale strict_since is removed.
//   - marker missing: SET strict_since <now> NX (the first replica fixes the
//     moment for all); within the window the state is Strict with the time
//     left; once the window has passed, SET generation <configured> NX and
//     DEL strict_since, and the state is Normal. There is no watchdog: the
//     next Check of any replica does it.
//   - marker holds another value: Strict (ReasonMarkerMismatch), no writes.
//
// A Redis failure, timeout or unparsable reply returns ErrAdmissionUnavailable:
// doubtful continuity is never "normal". An empty configured value is invalid.
func (k *Continuity) Check(ctx context.Context, configured string) (State, error) {
	if configured == "" || len(configured) > MaxKeyLength {
		return State{}, invalidRequest("configured generation must be 1..%d bytes", MaxKeyLength)
	}
	ctx, cancel := context.WithTimeout(ctx, k.c.timeout)
	defer cancel()
	now := k.clock().UnixMilli()
	res, err := k.c.run(ctx, k.script, []string{k.marker, k.since},
		configured, strconv.FormatInt(now, 10), k.window.Milliseconds())
	if err != nil {
		return State{}, unavailable(err)
	}
	out, ok := ints(res, 2)
	if !ok || out[1] < 0 {
		return State{}, unparsable("continuity")
	}
	switch out[0] {
	case continuityNormal:
		return State{Mode: Normal}, nil
	case continuityMissing:
		return State{Mode: Strict, Reason: ReasonMarkerMissing, Remaining: time.Duration(out[1]) * time.Millisecond}, nil
	case continuityMismatch:
		return State{Mode: Strict, Reason: ReasonMarkerMismatch}, nil
	default:
		return State{}, unparsable("continuity")
	}
}

const (
	continuityNormal   = 0
	continuityMissing  = 1
	continuityMismatch = 2
)

// continuityScript:
//
//	KEYS[1] marker, KEYS[2] strict_since
//	ARGV[1] configured generation, ARGV[2] now in ms, ARGV[3] window in ms
//
// Reply: {0|1|2, remaining ms}.
const continuityScript = `
local marker = redis.call('GET', KEYS[1])
if marker then
  if marker == ARGV[1] then
    redis.call('DEL', KEYS[2])
    return {0, 0}
  end
  return {2, 0}
end
local now = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'NX')
local since = tonumber(redis.call('GET', KEYS[2]))
if since == nil or since > now then
  redis.call('SET', KEYS[2], ARGV[2])
  since = now
end
local elapsed = now - since
if elapsed >= window then
  redis.call('SET', KEYS[1], ARGV[1], 'NX')
  redis.call('DEL', KEYS[2])
  return {0, 0}
end
return {1, window - elapsed}
`
