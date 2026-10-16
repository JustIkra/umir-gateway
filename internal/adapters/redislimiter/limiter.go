// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Reasons of a Decision.
const (
	// ReasonLimitExceeded: a dimension is exhausted; nothing was charged.
	ReasonLimitExceeded = "limit_exceeded"
	// ReasonReplay: the same ID and fingerprint were admitted before in the
	// window; the repeat is allowed and is not charged again.
	ReasonReplay = "replay"
)

// Dimension is one budget of a policy: at most Limit admissions per fixed
// window of length Window for the subject encoded in Key (dimension name and
// HMAC of the subject; no raw IP, session or preauth).
type Dimension struct {
	Key    string
	Limit  int
	Window time.Duration
}

// Request is one admission attempt.
//
// ID identifies the attempt (for example ClientCommandID, 1..256 code points)
// and lives no longer than the longest window of the request. Policy names the
// rule and separates ID spaces.
//
// Fingerprint identifies the content of the request: it must cover everything
// that makes two requests with one ID the same request, the body or its digest
// together with the subjects and the dimensions (their keys, limits and
// windows). Otherwise a retry that differs in a subject or a dimension would be
// taken for a replay and escape the charge it owes. Only its sha256 is stored.
//
// The counter of a dimension gets its TTL, the window, from the request that
// creates it; later requests with another window do not change it. Therefore the
// window belongs to the identity of the rule: put it in the dimension key (for
// example client:5m:<HMAC>) and use a new key when the window changes; the
// policy name does not take part in the counter key. The ID record behaves the
// same way: its TTL is the longest window of the request that created it.
type Request struct {
	ID          string
	Fingerprint string
	Policy      string
	Dimensions  []Dimension
}

// Decision is the verdict of Admit when Redis answered.
type Decision struct {
	// Allowed is true for a new admission and for a replay.
	Allowed bool
	// RetryAfter is, when denied, the time to the end of the window of the
	// exhausted dimension that frees last; callers round it up to whole
	// seconds, at least 1.
	RetryAfter time.Duration
	// Reason is ReasonReplay for a replay, ReasonLimitExceeded for a denial,
	// and empty for a new admission.
	Reason string
	// Dimension is the index in Request.Dimensions of the exhausted dimension
	// that sets RetryAfter. It is meaningful only when denied.
	Dimension int
}

// Limiter is the admission port. Create it with Client.Limiter.
type Limiter struct {
	c      *Client
	prefix string
	script *script
}

// Limiter returns the admission limiter whose keys live under umir:<owner>:.
func (c *Client) Limiter(owner string) (*Limiter, error) {
	if err := c.checkOwner(owner); err != nil {
		return nil, err
	}
	return &Limiter{c: c, prefix: c.ownerKey(owner), script: newScript(limiterScript)}, nil
}

func (r Request) validate() error {
	if r.ID == "" || codePoints(r.ID) > MaxIDLength || !validUTF8(r.ID) {
		return invalidRequest("ID must be 1..%d valid UTF-8 code points", MaxIDLength)
	}
	if r.Fingerprint == "" || len(r.Fingerprint) > MaxFingerprintLength {
		return invalidRequest("fingerprint must be 1..%d bytes", MaxFingerprintLength)
	}
	if !validName(r.Policy, MaxPolicyLength) {
		return invalidRequest("policy must be 1..%d characters of letters, digits, '.', '_' and '-'", MaxPolicyLength)
	}
	if len(r.Dimensions) == 0 || len(r.Dimensions) > MaxDimensions {
		return invalidRequest("need 1..%d dimensions", MaxDimensions)
	}
	seen := make(map[string]struct{}, len(r.Dimensions))
	for i, d := range r.Dimensions {
		if !validKey(d.Key) {
			return invalidRequest("dimension %d: key must be 1..%d printable ASCII characters", i, MaxKeyLength)
		}
		if _, dup := seen[d.Key]; dup {
			return invalidRequest("dimension %d: duplicate key", i)
		}
		seen[d.Key] = struct{}{}
		if d.Limit < 1 {
			return invalidRequest("dimension %d: limit must be at least 1", i)
		}
		if d.Window.Milliseconds() < 1 || d.Window > MaxWindow {
			return invalidRequest("dimension %d: window must be 1ms..%v", i, MaxWindow)
		}
	}
	return nil
}

// Admit checks all dimensions and, only if every one has room, charges them
// atomically in one script. A refused request leaves no trace.
//
// A repeat with the same ID and fingerprint inside the window is allowed
// without charging (Reason ReasonReplay). The same ID with another fingerprint
// returns ErrAdmissionConflict. Any Redis failure, timeout or unparsable reply
// returns ErrAdmissionUnavailable and a Decision that is not Allowed.
func (l *Limiter) Admit(ctx context.Context, r Request) (Decision, error) {
	if err := r.validate(); err != nil {
		return Decision{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, l.c.timeout)
	defer cancel()

	keys := make([]string, 0, 1+len(r.Dimensions))
	keys = append(keys, l.prefix+"admid:"+idRecordName(r.Policy, r.ID))
	args := make([]any, 0, 2+2*len(r.Dimensions))
	var idTTL time.Duration
	args = append(args, digest(r.Fingerprint), 0)
	for _, d := range r.Dimensions {
		keys = append(keys, l.prefix+"adm:"+d.Key)
		args = append(args, d.Limit, d.Window.Milliseconds())
		idTTL = max(idTTL, d.Window)
	}
	args[1] = idTTL.Milliseconds()

	res, err := l.c.run(ctx, l.script, keys, args...)
	if err != nil {
		return Decision{}, unavailable(err)
	}
	out, ok := ints(res, 3)
	if !ok {
		return Decision{}, unparsable("admission")
	}
	switch out[0] {
	case admitNew:
		return Decision{Allowed: true}, nil
	case admitReplay:
		return Decision{Allowed: true, Reason: ReasonReplay}, nil
	case admitDenied:
		if out[2] < 0 || int(out[2]) >= len(r.Dimensions) {
			return Decision{}, unparsable("admission")
		}
		retry := max(time.Duration(out[1])*time.Millisecond, time.Millisecond)
		return Decision{RetryAfter: retry, Reason: ReasonLimitExceeded, Dimension: int(out[2])}, nil
	case admitConflict:
		return Decision{}, ErrAdmissionConflict
	default:
		return Decision{}, unparsable("admission")
	}
}

// Result codes of the admission script.
const (
	admitDenied   = 0
	admitNew      = 1
	admitReplay   = 2
	admitConflict = 3
)

// idRecordName is the part of the admission record key after "admid:": the
// policy and the digest of the ID, so the key length does not depend on the ID.
func idRecordName(policy, id string) string { return policy + ":" + digest(id) }

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// limiterScript decides and charges in one step.
//
//	KEYS[1]      admission record: sha256(fingerprint), TTL = longest window, set once
//	KEYS[2..n+1] counters of the dimensions
//	ARGV[1]      sha256(fingerprint)
//	ARGV[2]      record TTL in ms
//	ARGV[3+2i], ARGV[4+2i]  limit and window in ms of dimension i (from 0)
//
// Reply: {code, retry_ms, dimension index}.
const limiterScript = `
local rec = redis.call('GET', KEYS[1])
if rec then
  if rec == ARGV[1] then return {2, 0, 0} end
  return {3, 0, 0}
end
local n = #KEYS - 1
local worst, worst_idx = 0, -1
for i = 1, n do
  local limit = tonumber(ARGV[1 + 2 * i])
  local window = tonumber(ARGV[2 + 2 * i])
  local cur = tonumber(redis.call('GET', KEYS[1 + i]) or '0')
  if cur >= limit then
    local ttl = redis.call('PTTL', KEYS[1 + i])
    if ttl < 0 then ttl = window end
    if worst_idx < 0 or ttl > worst then worst, worst_idx = ttl, i - 1 end
  end
end
if worst_idx >= 0 then return {0, worst, worst_idx} end
for i = 1, n do
  local window = tonumber(ARGV[2 + 2 * i])
  local k = KEYS[1 + i]
  local c = redis.call('INCR', k)
  if c == 1 or redis.call('PTTL', k) < 0 then redis.call('PEXPIRE', k, window) end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return {1, 0, 0}
`
