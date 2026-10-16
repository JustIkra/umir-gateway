// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// unitsSuffix is appended to a slot key for the HASH with the units held per
// holder. Slot keys must not end with it.
const unitsSuffix = ":u"

// Slot keys have the form <kind>:<rest>. The kind names the use (sse, capslots,
// capbytes) and keeps the key space of slots apart from the keys of the other
// operations under umir:<owner>:. The kinds below belong to those operations, and
// the suffixes below to their derived keys, so a slot key may not collide with:
//
//	adm:<dimension>, admid:<policy>:<digest>   Limiter
//	<name>:lease, <name>:fence                 Lease
//	<slot key>:u                               the units HASH of a slot
var (
	reservedSlotKinds    = []string{"adm", "admid", "lease", "fence", ownerLimiter}
	reservedSlotSuffixes = []string{unitsSuffix, ":lease", ":fence"}
)

// Slots are counted leases: a holder takes one slot in each of several keys at
// once (all or none), the slots expire after a TTL unless renewed, and the
// number of holders and the sum of their units per key are capped. They back
// the SSE quotas (session, organisation, cell) and the Warehouse capture slots
// (count, bytes, rows). Create it with Client.Slots.
//
// Keys: umir:<owner>:<key> is a ZSET holder -> expiry in ms of the Redis clock;
// with MaxUnits > 0 also umir:<owner>:<key>:u, a HASH holder -> units. Both
// get a TTL of at least the longest TTL of their holders, so abandoned keys
// vanish on their own.
type Slots struct {
	c       *Client
	prefix  string
	acquire *script
	renew   *script
	release *script
}

// SlotDimension is one capped key of an Acquire.
type SlotDimension struct {
	// Key is the key below umir:<owner>:, in the form <kind>:<rest>, for example
	// sse:s:<HMAC(session)> or capslots:<generation>:<restaurantID>. The kind is
	// lower case letters, digits, '_' or '-' starting with a letter; it must not
	// be one of adm, admid, lease, fence or limiter, and the key must not end
	// with :u, :lease or :fence (those belong to other operations).
	Key string
	// MaxCount caps the number of holders; zero means no cap on the count, and
	// then MaxUnits must be set so that the number of holders is still bounded.
	MaxCount int64
	// MaxUnits caps the sum of units of all holders; zero means no cap.
	MaxUnits int64
	// Units is what this holder adds to the sum (bytes, rows). With MaxUnits > 0
	// it must be at least 1 (a holder that adds nothing would not be bounded by
	// the sum) and must not exceed MaxUnits; without MaxUnits it must be zero.
	Units int64
}

// SlotRequest asks for a slot in every dimension.
type SlotRequest struct {
	// Holder identifies the holder (a stream or capture ID); a repeat Acquire
	// by the same holder refreshes its slot and units, it is not counted twice.
	Holder     string
	TTL        time.Duration
	Dimensions []SlotDimension
}

// SlotGrant is the result of Slots.Acquire.
type SlotGrant struct {
	Granted bool
	// Denied is the index of the first dimension without room when not granted.
	Denied int
}

// Slots returns the slot operations under umir:<owner>:.
func (c *Client) Slots(owner string) (*Slots, error) {
	if err := c.checkOwner(owner); err != nil {
		return nil, err
	}
	return &Slots{
		c: c, prefix: c.ownerKey(owner),
		acquire: newScript(slotsAcquireScript), renew: newScript(slotsRenewScript), release: newScript(slotsReleaseScript),
	}, nil
}

func validateHolder(holder string) error {
	if !validKey(holder) {
		return invalidRequest("holder must be 1..%d printable ASCII characters", MaxKeyLength)
	}
	return nil
}

func validateSlotKey(key string) error {
	if !validKey(key) {
		return invalidRequest("slot key must be 1..%d printable ASCII characters", MaxKeyLength)
	}
	kind, rest, ok := strings.Cut(key, ":")
	if !ok || rest == "" || !validSlotKind(kind) {
		return invalidRequest("slot key must have the form <kind>:<rest>, for example sse:s:<id>")
	}
	if slices.Contains(reservedSlotKinds, kind) {
		return invalidRequest("slot key kind %q is reserved", kind)
	}
	for _, suffix := range reservedSlotSuffixes {
		if strings.HasSuffix(key, suffix) {
			return invalidRequest("slot key must not end with %q", suffix)
		}
	}
	return nil
}

// validSlotKind checks the part of a slot key before the first ':'.
func validSlotKind(kind string) bool {
	if kind == "" || len(kind) > 32 || kind[0] < 'a' || kind[0] > 'z' {
		return false
	}
	for i := range len(kind) {
		ch := kind[i]
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

func (r SlotRequest) validate() error {
	if err := validateHolder(r.Holder); err != nil {
		return err
	}
	if r.TTL.Milliseconds() < 1 {
		return invalidRequest("TTL must be at least 1ms")
	}
	if len(r.Dimensions) == 0 || len(r.Dimensions) > MaxDimensions {
		return invalidRequest("need 1..%d dimensions", MaxDimensions)
	}
	seen := make(map[string]struct{}, len(r.Dimensions))
	for i, d := range r.Dimensions {
		if err := validateSlotKey(d.Key); err != nil {
			return fmt.Errorf("dimension %d: %w", i, err)
		}
		if _, dup := seen[d.Key]; dup {
			return invalidRequest("dimension %d: duplicate key", i)
		}
		seen[d.Key] = struct{}{}
		switch {
		case d.MaxCount < 0 || d.MaxUnits < 0 || d.Units < 0:
			return invalidRequest("dimension %d: negative limit or units", i)
		case d.MaxCount == 0 && d.MaxUnits == 0:
			return invalidRequest("dimension %d: set MaxCount or MaxUnits, or the number of holders is unbounded", i)
		case d.MaxUnits > 0 && d.Units < 1:
			return invalidRequest("dimension %d: Units must be at least 1 when MaxUnits is set", i)
		case d.Units > 0 && d.MaxUnits == 0:
			return invalidRequest("dimension %d: Units need MaxUnits", i)
		case d.Units > d.MaxUnits && d.MaxUnits > 0:
			return invalidRequest("dimension %d: Units exceed MaxUnits", i)
		}
	}
	return nil
}

// keySet returns the ZSET keys followed by the HASH keys of the slot keys.
func (s *Slots) keySet(keys []string) []string {
	out := make([]string, 0, 2*len(keys))
	for _, k := range keys {
		out = append(out, s.prefix+k)
	}
	for _, k := range keys {
		out = append(out, s.prefix+k+unitsSuffix)
	}
	return out
}

// Acquire gives the holder a slot in every dimension, or in none: the script
// purges expired holders, checks all dimensions, and only then writes. It never
// hands out more than MaxCount holders or MaxUnits units per key, however many
// callers race.
func (s *Slots) Acquire(ctx context.Context, r SlotRequest) (SlotGrant, error) {
	if err := r.validate(); err != nil {
		return SlotGrant{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, s.c.timeout)
	defer cancel()
	keys := make([]string, len(r.Dimensions))
	args := make([]any, 0, 2+3*len(r.Dimensions))
	args = append(args, r.Holder, r.TTL.Milliseconds())
	for i, d := range r.Dimensions {
		keys[i] = d.Key
		args = append(args, d.MaxCount, d.MaxUnits, d.Units)
	}
	res, err := s.c.run(ctx, s.acquire, s.keySet(keys), args...)
	if err != nil {
		return SlotGrant{}, fmt.Errorf("redis: slots acquire: %w", err)
	}
	out, ok := ints(res, 2)
	if !ok {
		return SlotGrant{}, errors.New("redis: slots acquire: unexpected reply")
	}
	if out[0] == 1 {
		return SlotGrant{Granted: true}, nil
	}
	if out[1] < 0 || int(out[1]) >= len(r.Dimensions) {
		return SlotGrant{}, errors.New("redis: slots acquire: unexpected reply")
	}
	return SlotGrant{Denied: int(out[1])}, nil
}

// Renew extends the holder's slot in every key by ttl. It returns false and
// changes nothing when the holder has no live slot in any one of them (it
// expired or was released); the caller must then stop the work the slot guards.
func (s *Slots) Renew(ctx context.Context, holder string, ttl time.Duration, keys ...string) (bool, error) {
	if err := validateKeys(holder, keys); err != nil {
		return false, err
	}
	if ttl.Milliseconds() < 1 {
		return false, invalidRequest("TTL must be at least 1ms")
	}
	ctx, cancel := context.WithTimeout(ctx, s.c.timeout)
	defer cancel()
	res, err := s.c.run(ctx, s.renew, s.keySet(keys), holder, ttl.Milliseconds())
	if err != nil {
		return false, fmt.Errorf("redis: slots renew: %w", err)
	}
	out, ok := ints([]any{res}, 1)
	if !ok {
		return false, errors.New("redis: slots renew: unexpected reply")
	}
	return out[0] == 1, nil
}

// Release frees the holder's slot in every key. It is idempotent: a repeat, an
// expired slot and an unknown holder are no-ops, and a holder never frees
// another holder's slot.
func (s *Slots) Release(ctx context.Context, holder string, keys ...string) error {
	if err := validateKeys(holder, keys); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.c.timeout)
	defer cancel()
	if _, err := s.c.run(ctx, s.release, s.keySet(keys), holder); err != nil {
		return fmt.Errorf("redis: slots release: %w", err)
	}
	return nil
}

func validateKeys(holder string, keys []string) error {
	if err := validateHolder(holder); err != nil {
		return err
	}
	if len(keys) == 0 || len(keys) > MaxDimensions {
		return invalidRequest("need 1..%d keys", MaxDimensions)
	}
	for _, k := range keys {
		if err := validateSlotKey(k); err != nil {
			return err
		}
	}
	return nil
}

// slotsAcquireScript:
//
//	KEYS[1..n] ZSETs, KEYS[n+1..2n] HASHes of units
//	ARGV[1] holder, ARGV[2] TTL ms, then per dimension: max count, max units, units
//
// Reply: {1, 0} granted or {0, index} denied by dimension index.
const slotsAcquireScript = `
local n = #KEYS / 2
local holder = ARGV[1]
local ttl = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local exp = now + ttl

local function purge(z, h, with_units)
  while true do
    local gone = redis.call('ZRANGEBYSCORE', z, '-inf', now, 'LIMIT', 0, 500)
    if #gone == 0 then return end
    redis.call('ZREM', z, unpack(gone))
    if with_units then redis.call('HDEL', h, unpack(gone)) end
    if #gone < 500 then return end
  end
end

for i = 1, n do
  local z, h = KEYS[i], KEYS[n + i]
  local max_count = tonumber(ARGV[3 * i])
  local max_units = tonumber(ARGV[3 * i + 1])
  local units = tonumber(ARGV[3 * i + 2])
  purge(z, h, max_units > 0)
  local mine = redis.call('ZSCORE', z, holder)
  if max_count > 0 then
    local held = redis.call('ZCARD', z)
    if mine then held = held - 1 end
    if held + 1 > max_count then return {0, i - 1} end
  end
  if max_units > 0 then
    local sum = 0
    for _, v in ipairs(redis.call('HVALS', h)) do sum = sum + tonumber(v) end
    if mine then
      local own = redis.call('HGET', h, holder)
      if own then sum = sum - tonumber(own) end
    end
    if sum + units > max_units then return {0, i - 1} end
  end
end

for i = 1, n do
  local z, h = KEYS[i], KEYS[n + i]
  local max_units = tonumber(ARGV[3 * i + 1])
  local units = tonumber(ARGV[3 * i + 2])
  redis.call('ZADD', z, exp, holder)
  if redis.call('PTTL', z) < ttl then redis.call('PEXPIRE', z, ttl) end
  if max_units > 0 then
    redis.call('HSET', h, holder, units)
    if redis.call('PTTL', h) < ttl then redis.call('PEXPIRE', h, ttl) end
  end
end
return {1, 0}
`

// slotsRenewScript: KEYS as above, ARGV[1] holder, ARGV[2] TTL ms. Reply 1 or 0.
const slotsRenewScript = `
local n = #KEYS / 2
local holder = ARGV[1]
local ttl = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local exp = now + ttl
for i = 1, n do
  local score = redis.call('ZSCORE', KEYS[i], holder)
  if not score or tonumber(score) <= now then return 0 end
end
for i = 1, n do
  local z, h = KEYS[i], KEYS[n + i]
  redis.call('ZADD', z, 'XX', exp, holder)
  if redis.call('PTTL', z) < ttl then redis.call('PEXPIRE', z, ttl) end
  if redis.call('EXISTS', h) == 1 and redis.call('PTTL', h) < ttl then redis.call('PEXPIRE', h, ttl) end
end
return 1
`

// slotsReleaseScript: KEYS as above, ARGV[1] holder.
const slotsReleaseScript = `
local n = #KEYS / 2
for i = 1, n do
  redis.call('ZREM', KEYS[i], ARGV[1])
  redis.call('HDEL', KEYS[n + i], ARGV[1])
end
return 1
`
