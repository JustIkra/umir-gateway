// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Lease is a single-owner lease with a fence token, for the Gateway background
// work that must run on one replica (the expiry scheduler, C4 keeps the
// database-backed leases of the other services in Postgres). Create it with
// Client.Lease.
//
// Keys: umir:<owner>:<name>:lease holds the owner ID with a TTL;
// umir:<owner>:<name>:fence is a counter without TTL, incremented at every new
// acquisition, so the token grows monotonically across expiries. If Redis
// loses the counter (restart without persistence) the token restarts; it is
// meant for logs and for "is the lease still mine" checks, not for storage.
//
// The holder string passed to Acquire, Renew and Release must be unique per
// process lifetime: the instance identity plus a nonce drawn at boot (C19), for
// example "gw-3:9f1c2a7e". A holder that is only the instance name lets a
// restarted process treat the lease of its dead predecessor as its own, keep it
// without a new fence and run beside a replacement. The package cannot check
// this; the caller is responsible.
//
// Lease names must not be "adm" or "admid": umir:<owner>:adm:lease would equal
// the counter of a limiter dimension whose key is "lease".
type Lease struct {
	c       *Client
	prefix  string
	acquire *script
	renew   *script
	release *script
}

// LeaseGrant is the result of Acquire.
type LeaseGrant struct {
	// Acquired is true when the caller holds the lease after the call.
	Acquired bool
	// Fence is the fence token of the holder; zero when not acquired.
	Fence int64
}

// Lease returns the lease operations under umir:<owner>:.
func (c *Client) Lease(owner string) (*Lease, error) {
	if err := c.checkOwner(owner); err != nil {
		return nil, err
	}
	return &Lease{
		c: c, prefix: c.ownerKey(owner),
		acquire: newScript(leaseAcquireScript), renew: newScript(leaseRenewScript), release: newScript(leaseReleaseScript),
	}, nil
}

func (l *Lease) keys(name string) []string {
	return []string{l.prefix + name + ":lease", l.prefix + name + ":fence"}
}

func validateLease(name, holder string, ttl time.Duration) error {
	if !validName(name, MaxPolicyLength) {
		return invalidRequest("lease name must be 1..%d characters of letters, digits, '.', '_' and '-'", MaxPolicyLength)
	}
	if name == "adm" || name == "admid" {
		return invalidRequest("lease name %q is reserved", name)
	}
	if !validKey(holder) {
		return invalidRequest("lease holder must be 1..%d printable ASCII characters", MaxKeyLength)
	}
	if ttl.Milliseconds() < 1 {
		return invalidRequest("lease TTL must be at least 1ms")
	}
	return nil
}

// Acquire takes the lease name for owner when it is free, with the given TTL.
// When owner already holds it, Acquire extends it and returns the same fence.
// A lease held by another owner gives Acquired == false and no error.
func (l *Lease) Acquire(ctx context.Context, name, owner string, ttl time.Duration) (LeaseGrant, error) {
	if err := validateLease(name, owner, ttl); err != nil {
		return LeaseGrant{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, l.c.timeout)
	defer cancel()
	res, err := l.c.run(ctx, l.acquire, l.keys(name), owner, ttl.Milliseconds())
	if err != nil {
		return LeaseGrant{}, fmt.Errorf("redis: lease acquire: %w", err)
	}
	out, ok := ints(res, 2)
	if !ok {
		return LeaseGrant{}, errors.New("redis: lease acquire: unexpected reply")
	}
	return LeaseGrant{Acquired: out[0] == 1, Fence: out[1]}, nil
}

// Renew extends the lease when owner still holds it. It returns false when the
// lease expired (even if nobody took it meanwhile) or belongs to someone else;
// the caller must then stop its work.
func (l *Lease) Renew(ctx context.Context, name, owner string, ttl time.Duration) (bool, error) {
	if err := validateLease(name, owner, ttl); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, l.c.timeout)
	defer cancel()
	res, err := l.c.run(ctx, l.renew, l.keys(name)[:1], owner, ttl.Milliseconds())
	if err != nil {
		return false, fmt.Errorf("redis: lease renew: %w", err)
	}
	out, ok := ints([]any{res}, 1)
	if !ok {
		return false, errors.New("redis: lease renew: unexpected reply")
	}
	return out[0] == 1, nil
}

// Release frees the lease when owner holds it. Releasing a foreign, expired or
// missing lease is a harmless no-op.
func (l *Lease) Release(ctx context.Context, name, owner string) error {
	if err := validateLease(name, owner, time.Millisecond); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, l.c.timeout)
	defer cancel()
	if _, err := l.c.run(ctx, l.release, l.keys(name)[:1], owner); err != nil {
		return fmt.Errorf("redis: lease release: %w", err)
	}
	return nil
}

const leaseAcquireScript = `
local cur = redis.call('GET', KEYS[1])
if cur == false then
  redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
  return {1, redis.call('INCR', KEYS[2])}
end
if cur == ARGV[1] then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  local fence = redis.call('GET', KEYS[2])
  if fence == false then fence = redis.call('INCR', KEYS[2]) end
  return {1, tonumber(fence)}
end
return {0, 0}
`

const leaseRenewScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return 1
end
return 0
`

const leaseReleaseScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`
