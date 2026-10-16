// Source: umir-factory reference/durable@26166c8ba197

// Package redis is the reference Redis adapter of the durable stack: the
// admission limiter, the continuity marker, Gateway leases and counted slots.
//
// Services copy the package to internal/adapters/redis without changing its
// logic. The package imports only the standard library and go-redis.
//
// # Keys
//
// Every key has the form <root>umir:<owner>:<kind>:..., where owner is chosen
// by the caller from a short list (gw for the Gateway, wh for the Warehouse;
// Config.AllowAnyOwner lifts the list in tests; limiter is never accepted),
// kind and the rest come from the operation, and root is the optional
// Config.KeyRoot (empty in production, the itest prefix in tests). The
// continuity marker lives under umir:limiter:, shared by services.
//
//	umir:<owner>:adm:<dimension key>          fixed-window counter of one dimension
//	umir:<owner>:admid:<policy>:<sha256(ID)>  admission record, holds sha256(fingerprint)
//	umir:<owner>:<name>:lease, :fence         Lease
//	umir:<owner>:<slot key>, <slot key>:u     Slots (ZSET of holders, HASH of units)
//	umir:limiter:generation, strict_since     Continuity
//
// A slot key is <kind>:<rest> (sse:s:<id>, capslots:<generation>:<restaurant>).
// The kinds adm, admid, lease, fence and limiter and the suffixes :u, :lease and
// :fence are reserved for the other operations and are refused in slot keys.
//
// Scripts touch several keys at once, so the package targets a single Redis
// node (one cell), not Redis Cluster.
//
// # Failure model
//
// Admission never answers "allowed" without a verified reply from Redis. Any
// Redis error, timeout, canceled context or unparsable reply from
// Limiter.Admit or Continuity.Check is returned as ErrAdmissionUnavailable.
// The client does not retry commands on its own: a lost reply is resolved by
// the caller repeating the request with the same ID, which is charged once.
//
// # Strict mode
//
// Limiter.Admit knows nothing about the strict mode. The caller (the Gateway)
// must call Continuity.Check first and, when the state is Strict, substitute its
// strict limits (never zero) in the Request before it calls Admit. An Admit
// without that check applies the normal limits during a window in which the
// counters are not proven to be continuous.
//
// Continuity uses the clock of the replica that calls Check (ContinuityConfig.Clock,
// time.Now by default) and stores that moment in umir:limiter:strict_since, so
// the clocks of all Gateway replicas must be synchronised (R12, for example
// with chrony or the platform's time service). A replica whose clock is ahead
// ends the strict window early for everyone, and one that is behind prolongs it,
// by the size of the offset; the window is capped at MaxStrictWindow in any
// case. strict_since has no TTL of its own: the next Check after the window
// removes it, and a Check that finds the marker present removes it too.
//
// If the marker holds a value other than the configured generation
// (ReasonMarkerMismatch), the state is Strict for as long as the values differ
// and nothing is written: a conflicting generation is a configuration error (two
// Gateway generations share one Redis), not a loss of counters, and no replica
// may overwrite another's marker. The mode ends when the configured value
// matches the marker, that is, after the configuration or the marker is fixed.
//
// # Redis ACL
//
// The Gateway and the Warehouse use a dedicated ACL user each. The package
// sends only these commands:
//
//   - connection: HELLO (go-redis negotiates RESP3 and authenticates), PING,
//     CLIENT (SETNAME from Config.ClientName and SETINFO from the library),
//     SELECT when the URL names a database other than 0;
//   - scripts: EVALSHA and SCRIPT LOAD (first call and after a script flush);
//   - inside the scripts, on the keys below: GET, SET, DEL, INCR, EXISTS, PTTL,
//     PEXPIRE, TIME, ZADD, ZREM, ZRANGEBYSCORE, ZSCORE, ZCARD, HSET, HGET, HVALS
//     and HDEL.
//
// Key access: each service gets umir:<owner>:* for its own owner. The Gateway
// also needs exactly two more keys, umir:limiter:generation and
// umir:limiter:strict_since (GET, SET with NX, DEL; C61), because Continuity
// keeps the marker there; the Warehouse does not use them. The commands
// run by the scripts are checked against the user's ACL like direct ones, so
// the user needs them and the key patterns together. Use the categories
// -@all +@connection... only as a base; do not grant EVAL, KEYS, FLUSHALL, CONFIG
// or other administrative commands.
package redislimiter
