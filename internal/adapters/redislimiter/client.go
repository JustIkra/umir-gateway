// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	goredis "github.com/redis/go-redis/v9"
)

const (
	// DefaultTimeout bounds one operation: dial, every command and the whole
	// call of Admit (GATEWAY_REDIS_TIMEOUT default).
	DefaultTimeout = 200 * time.Millisecond

	// Bounds of request values. Services validate their own inputs against the
	// same numbers (C43: IDs are at most 256 code points).
	MaxIDLength          = 256
	MaxFingerprintLength = 1024
	MaxPolicyLength      = 64
	MaxKeyLength         = 256
	MaxDimensions        = 16
	MaxWindow            = 24 * time.Hour
)

// Owners that may use Limiter, Lease and Slots (Config.AllowAnyOwner lifts the
// list for tests).
const (
	// OwnerGateway is the key space of the Gateway.
	OwnerGateway = "gw"
	// OwnerWarehouse is the key space of the Warehouse capture slots.
	OwnerWarehouse = "wh"

	// ownerLimiter names the continuity marker namespace, umir:limiter:.
	ownerLimiter = "limiter"
)

// Config opens a Client.
type Config struct {
	// URL is redis:// or rediss:// with the credentials. It never appears in errors.
	URL string
	// ClientName is sent with CLIENT SETNAME (optional).
	ClientName string
	// Timeout bounds dial, each command and each operation; zero means DefaultTimeout.
	Timeout time.Duration
	// PoolSize is the connection pool size; zero keeps the go-redis default.
	PoolSize int
	// KeyRoot is prepended to every key: empty in production, the itest prefix
	// (t:factory:<rand>:) in tests. It must be empty or end with ':'.
	KeyRoot string
	// AllowAnyOwner lifts the owner whitelist (OwnerGateway, OwnerWarehouse) for
	// tests that need their own owners. Production leaves it false, so that a
	// typo or a stray owner cannot write into another component's key space.
	// The owner "limiter" is never accepted: umir:limiter: is the continuity
	// marker namespace.
	AllowAnyOwner bool
}

// Client is a connection pool to one Redis node plus the key root. Limiter,
// Continuity, Lease and Slots are built from it. It is safe for concurrent use.
type Client struct {
	rdb      *goredis.Client
	timeout  time.Duration
	root     string
	anyOwner bool
}

// Open connects to Redis and checks the connection with PING.
func Open(ctx context.Context, cfg Config) (*Client, error) {
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.rdb.Ping(pctx).Err(); err != nil {
		return nil, errors.Join(fmt.Errorf("redis: connect: %w", err), c.Close())
	}
	return c, nil
}

// newClient builds the pool without connecting.
func newClient(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, invalidConfig("URL is empty")
	}
	if cfg.Timeout < 0 {
		return nil, invalidConfig("Timeout is negative")
	}
	if cfg.PoolSize < 0 {
		return nil, invalidConfig("PoolSize is negative")
	}
	if !validRoot(cfg.KeyRoot) {
		return nil, invalidConfig("KeyRoot must be empty or printable ASCII ending with ':'")
	}
	opts, err := parseRedisURL(cfg.URL)
	if err != nil {
		return nil, invalidConfig("URL is not a valid redis:// or rediss:// URL")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	opts.DialTimeout = timeout
	opts.ReadTimeout = timeout
	opts.WriteTimeout = timeout
	opts.PoolTimeout = timeout
	opts.MaxRetries = -1 // a retried write could hide a lost reply; callers repeat with the same ID
	if cfg.PoolSize > 0 {
		opts.PoolSize = cfg.PoolSize
	}
	if cfg.ClientName != "" {
		opts.ClientName = cfg.ClientName
	}
	return &Client{rdb: goredis.NewClient(opts), timeout: timeout, root: cfg.KeyRoot, anyOwner: cfg.AllowAnyOwner}, nil
}

// Close closes the pool.
func (c *Client) Close() error { return c.rdb.Close() }

// Ping checks the connection within the client timeout.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis: ping: %w", err)
	}
	return nil
}

// parseRedisURL accepts redis:// and rediss:// only. go-redis also understands
// unix://, which this package does not use. Errors carry no part of the URL.
func parseRedisURL(raw string) (*goredis.Options, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "redis" && u.Scheme != "rediss") {
		return nil, errors.New("not a redis URL")
	}
	opts, err := goredis.ParseURL(raw)
	if err != nil { // the error text of the URL parser may quote the URL
		return nil, errors.New("not a redis URL")
	}
	return opts, nil
}

// ownerKey returns the common prefix of the keys of one owner.
func (c *Client) ownerKey(owner string) string { return c.root + "umir:" + owner + ":" }

func validRoot(root string) bool {
	return root == "" || (strings.HasSuffix(root, ":") && printableASCII(root))
}

// checkOwner validates an owner passed to Limiter, Lease or Slots: the format,
// then the whitelist unless Config.AllowAnyOwner is set. "limiter" is refused in
// every case.
func (c *Client) checkOwner(owner string) error {
	if !validOwner(owner) {
		return invalidConfig("owner must be 1..32 characters of a-z0-9 starting with a letter")
	}
	if owner == ownerLimiter {
		return invalidConfig("owner %q is reserved for the continuity marker", ownerLimiter)
	}
	if !c.anyOwner && owner != OwnerGateway && owner != OwnerWarehouse {
		return invalidConfig("owner must be %q or %q", OwnerGateway, OwnerWarehouse)
	}
	return nil
}

func validOwner(owner string) bool {
	if owner == "" || len(owner) > 32 || owner[0] < 'a' || owner[0] > 'z' {
		return false
	}
	for i := range len(owner) {
		ch := owner[i]
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}

// printableASCII reports whether s has only bytes 0x21..0x7e.
func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// validKey checks a key part: 1..MaxKeyLength printable ASCII bytes.
func validKey(s string) bool { return s != "" && len(s) <= MaxKeyLength && printableASCII(s) }

// validName checks a policy or lease name: letters, digits, '.', '_' and '-'.
func validName(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '.', ch == '_', ch == '-':
		default:
			return false
		}
	}
	return true
}

func codePoints(s string) int { return utf8.RuneCountInString(s) }

func validUTF8(s string) bool { return utf8.ValidString(s) }
