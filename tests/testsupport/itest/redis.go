// Source: umir-factory reference/durable/itest@26166c8ba197 (adapted: repository name gateway, no PostgreSQL and no cache Redis helpers)

package itest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

const (
	redisPrefixRoot = "t:" + repo + ":"
	scanCount       = 200
)

// RedisPrefix returns a fresh key prefix t:gateway:<rand>: on the limiter
// Redis. When the test ends, exactly the keys under that prefix are removed
// (SCAN MATCH prefix* and UNLINK); FLUSHALL and FLUSHDB are never used.
func RedisPrefix(tb testing.TB) string {
	tb.Helper()
	redisURL := RedisLimiterURL(tb)
	prefix := redisPrefixRoot + randHex(tb) + ":"
	tb.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := removePrefix(ctx, redisURL, prefix); err != nil {
			tb.Errorf("remove test keys under %s: %v", prefix, err)
		}
	})
	return prefix
}

// removePrefix deletes all keys that start with prefix and nothing else.
func removePrefix(ctx context.Context, redisURL, prefix string) (err error) {
	if !strings.HasPrefix(prefix, redisPrefixRoot) || !strings.HasSuffix(prefix, ":") || len(prefix) <= len(redisPrefixRoot)+1 {
		return fmt.Errorf("refusing to remove keys under %q: not a test prefix", prefix)
	}
	opts, perr := redis.ParseURL(redisURL)
	if perr != nil {
		return errors.New("the Redis URL is not valid")
	}
	client := redis.NewClient(opts)
	defer func() { err = errors.Join(err, client.Close()) }()
	var cursor uint64
	for {
		keys, next, serr := client.Scan(ctx, cursor, prefix+"*", scanCount).Result()
		if serr != nil {
			return fmt.Errorf("scan: %w", serr)
		}
		if len(keys) > 0 {
			if uerr := client.Unlink(ctx, keys...).Err(); uerr != nil {
				return fmt.Errorf("unlink: %w", uerr)
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}
