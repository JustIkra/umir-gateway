// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"sync"

	goredis "github.com/redis/go-redis/v9"
)

// script is a Lua script addressed by its SHA-1 digest. The text is loaded into
// the server lazily: the first EVALSHA that answers NOSCRIPT triggers
// SCRIPT LOAD and one retry.
type script struct {
	src string
	mu  sync.RWMutex
	sha string
}

func newScript(src string) *script {
	sum := sha1.Sum([]byte(src)) // the digest Redis uses for EVALSHA
	return &script{src: src, sha: hex.EncodeToString(sum[:])}
}

func (s *script) digest() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sha
}

func (s *script) setDigest(sha string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sha = sha
}

// run executes the script. On NOSCRIPT it loads the text once and repeats; the
// repeat is safe because a NOSCRIPT error means nothing was executed.
func (c *Client) run(ctx context.Context, s *script, keys []string, args ...any) (any, error) {
	res, err := c.rdb.EvalSha(ctx, s.digest(), keys, args...).Result()
	if err == nil || !goredis.HasErrorPrefix(err, "NOSCRIPT") {
		return res, err
	}
	sha, err := c.rdb.ScriptLoad(ctx, s.src).Result()
	if err != nil {
		return nil, err
	}
	s.setDigest(sha)
	return c.rdb.EvalSha(ctx, sha, keys, args...).Result()
}

// ints converts a Lua array reply of integers.
func ints(res any, n int) ([]int64, bool) {
	arr, ok := res.([]any)
	if !ok || len(arr) < n {
		return nil, false
	}
	out := make([]int64, len(arr))
	for i, v := range arr {
		x, ok := v.(int64)
		if !ok {
			return nil, false
		}
		out[i] = x
	}
	return out, true
}
