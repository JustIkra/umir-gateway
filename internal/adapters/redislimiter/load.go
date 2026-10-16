// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"fmt"
	"strings"
)

// Kind selects one of the two Redis instances of the stack.
type Kind int

const (
	// KindLimiter is redis-limiter: admission, leases, the continuity marker.
	KindLimiter Kind = iota + 1
	// KindCache is redis-cache: Warehouse page captures.
	KindCache
)

func (k Kind) name() (string, bool) {
	switch k {
	case KindLimiter:
		return "LIMITER", true
	case KindCache:
		return "CACHE", true
	default:
		return "", false
	}
}

// LoadURL reads the Redis URL of one instance from the environment:
// <prefix>_REDIS_LIMITER_URL or <prefix>_REDIS_CACHE_URL, or the same name with
// the _FILE suffix naming a file with the URL (surrounding whitespace is
// trimmed; the file must be a regular private file, not a symbolic link, as in postgres.LoadDSN). Exactly one of the two must be set; both or neither is an error.
// getenv is os.Getenv in production; an empty value counts as not set.
//
// The URL is validated: only the schemes redis and rediss are accepted (not
// unix, which go-redis would also parse). Errors name variables only and
// never contain the URL or the path.
func LoadURL(getenv func(string) string, prefix string, kind Kind) (string, error) {
	if getenv == nil || prefix == "" {
		return "", invalidConfig("LoadURL needs getenv and a variable prefix")
	}
	kindName, ok := kind.name()
	if !ok {
		return "", invalidConfig("unknown Redis kind")
	}
	name := prefix + "_REDIS_" + kindName + "_URL"
	fileName := name + "_FILE"
	direct, file := getenv(name), getenv(fileName)
	var value string
	switch {
	case direct != "" && file != "":
		return "", invalidConfig("%s and %s are both set; set exactly one", name, fileName)
	case direct == "" && file == "":
		return "", invalidConfig("neither %s nor %s is set", name, fileName)
	case direct != "":
		value = strings.TrimSpace(direct)
	default:
		raw, err := readSecretFile(file, fileName)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		value = strings.TrimSpace(raw)
	}
	if value == "" {
		return "", invalidConfig("%s is empty", name)
	}
	if _, err := parseRedisURL(value); err != nil {
		return "", invalidConfig("%s is not a valid redis:// or rediss:// URL", name)
	}
	return value, nil
}
