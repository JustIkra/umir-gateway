// Source: umir-factory reference/durable@26166c8ba197

package redislimiter

import (
	"errors"
	"fmt"
)

var (
	// ErrAdmissionUnavailable means the admission store cannot give a verified
	// answer: a Redis error, a timeout, a canceled context or an unparsable
	// reply. The caller must refuse the request; it must never treat this as
	// "allowed". The cause is wrapped.
	ErrAdmissionUnavailable = errors.New("redis: admission store unavailable")
	// ErrAdmissionConflict means an admission ID was reused with a different
	// fingerprint inside its window.
	ErrAdmissionConflict = errors.New("redis: admission ID reused with a different fingerprint")
	// ErrInvalidRequest wraps every argument validation failure of an
	// operation. It is a caller bug, not an outage.
	ErrInvalidRequest = errors.New("redis: invalid request")
	// ErrInvalidConfig wraps every configuration validation failure. Messages
	// never contain the Redis URL.
	ErrInvalidConfig = errors.New("redis: invalid config")
)

func unavailable(err error) error {
	return fmt.Errorf("%w: %w", ErrAdmissionUnavailable, err)
}

func unparsable(op string) error {
	return fmt.Errorf("%w: unexpected %s reply", ErrAdmissionUnavailable, op)
}

func invalidRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, fmt.Sprintf(format, args...))
}

func invalidConfig(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
}

// ignoreErr documents a deliberately ignored error from a cleanup path.
func ignoreErr(error) {}
