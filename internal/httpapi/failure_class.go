package httpapi

import (
	"context"
	"errors"
	"net"
)

// Classes of an upstream failure written to the structured log. They name the reason, never the text of
// the cause, which may carry addresses.
const (
	ClassTimeout         = "timeout"
	ClassTransport       = "transport"
	ClassInvalidResponse = "invalid_response"
	ClassSchema          = "schema"
	ClassScopeMismatch   = "scope_mismatch"
	ClassUpstreamStatus  = "upstream_status"
)

// ClassedError attaches a failure class to a cause.
type ClassedError struct {
	Class string
	Err   error
}

func (e *ClassedError) Error() string { return e.Class + ": " + e.Err.Error() }
func (e *ClassedError) Unwrap() error { return e.Err }

// Classed marks err with a failure class; a nil err stays nil.
func Classed(class string, err error) error {
	if err == nil {
		return nil
	}
	return &ClassedError{Class: class, Err: err}
}

// FailureClass names why err failed. A deadline or a network timeout is always a timeout.
func FailureClass(err error) string {
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return ClassTimeout
	}
	var classed *ClassedError
	if errors.As(err, &classed) {
		return classed.Class
	}
	var failure *ScopeError
	if errors.As(err, &failure) && failure.Cause == nil && failure.Status >= 500 {
		return ClassUpstreamStatus
	}
	if errors.As(err, &network) {
		return ClassTransport
	}
	return ClassInvalidResponse
}
