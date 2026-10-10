package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type healthTransport struct {
	status int
	err    error
}

func (transport healthTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: transport.status, Body: healthBody{err: transport.err}, Header: make(http.Header)}, nil
}

type healthBody struct {
	err error
}

func (healthBody) Read([]byte) (int, error) { return 0, io.EOF }
func (body healthBody) Close() error        { return body.err }

func TestHealthcheckRetainsCleanupFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			closeErr := errors.New("fixture body close failure")
			original := http.DefaultTransport
			http.DefaultTransport = healthTransport{status: status, err: closeErr}
			t.Cleanup(func() { http.DefaultTransport = original })
			err := healthcheck()
			if !errors.Is(err, closeErr) {
				t.Fatalf("cleanup failure was lost: %v", err)
			}
			if status != http.StatusOK && !strings.Contains(err.Error(), "health status: 503") {
				t.Fatalf("HTTP failure was lost: %v", err)
			}
		})
	}
}
