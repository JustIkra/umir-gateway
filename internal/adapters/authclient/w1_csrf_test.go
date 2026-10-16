package authclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-gateway/internal/httpapi"
)

type countingTransport struct{ calls atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("the test transport must not be called")
}

func TestW1CheckCSRFWithoutCookiesDoesNotCallAuth(t *testing.T) {
	transport := &countingTransport{}
	target, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{URL: target, ServiceKey: "key", Timeout: time.Second, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "csrf-token"} {
		err := client.CheckCSRF(context.Background(), "", "", token)
		var failure *httpapi.ScopeError
		if !errors.As(err, &failure) || failure.Status != 403 || failure.Code != "InvalidCsrfToken" || failure.Outcome != "not_committed" || failure.Message != "invalid CSRF token" {
			t.Fatalf("token %q: %v", token, err)
		}
	}
	if got := transport.calls.Load(); got != 0 {
		t.Fatalf("Auth called %d times without any cookie", got)
	}
}
